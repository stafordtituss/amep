// Completeness from an Observed Effect record (in-toto/attestation#607; predicate by probityai/agent-evidence-vectors).
//
// AMEP checks the evidence it is given; it cannot see an effect nobody recorded (LIMITS.md, section A). An Observed
// Effect statement can close part of that gap. An observer below the agent signs every write in a path scope over an
// interval, and, when its own verifier grades it authoritative with absence established, nothing else was written there.
//
// This module reconciles one such statement with an AMEP packet. The division of labour is deliberate:
// - The statement's own validity (41 conditions: write chain, prior commitment, tier recompute, ...) is the predicate's
//   verifier's job. The caller supplies that verifier's result, and this module never upgrades it.
// - This module checks only what AMEP relies on: the DSSE signature under the observer key the caller names, the
//   predicate type, subject = afterRoot, that the observer key is not one of the agent host's keys, and whether the
//   statement's authorityDigest is the digest of an authority object in the packet.
// Then it compares writes with receipts, both ways, and reports calls whose outcome the record settles.
//
// It never says more than the record does: outside pathScope, or outside the interval, nothing is concluded, and
// "no write observed" means absence only when the supplied verdict established absence.
import { createPublicKey, verify as edVerify } from "node:crypto";
import { posix } from "node:path";
import { digest, toTime } from "@stafordtituss/amep/core";

export const OBSERVED_EFFECT_TYPE = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/observed-effect";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function pae(type, body) {   // DSSE v1 pre-authentication encoding
  const t = Buffer.from(type, "utf8");
  return Buffer.concat([Buffer.from(`DSSEv1 ${t.length} `), t, Buffer.from(` ${body.length} `), body]);
}
function edOk(pubHex, msg, sigB64) {
  try {
    const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pubHex, "hex")]), format: "der", type: "spki" });
    return edVerify(null, msg, key, Buffer.from(sigB64, "base64"));
  } catch { return false; }
}
// Paths are normalized before any scope test, so "/srv/app/../etc/passwd" is "/etc/passwd", not a path in /srv/app/.
// A path that isn't absolute, or that changes under normalization, is refused rather than guessed at.
const norm = path => (typeof path === "string" && path.startsWith("/") && posix.normalize(path) === path ? path : null);
const inScope = (path, scope) => path !== null && scope.some(p => path === p || path.startsWith(p.endsWith("/") ? p : p + "/"));
function toPath(resource, pathMap) {   // AMEP resource -> observed path, by the deployment's declared prefix map
  for (const { resource: r, path: p } of pathMap) if (resource.startsWith(r)) return norm(p + resource.slice(r.length));
  return null;
}

/**
 * @param {object} a
 * @param {object} a.envelope      DSSE envelope carrying the Observed Effect statement
 * @param {object} a.observer      { keyid, publicKey (hex Ed25519) }: the observer key the caller trusts
 * @param {object} a.oeVerdict     the predicate verifier's result: { verdict, derivedTier, absenceEstablished }
 * @param {object} a.packet        AMEP packet
 * @param {object} a.keys          AMEP key set
 * @param {Array}  a.pathMap       [{ resource: "repo:app/", path: "/srv/app/" }]: how AMEP resources name observed paths
 */
export function reconcile({ envelope, observer, oeVerdict, packet, keys = {}, pathMap = [] }) {
  const checks = [], add = (rule, pass, detail) => checks.push({ rule, pass, detail });
  const out = { checks, usable: false, absence: false, authority: null, accounted: [], unaccounted_writes: [],
    unobserved_receipts: [], settled: [], not_concluded: [] };

  // 1. what this module itself relies on
  const body = Buffer.from(envelope?.payload ?? "", "base64");
  const sig = (envelope?.signatures ?? []).find(s => s.keyid === observer?.keyid);
  const sigOk = !!sig && envelope.payloadType === "application/vnd.in-toto+json" && edOk(observer.publicKey, pae(envelope.payloadType, body), sig.sig);
  add("DSSE signature by the named observer key", sigOk, observer?.keyid);
  let st = null;
  try { st = JSON.parse(body.toString("utf8")); } catch { /* reported below */ }
  const p = st?.predicate;
  add("predicate type is Observed Effect", st?.predicateType === OBSERVED_EFFECT_TYPE, st?.predicateType);
  const subjOk = Array.isArray(st?.subject) && st.subject.length === 1 && st.subject[0]?.digest?.sha256 === p?.interval?.afterRoot;
  add("subject is the after-state (afterRoot)", subjOk, p?.interval?.afterRoot);
  const hostKeys = Object.values(keys).filter(k => (k.roles || []).includes("host")).map(k => k.x);
  const independent = !!observer?.publicKey && !hostKeys.includes(observer.publicKey.toLowerCase());
  add("observer key is not a key of the agent's host", independent, independent ? "not in the AMEP key set as host" : "the observer is the host");
  const valid = oeVerdict?.verdict === "valid";
  add("the Observed Effect verifier graded the statement valid (supplied by the caller)", valid, JSON.stringify(oeVerdict ?? null));
  if (!(sigOk && st && subjOk && independent && valid && p)) return out;
  out.usable = true;
  out.absence = oeVerdict.absenceEstablished === true && oeVerdict.derivedTier === "authoritative";
  add("absence established (authoritative, complete coverage of the scope)", out.absence,
    out.absence ? "a write not in the record did not happen in the scope during the interval" : "writes in the record happened; a write missing from it may still have happened");

  // 2. which authority the interval ran under
  const authorities = [...(packet.mandates || []), ...(packet.delegations || [])];
  const bound = authorities.find(o => digest(o) === p.authorityDigest);
  out.authority = bound ? { bound: true, id: bound.id }
    : { bound: false, detail: "authorityDigest is not the digest of any mandate or delegation in the packet; the record and the packet may be under different authority" };

  // 3. compare, inside the scope and the interval only
  const from = toTime(p.interval.openedAt), to = toTime(p.interval.sealedAt), scope = p.pathScope;
  const writes = (p.writes || []).filter(w => w.inScope !== false && inScope(norm(w.path), scope)).map(w => ({ path: w.path, used: false }));
  const effects = packet.effects || [], invs = packet.invocations || [], stmts = packet.call_statements || [];
  for (const e of effects) {
    const path = toPath(e.executed?.resource ?? "", pathMap), t = toTime(e.executed?.t);
    if (!path || !inScope(path, scope) || !(t >= from && t <= to)) {
      out.not_concluded.push({ effect: e.id, why: !path ? "the path map does not cover its resource" : "outside the record's scope or interval" });
      continue;
    }
    const w = writes.find(x => !x.used && x.path === path);
    if (w) { w.used = true; out.accounted.push({ effect: e.id, invocation: e.invocation, path }); }
    else out.unobserved_receipts.push({ effect: e.id, invocation: e.invocation, path,
      finding: out.absence ? "the observer, with complete coverage, saw no such write: the receipt and the record contradict each other"
        : "the record does not show this write; without established absence that is not a contradiction" });
  }
  for (const inv of invs) {
    if (effects.some(e => e.invocation === inv.id)) continue;
    if (stmts.some(c => c.invocation === inv.id && c.disposition === "not_executed")) continue;
    const path = toPath(inv.declared?.resource ?? "", pathMap), t = toTime(inv.t);
    if (!path || !inScope(path, scope) || !(t >= from && t <= to)) { out.not_concluded.push({ invocation: inv.id, why: !path ? "its resource does not map to a normalized path in the record" : "outside the record's scope or interval" }); continue; }
    const w = writes.find(x => !x.used && x.path === path);
    if (w) { w.used = true; out.settled.push({ invocation: inv.id, path, outcome: "wrote",
      finding: "the call has no receipt, but the observer saw its write: its outcome is known, and the missing receipt is the gap" }); }
    else if (out.absence) out.settled.push({ invocation: inv.id, path, outcome: "no write in scope",
      finding: "no write at this path in the interval, with absence established: the call wrote nothing in the record's scope" });
    else out.not_concluded.push({ invocation: inv.id, why: "no write recorded, but absence is not established" });
  }
  for (const w of writes.filter(x => !x.used))
    out.unaccounted_writes.push({ path: w.path, finding: "a write the observer saw with no AMEP receipt or call: the presented evidence is incomplete, or an effect had no authorized call (I11)" });
  if (Array.isArray(p.doesNotAssert)) out.record_does_not_assert = p.doesNotAssert;
  return out;
}
