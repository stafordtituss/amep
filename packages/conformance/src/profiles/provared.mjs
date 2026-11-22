// Import profile for Provared books (draft-izmaylov-agent-permission-receipts; the format of github.com/provared/provared,
// "The Provared format, draft version 0"). A book is a file of JSON lines: a slip (the person's permission, signed with a
// passkey), the agent's stubs (one per action, each signed by the agent's hybrid Ed25519 + ML-DSA-87 key set), the
// service's countersignatures, approvals, refusals, terms and seals.
//
// The profile does two things, in this order:
//  1. It checks every record by the format's own rules (sections 3 to 7 and 17 to 19 of the format): the envelope, the
//     protected-header labels, the canonical form, both hybrid signatures, the passkey signature, fingerprints and the
//     chain. A record that fails its own checks is not used.
//  2. It re-expresses what the verified records say as AMEP evidence, signed by the importer: the slip as a mandate, each
//     stub as an invocation, each stub as an effect (observed by the service if it countersigned, by the agent if not),
//     and each approval as an AMEP approval. AMEP then gives its verdict.
// Re-expression is reported, never hidden: the importer's keys sign the AMEP objects, and reconstructed receipts are
// capped at assurance L1 (spec 5.14, minting). Anything AMEP cannot express faithfully is a gap, not an approximation.
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { CEILING, approvalDigest, canon, ed25519StrictOk, parseStrict } from "@stafordtituss/amep/core";

const b64 = s => Buffer.from(s, "base64url");
const B64URL = /^[A-Za-z0-9_-]*$/;
const strictB64url = s => typeof s === "string" && B64URL.test(s) && s.length % 4 !== 1 && b64(s).toString("base64url") === s;
export const fingerprint = payload => createHash("sha256").update(b64(payload)).digest("base64url");

const LABEL = (typ, alg) => `{"typ":"vnd.provared.${typ}.v0+json","alg":"${alg}"}`;
const PASSKEY = "prova.red/webauthn/v0";
const HYBRID_KINDS = new Set(["stub", "countersignature", "refusal", "terms"]);
const PASSKEY_KINDS = new Set(["slip", "approval"]);
const HANDLED = new Set([...HYBRID_KINDS, ...PASSKEY_KINDS, "seal", "stamps"]);

// Section 16: the shared actions' kinds, and the AMEP effect class each kind corresponds to. Kinds with no AMEP class
// (grants, runs, enters) are not guessed: their stubs are not imported unless the caller's map gives a class.
export const KIND_OF = {
  "provared.data.read": "reads", "provared.data.search": "reads", "provared.data.create": "changes",
  "provared.data.change": "changes", "provared.data.delete": "destroys", "provared.data.export": "sends",
  "provared.message.read": "reads", "provared.message.draft": "changes", "provared.message.send": "sends",
  "provared.post.publish": "sends", "provared.calendar.read": "reads", "provared.calendar.change": "changes",
  "provared.booking.make": "commits", "provared.booking.cancel": "commits", "provared.order.place": "commits",
  "provared.order.cancel": "commits", "provared.terms.accept": "commits", "provared.form.submit": "commits",
  "provared.account.create": "commits", "provared.account.sign-in": "enters", "provared.access.grant": "grants",
  "provared.access.remove": "changes", "provared.key.create": "grants", "provared.code.read": "reads",
  "provared.code.change": "changes", "provared.code.run": "runs", "provared.code.release": "runs",
  "provared.system.configure": "changes", "provared.web.read": "reads", "provared.agent.instruct": "sends",
};
export const CLASS_OF_KIND = { reads: "read", changes: "write_shared", destroys: "destructive", sends: "external_send", commits: "financial" };

const amepUnit = u => (/^[A-Z]{3}$/.test(u) ? `iso4217:${u}` : `provared:${u}`);
const thumb = jwk => {   // RFC 7638 thumbprint, used only to name parties in AMEP identifiers
  const req = jwk.kty === "EC" ? ["crv", "kty", "x", "y"] : jwk.kty === "OKP" ? ["crv", "kty", "x"] : jwk.kty === "RSA" ? ["e", "kty", "n"] : ["alg", "kty", "pub"];
  return createHash("sha256").update(JSON.stringify(Object.fromEntries(req.map(k => [k, jwk[k]])))).digest("base64url");
};

/** Envelope, label and canonical-form checks (sections 3.1 to 3.4). Returns { content, problems }. */
function envelope(rec, kind) {
  const problems = [];
  if (!rec || typeof rec !== "object" || Object.keys(rec).sort().join() !== "payload,signatures") return { problems: ["envelope must hold exactly payload and signatures"] };
  if (!strictB64url(rec.payload)) return { problems: ["payload is not strict base64url"] };
  const text = b64(rec.payload).toString("utf8");
  let content;
  try { content = parseStrict(text); } catch (e) { return { problems: [`content is not strict JSON: ${e.message}`] }; }
  if (canon(content) !== text) problems.push("content is not in its canonical form (section 3.4)");
  if (content?.type !== `provared.${kind}.v0`) problems.push(`content type ${JSON.stringify(content?.type)} does not match a ${kind}`);
  return { content, problems };
}

function hybrid(rec, kind, keys) {
  const problems = [], notChecked = [];
  const sigs = rec.signatures;
  if (!Array.isArray(sigs) || sigs.length !== 2) return { problems: ["a hybrid record carries exactly two signatures"], notChecked };
  if (!Array.isArray(keys) || keys.length !== 2 || keys[0].alg !== "Ed25519" || keys[1].alg !== "ML-DSA-87")
    return { problems: ["the key set is not an Ed25519 key then an ML-DSA-87 key (section 3.9)"], notChecked };
  sigs.forEach((s, i) => {
    const alg = i === 0 ? "Ed25519" : "ML-DSA-87";
    if (Object.keys(s).sort().join() !== "protected,signature" || !strictB64url(s.protected) || !strictB64url(s.signature)) { problems.push(`${alg} signature entry is malformed`); return; }
    if (b64(s.protected).toString("utf8") !== LABEL(kind, alg)) { problems.push(`${alg} protected header is not the ${kind} label`); return; }
    const sig = b64(s.signature), input = Buffer.from(`${s.protected}.${rec.payload}`, "ascii");
    if (sig.length !== (alg === "Ed25519" ? 64 : 4627)) { problems.push(`${alg} signature has the wrong length`); return; }
    if (alg === "Ed25519" && !ed25519StrictOk(b64(keys[0].x).toString("hex"), sig.toString("hex"))) { problems.push("Ed25519 key or signature fails the strict acceptance rule"); return; }
    let pub;
    try { pub = createPublicKey({ key: keys[i], format: "jwk" }); } catch { notChecked.push(`${alg} (this runtime cannot load the key)`); return; }
    if (!cryptoVerify(null, input, pub, sig)) problems.push(`${alg} signature does not check`);
  });
  return { problems, notChecked };
}

/** A passkey signature on a slip or an approval (section 4.4, steps 2 to 7), against the slip's issuer. */
function passkey(rec, kind, issuer) {
  const problems = [], notChecked = [];
  const s = rec.signatures?.[0];
  if (rec.signatures?.length !== 1 || !s?.header || Object.keys(s).sort().join() !== "header,protected,signature") return { problems: ["a passkey record carries exactly one signature with a header"], notChecked };
  if (b64(s.protected).toString("utf8") !== LABEL(kind, PASSKEY)) return { problems: [`protected header is not the ${kind} label`], notChecked };
  let cd;
  try { cd = JSON.parse(b64(s.header.clientDataJSON).toString("utf8")); } catch { return { problems: ["client data is not JSON"], notChecked }; }
  const input = Buffer.from(`${s.protected}.${rec.payload}`, "ascii");
  if (cd.type !== "webauthn.get") problems.push("client data type is not webauthn.get");
  if (cd.challenge !== createHash("sha256").update(input).digest("base64url")) problems.push("challenge is not the hash of the signing input");
  if (cd.origin !== issuer.origin || cd.crossOrigin === true) problems.push("client data origin does not match the slip's origin");
  const ad = b64(s.header.authenticatorData);
  if (ad.length < 37 || !ad.subarray(0, 32).equals(createHash("sha256").update(issuer.rpId).digest())) problems.push("authenticator data does not name the slip's rpId");
  const flags = ad[32];
  if (!(flags & 1) || !(flags & 4) || (flags & 64) || (!(flags & 128) && ad.length !== 37)) problems.push("authenticator flags: user present and verified are required, attested data is not allowed");
  if (issuer.key?.alg === "RS256") { notChecked.push("RS256 passkey signature (not supported by this profile)"); return { problems, notChecked }; }
  try {
    const pub = createPublicKey({ key: issuer.key, format: "jwk" });
    const signed = Buffer.concat([ad, createHash("sha256").update(b64(s.header.clientDataJSON)).digest()]);
    if (!cryptoVerify(issuer.key.alg === "ES256" ? "sha256" : null, signed, pub, b64(s.signature))) problems.push("passkey signature does not check");
  } catch (e) { problems.push(`passkey key or signature is malformed: ${e.message}`); }
  return { problems, notChecked };
}

/**
 * Check a Provared book and re-express it as AMEP evidence.
 * keys: { issuer, host, observer } AMEP Key objects of the importer (roles issuer+approver, host, observer).
 * map: optional { actions: { "<action name>": "<AMEP effect class>" } } for action names outside the shared list.
 * Returns { lines, packet, keys, state, mapping, gaps }.
 */
export function importProvaredBook(text, { keys, map = { actions: {} } } = {}) {
  const lines = [];
  const gaps = new Map();
  const gap = (need, detail) => { if (!gaps.has(need)) gaps.set(need, detail); };
  const entries = String(text).split("\n").filter(l => l.trim() !== "").map((l, i) => {
    try { return parseStrict(l); } catch (e) { return { __bad: e.message, __line: i }; }
  });
  // the slip comes first: every other record is checked against it
  let slip = null, slipFp = null;
  const ids = new Set();
  const chain = [];
  entries.forEach((e, n) => {
    const line = { line: n, kinds: Object.keys(e).filter(k => !k.startsWith("__")), problems: [], notChecked: [], notHandled: [] };
    lines.push(line);
    if (e.__bad) { line.problems.push(`line is not strict JSON: ${e.__bad}`); return; }
    for (const k of line.kinds) if (!HANDLED.has(k)) line.notHandled.push(k);
    const take = (kind, checkSig) => {
      if (!(kind in e)) return null;
      const env = envelope(e[kind], kind);
      line.problems.push(...env.problems.map(p => `${kind}: ${p}`));
      if (!env.content) return null;
      const sig = checkSig(e[kind], env.content);
      line.problems.push(...sig.problems.map(p => `${kind}: ${p}`));
      line.notChecked.push(...sig.notChecked.map(p => `${kind}: ${p}`));
      if (env.content.id) { if (ids.has(env.content.id)) line.problems.push(`${kind}: duplicate id`); ids.add(env.content.id); }
      return { content: env.content, fp: fingerprint(e[kind].payload) };
    };
    if ("slip" in e) {
      const s = take("slip", (rec, c) => passkey(rec, "slip", c.issuer ?? {}));
      if (s && !line.problems.length) { slip = s.content; slipFp = s.fp; }
      line.role = "slip";
      return;
    }
    if (!slip) { line.problems.push("no verified slip before this record"); return; }
    const service = id => (slip.with ?? []).find(w => w.id === id);
    if ("terms" in e) { take("terms", (rec, c) => hybrid(rec, "terms", c.by?.keys)); line.role = "terms"; }
    if ("refusal" in e) {
      const r = take("refusal", (rec, c) => hybrid(rec, "refusal", c.by?.keys));
      line.role = "refusal";
      if (r) line.refusal = { action: r.content.action, reason: r.content.reason, by_slip_service: (slip.with ?? []).some(w => w.keys && canon(w.keys) === canon(r.content.by?.keys)) };
    }
    if ("seal" in e) { line.role = "seal"; line.notChecked.push("seal: signatures and tree root are not checked by this profile"); }
    if ("stub" in e) {
      line.role = "stub";
      const st = take("stub", (rec) => hybrid(rec, "stub", slip.agent?.keys));
      if (!st) return;
      const c = st.content;
      if (c.slip !== slipFp) line.problems.push("stub: names a different slip");
      if (c.pass) line.notHandled.push("stub under a pass (helper agent, section 25)");
      // the chain (section 7), for the slip's own agent
      const prev = chain[chain.length - 1];
      if (!c.pass) {
        if (c.seq !== chain.length) line.problems.push(`stub: seq ${c.seq} where ${chain.length} was expected`);
        if (chain.length ? c.previous !== prev.fp : "previous" in c) line.problems.push("stub: previous does not name the stub before");
        if (prev && c.when < prev.content.when) line.problems.push("stub: when goes backwards");
      }
      const out = { content: c, fp: st.fp, line: n, countersigned: false, approval: null };
      if ("countersignature" in e) {
        const svc = service(c.with);
        const cs = take("countersignature", (rec) => svc?.keys ? hybrid(rec, "countersignature", svc.keys) : { problems: ["the stub's service has no keys in the slip"], notChecked: [] });
        if (cs && cs.content.stub !== st.fp) line.problems.push("countersignature: names another stub");
        out.countersigned = !!cs && !line.problems.some(p => p.startsWith("countersignature"));
        out.countersignedAt = cs?.content.when;
      }
      if ("approval" in e) {
        const ap = take("approval", (rec) => passkey(rec, "approval", slip.issuer));
        if (ap) {
          if (c.approval !== ap.fp) line.problems.push("approval: the stub names another approval");
          for (const k of ["action", "amount", "with", "details"]) if (canon(ap.content[k] ?? null) !== canon(c[k] ?? null)) line.problems.push(`approval: ${k} differs from the stub's`);
          if (ap.content.slip !== slipFp) line.problems.push("approval: names a different slip");
          if (Date.parse(ap.content.when) > Date.parse(c.when) + 300000) line.problems.push("approval: dated more than 300 seconds after the stub");
          if (!line.problems.some(p => p.startsWith("approval"))) out.approval = ap.content;
        }
      } else if (c.approval) line.problems.push("stub: names an approval that is not with it");
      line.stub = { seq: c.seq, action: c.action, countersigned: out.countersigned, approved: !!out.approval };
      if (!line.problems.some(p => p.startsWith("stub"))) chain.push(out);
    }
  });
  if (!slip) return { lines, packet: null, gaps: [...gaps].map(([need, detail]) => ({ need, detail })), mapping: {} };

  // ---- re-express as AMEP evidence ----
  const classOf = a => map.actions?.[a] ?? CLASS_OF_KIND[KIND_OF[a]];
  for (const a of slip.actions) if (!classOf(a)) gap(`effect class for ${a}`, `${a} has no AMEP effect class (its kind ${KIND_OF[a] ?? "is not on the shared list"}); its stubs are not imported unless the map gives one`);
  const allowed = slip.actions.filter(classOf);
  const agentId = `provared-agent:${thumb(slip.agent.keys[0])}`;
  const issuerId = `provared-issuer:${thumb(slip.issuer.key)}`;
  const resOf = c => (c.with ? `provared:service/${c.with}` : "provared:no-service");
  const ceiling = allowed.reduce((m, a) => (CEILING.indexOf(classOf(a)) > CEILING.indexOf(m) ? classOf(a) : m), "read");
  const validity = (Date.parse(slip.validUntil) - Date.parse(slip.validFrom)) / 1000;
  const limits = [], seeded = {};
  for (const l of slip.limits ?? []) {
    if ("each" in l) gap(`hard per-stub cap (${l.action} each ${l.each} ${l.unit})`, "AMEP limits can all be lifted by an approval that passed I8; a Provared `each` cap cannot. Not mapped; an approved stub above it would be preserved in AMEP but over-limit in Provared");
    else if ("count" in l) gap(`count limit (${l.action} count ${l.count}${l.per ? ` per ${l.per} s` : ""})`, "AMEP limits cap amounts in a unit, not numbers of actions. Not mapped");
    else if ("per" in l) gap(`max per sliding period (${l.action} max ${l.max} ${l.unit} per ${l.per} s)`, "Provared counts this period backwards from each stub; AMEP periods are fixed windows from the mandate's nbf. Not mapped, rather than mapped inexactly");
    else {   // max over the slip's whole life: one AMEP window covering the validity period
      const unit = amepUnit(l.unit);
      limits.push({ unit, per_period: String(l.max), period: validity, actions: [l.action] });
      // The chain starts at seq 0 and every stub names the one before, so no earlier spending under this slip can
      // have been left out: the importer seeds the window's running total at zero (spec 7.6 rule 5, 10.7).
      seeded[`m-1|${unit}|${validity}|0|${l.action}`] = "0";
    }
  }
  for (const r of slip.requires ?? []) {
    if (r.need === "approval" && "above" in r) limits.push({ unit: amepUnit(r.unit), per_effect: String(r.above), actions: [r.action] });
    else if (r.need === "approval") gap(`approval for every ${r.action ?? "action"}`, "AMEP requires an approval only above an amount or budget; an approval required for every action has no AMEP equivalent. Not mapped");
    else if (r.need === "countersignature") {
      const low = (r.action ? [r.action] : allowed).filter(a => CEILING.indexOf(classOf(a)) < CEILING.indexOf("write_shared"));
      if (low.length) gap(`countersignature for ${low.join(", ")}`, "AMEP requires an independent observer (I10) for effects of class write_shared and above only; for lower classes a missing countersignature is not a finding in AMEP");
    }
  }
  if (slip.never?.length) gap("rules of conduct", `never: ${slip.never.join(", ")}. Kinds of action are enforced by the mapped actions list; rules of conduct cannot be checked from records (Provared says so too, section 13)`);
  gap("origin of the AMEP objects", "AMEP objects are signed by the importer's keys after the profile verified the Provared signatures (passkey, Ed25519 and ML-DSA-87). AMEP cannot yet verify passkey or ML-DSA signatures itself, so the mandate, invocations and approvals are re-expressions and receipts are capped at L1");
  const mandate = keys.issuer.sign({ id: "m-1", kind: "mandate", principal: issuerId, claims: {
    actions: allowed, resources: [...(slip.with ?? []).map(w => `provared:service/${w.id}`), "provared:no-service"],
    ceiling, nbf: slip.validFrom, exp: slip.validUntil, ...(limits.length ? { limits } : {}) } }, { v: 2 });
  const interp = keys.host.sign({ id: "a-1", kind: "interpretation", source: "curated", adapter: "provared-format", version: "v0" }, { v: 2 });
  const invocations = [], effects = [], approvals = [], byInvocation = {};
  for (const s of chain) {
    const c = s.content, cls = classOf(c.action), id = `i-${c.seq}`;
    byInvocation[id] = s.line;
    if (!cls) { lines[s.line].notImported = `${c.action} has no AMEP effect class`; continue; }
    const executed = { action: c.action, resource: resOf(c), effect: cls, released: [], t: c.when,
      ...(c.amount ? { value: { amount: String(c.amount.value), unit: amepUnit(c.amount.unit) } } : {}),
      "x-provared": { stub: s.fp } };
    let approvalRef;
    if (s.approval) {
      approvals.push(keys.issuer.sign({ id: `ap-${c.seq}`, kind: "approval", effect_digest: approvalDigest(executed),
        presence: "webauthn", approver: issuerId }, { v: 2 }));
      approvalRef = `ap-${c.seq}`;
    }
    invocations.push(keys.host.sign({ id, kind: "invocation", authority_ref: "m-1", interpretation_ref: "a-1", actor: agentId,
      t: c.when, declared: { action: c.action, resource: resOf(c), effect: cls }, ...(approvalRef ? { approval_ref: approvalRef } : {}) }, { v: 2 }));
    effects.push(keys.observer.sign({ id: `e-${c.seq}`, kind: "effect", invocation: id,
      observed_by: s.countersigned ? `provared-service:${c.with}` : agentId, assurance: s.countersigned ? "L1" : "L0", executed }, { v: 2 }));
  }
  const packet = { amep_version: "0.3", mandates: [mandate], delegations: [], interpretations: [interp], invocations, effects,
    ...(approvals.length ? { approvals } : {}) };
  const amepKeys = Object.fromEntries([keys.issuer, keys.host, keys.observer].map(k => [k.kid, k.publicEntry()]));
  return { lines, packet, keys: amepKeys, state: { period_totals: seeded }, byInvocation,
    gaps: [...gaps].map(([need, detail]) => ({ need, detail })),
    mapping: { agent: agentId, issuer: issuerId, ceiling, limits, actions: allowed } };
}
