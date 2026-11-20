// AMEP v0.2 evaluation core (spec/amep-v0.2.md section 10). Pure JavaScript, no I/O and no platform crypto:
// signature checks are injected (`sigOk(obj, key) -> boolean`), so the Node CLI and the in-browser verifier
// share this exact code. Independent of the Python reference verifier.

export const CEILING = ["read", "write_local", "write_shared", "external_send", "destructive", "financial"];
const MARKERS = ["/.claude/", "/.codex/", "/.cursor/", "/.gemini/", "/.git/hooks/", "/.ssh/authorized_keys"];
const NAMES = ["AGENTS.md", "CLAUDE.md", ".mcp.json", ".zshrc", ".bashrc"];
export const SIGNER_ROLES = {
  mandate: ["issuer"], revocation: ["issuer"], status: ["issuer"],
  delegation: ["issuer", "host"], intent: ["issuer", "host"],
  interpretation: ["host"], invocation: ["host"], decision: ["host"],
  effect: ["observer"], approval: ["approver"], finding: ["host", "observer"],
};
const COST_BASE = { read: 0, write_local: 1, write_shared: 3, external_send: 5, destructive: 10, financial: 20 };
const DATA_MULT = { public: 1, internal: 1, source: 1, confidential: 2, secret: 5, phi: 5, pci: 5 };

class Malformed extends Error {}
class Stop { constructor(outcome, invariant, reason) { Object.assign(this, { outcome, invariant, reason }); } }
const check = (cond, outcome, invariant, reason) => { if (cond) throw new Stop(outcome, invariant, reason); };

export const isGuardrail = (res, extra = []) => {
  const r = "/" + res.replace("~", "home").replace(/^\/+/, "");
  return [...MARKERS, ...extra].some(m => r.includes(m)) || NAMES.includes(r.split("/").pop());
};

// ---- time (spec 5.1.1) ----
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$/;
export function toTime(v) {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && RFC3339.test(v)) { const ms = Date.parse(v); if (!Number.isNaN(ms)) return ms / 1000; }
  throw new Malformed(`malformed time ${JSON.stringify(v)}`);
}

// ---- RFC 8785 canonical form (spec 12.1). JSON.stringify of a number is ECMAScript Number::toString, and the
// default sort compares UTF-16 code units, so this is JCS as written. ----
// I-JSON (RFC 7493): numbers beyond +/-(2^53 - 1) are not interoperable. ECMAScript rounds them to a double while
// Python keeps integers exact, so two verifiers would canonicalize the same packet differently. Spec 12.1 makes
// them malformed everywhere: canon() refuses to serialize them and evaluate() returns unresolved (I7).
export function canon(v) {
  if (v === null || typeof v !== "object") {
    if (typeof v === "number" && !Number.isFinite(v)) throw new Malformed("NaN and Infinity are not allowed");
    if (typeof v === "number" && Math.abs(v) > Number.MAX_SAFE_INTEGER)
      throw new Malformed(`number ${v} is outside the I-JSON range (|n| > 2^53-1)`);
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  return "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
}
export const stripProof = o => Object.fromEntries(Object.entries(o).filter(([k]) => k !== "proof"));

// Path of the first number outside the I-JSON range, or null.
export function unsafeNumber(v, path = "$") {
  if (typeof v === "number") return Math.abs(v) > Number.MAX_SAFE_INTEGER ? path : null;
  if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) { const p = unsafeNumber(v[i], `${path}[${i}]`); if (p) return p; } return null; }
  if (v && typeof v === "object") { for (const [k, x] of Object.entries(v)) { const p = unsafeNumber(x, `${path}.${k}`); if (p) return p; } }
  return null;
}

// A decimal literal as sign + significant digits + exponent, so "1200.00" and "1.2e3" compare equal.
function normDec(s) {
  const m = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(s);
  if (!m) return null;
  let digits = (m[2] + (m[3] || "")).replace(/^0+/, ""), exp = Number(m[4] || 0) - (m[3] || "").length;
  if (!digits) return "0";
  while (digits.endsWith("0")) { digits = digits.slice(0, -1); exp++; }
  return (m[1] ? "-" : "") + digits + "e" + exp;
}

// Parse JSON text for evaluation (spec 12.1). A non-integer number literal must equal, as a decimal, the double it
// denotes, so two distinct literals can never share one canonical form or approval digest. Integers are checked
// against the I-JSON range by evaluate(). The literals are read from the text itself (after JSON.parse has
// accepted it, so it is valid JSON), which works on every engine, without JSON.parse source-text access.
const NUMBER = /-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
export function parseStrict(text) {
  const value = JSON.parse(text);
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') { for (i++; i < text.length && text[i] !== '"'; i++) if (text[i] === "\\") i++; continue; }
    if (c !== "-" && (c < "0" || c > "9")) continue;
    NUMBER.lastIndex = i;
    const lit = NUMBER.exec(text)[0];
    i += lit.length - 1;
    if (/[.eE]/.test(lit) && normDec(lit) !== normDec(String(Number(lit))))
      throw new Malformed(`number literal ${lit} is not exactly representable as an IEEE 754 double`);
  }
  return value;
}

// ---- SHA-256 over UTF-8 (pure JS, so evaluation stays synchronous in the browser) ----
const K = Uint32Array.from([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
export function sha256Hex(str) {
  const msg = new TextEncoder().encode(str);
  const len = msg.length, blocks = ((len + 9 + 63) >> 6) << 6;
  const buf = new Uint8Array(blocks); buf.set(msg); buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(blocks - 8, Math.floor(len / 0x20000000)); dv.setUint32(blocks - 4, (len * 8) >>> 0);
  const H = Uint32Array.from([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const W = new Uint32Array(64); const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < blocks; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + W[i]) >>> 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    [a, b, c, d, e, f, g, h].forEach((v, i) => { H[i] = (H[i] + v) >>> 0; });
  }
  return Array.from(H, x => x.toString(16).padStart(8, "0")).join("");
}
export const digest = o => sha256Hex(canon(o));
// spec 5.10: approvals bind the executed body without its time
export const approvalDigest = x => digest(Object.fromEntries(Object.entries(x).filter(([k]) => k !== "t")));

// ---- claim algebra (spec 6.3, 7) ----
const patMatch = (v, p) => p === "*" || v === p || (p.endsWith("*") && v.startsWith(p.slice(0, -1)));
const subsumed = (cs, ps) => cs.every(c => ps.some(p => p === "*" || c === p || (p.endsWith("*") && c.replace(/\*+$/, "").startsWith(p.slice(0, -1)))));
function narrower(c, p) {
  if (!subsumed(c.actions, p.actions)) return [false, "actions widened"];
  if (!subsumed(c.resources, p.resources)) return [false, "resources widened"];
  if (!(c.data || []).every(d => (p.data || []).includes(d))) return [false, "data classes widened"];
  if (CEILING.indexOf(c.ceiling) > CEILING.indexOf(p.ceiling)) return [false, "effect ceiling raised"];
  if (toTime(c.exp) > toTime(p.exp)) return [false, "validity extended"];
  if ("nbf" in p && (!("nbf" in c) || toTime(c.nbf) < toTime(p.nbf))) return [false, "validity extended (nbf)"];
  if ("purpose" in p && c.purpose !== p.purpose) return [false, "purpose changed"];
  // spec 7.1: denies only grow; every parent deny must be covered by an equal-or-broader child deny
  for (const key of ["deny_actions", "deny_resources"])
    if (!(p[key] || []).every(d => subsumed([d], c[key] || []))) return [false, `${key} removed`];
  if ("budget" in p && (c.budget ?? p.budget) > p.budget) return [false, "risk budget widened"];
  if ("depth" in p) {
    if (p.depth === 0) return [false, "parent may not be delegated (depth 0)"];
    if (!("depth" in c)) return [false, "delegation depth missing under a bounded parent"];
    if (c.depth >= p.depth) return [false, "delegation depth not decreasing"];
  }
  return [true, ""];
}
function meet(a, b) {
  const m = { actions: a.actions.filter(x => subsumed([x], b.actions)), resources: a.resources.filter(x => subsumed([x], b.resources)),
    data: (a.data || []).filter(d => (b.data || []).includes(d)).sort(),
    ceiling: CEILING[Math.min(CEILING.indexOf(a.ceiling), CEILING.indexOf(b.ceiling))], exp: Math.min(toTime(a.exp), toTime(b.exp)) };
  const nbfs = [a, b].filter(c => "nbf" in c).map(c => toTime(c.nbf)); if (nbfs.length) m.nbf = Math.max(...nbfs);
  if ("purpose" in a || "purpose" in b) m.purpose = a.purpose ?? b.purpose;
  for (const key of ["deny_actions", "deny_resources"]) // denies are unioned: no hop or intent can lift one
    if (key in a || key in b) m[key] = [...new Set([...(a[key] || []), ...(b[key] || [])])].sort();
  return m;
}
function effectOk(x, c) {
  if (!c.actions.some(p => patMatch(x.action, p))) return [false, "action outside claims"];
  if ((c.deny_actions || []).some(p => patMatch(x.action, p))) return [false, "action denied"];
  if (!c.resources.some(p => patMatch(x.resource, p))) return [false, "resource outside claims"];
  if ((c.deny_resources || []).some(p => patMatch(x.resource, p))) return [false, "resource denied"];
  if (CEILING.indexOf(x.effect) > CEILING.indexOf(c.ceiling)) return [false, "effect above ceiling"];
  for (const d of x.released || []) if (!(c.data || []).includes(d)) return [false, `released ${d} not allowed`];
  if (toTime(x.t) > toTime(c.exp)) return [false, "after validity"];
  if ("nbf" in c && toTime(x.t) < toTime(c.nbf)) return [false, "before validity"];
  return [true, ""];
}
const cost = x => {
  const m = Math.max(1, ...(x.released || []).map(d => DATA_MULT[d.split("->")[0]] ?? 1));
  const rev = (x.effect === "read" || (x.reversible && x.effect !== "external_send")) ? 1 : 3;
  return COST_BASE[x.effect] * m * rev;
};

// ---- evaluation (spec 10) ----
// state (spec 10.6): { approvals_used: {id: [invocation, digest]}, spent: {node: points} }, read on entry and
// updated on exit, so approval single use and risk budgets hold across a stream of packets.
export function evaluate(pk, keys, sigOk, extraProtected = [], state = {}) {
  const bad = unsafeNumber(pk);
  if (bad) {   // spec 12.1: such a packet cannot be canonicalized the same way by every verifier
    const ids = (pk.invocations || []).map(i => (i && typeof i === "object" && i.id) || "?");
    return (ids.length ? ids : ["-"]).map(id => ({ id, outcome: "unresolved", invariant: "I7", reason: `number outside the I-JSON range at ${bad}` }));
  }
  // signature valid AND the signing key holds a role allowed for this object kind (spec 12.5)
  const verify = o => {
    if (!o || typeof o !== "object" || !o.proof || o.proof.alg !== "Ed25519") return false;
    const k = keys[o.proof.kid]; if (!k || k.alg !== "Ed25519") return false;
    if (!(k.roles || []).some(r => (SIGNER_ROLES[o.kind] || []).includes(r))) return false;
    try { return sigOk(o, k); } catch { return false; }
  };
  const objs = {};
  for (const kind of ["mandates", "delegations", "intents", "interpretations", "invocations", "effects", "approvals", "findings"])
    for (const o of pk[kind] || []) if (o && typeof o === "object" && "id" in o) objs[o.id] = o;
  const revocations = pk.revocations || [], statuses = pk.statuses || [], effects = pk.effects || [];
  const spent = { ...(state.spent || {}) };
  const approvalUse = Object.fromEntries(Object.entries(state.approvals_used || {}).map(([k, v]) => [k, [...v]]));
  let out = [];
  const invocations = pk.invocations || [];
  const order = new Map(invocations.map((i, n) => [i.id, n]));
  // spec 5.9.1 data lineage: data classes each invocation's output carries, through derived_from, earlier only
  const taint = new Map();
  invocations.forEach((i, n) => {
    const own = new Set(effects.filter(e => e.invocation === i.id).flatMap(e => (e.executed || {}).accessed || []));
    for (const j of i.derived_from || []) if ((order.get(j) ?? n) < n) for (const d of taint.get(j) || []) own.add(d);
    taint.set(i.id, own);
  });
  const decisions = (pk.decisions || []).filter(d => verify(d));
  // spec 5.13: a verified pre-execution quarantine withholds findings from every LATER invocation
  const quarantined = new Map();
  for (const d of decisions)
    if (d.mode === "quarantine" && d.phase === "pre_execution" && order.has(d.invocation))
      for (const f of d.quarantined || []) quarantined.set(f, Math.min(quarantined.get(f) ?? invocations.length, order.get(d.invocation)));

  for (const [n, inv] of invocations.entries()) {
    const id = inv.id ?? "?";
    try {
      const leaked = (inv.influenced_by || []).filter(f => quarantined.has(f) && n > quarantined.get(f));
      check(leaked.length > 0 && !inv.principal_confirmed, "violated", "I4", `quarantined content reached the agent (${leaked.join(", ")})`);
      evalInvocation(inv);
      out.push({ id, outcome: "preserved", invariant: "-", reason: "continuity preserved" });
    } catch (e) {
      if (e instanceof Stop) out.push({ id, outcome: e.outcome, invariant: e.invariant, reason: e.reason });
      else out.push({ id, outcome: "unresolved", invariant: "I7", reason: `malformed evidence: ${e.message}` });
    }
  }

  function evalInvocation(inv) {
    const id = inv.id, tInv = toTime(inv.t);
    const chain = []; const seen = new Set(); let n = objs[inv.authority_ref];
    while (n && !seen.has(n.id)) { seen.add(n.id); chain.unshift(n); n = objs[n.parent]; }
    check(!chain.length || chain[0].kind !== "mandate", "unresolved", "I7", "no root mandate");
    const interp = objs[inv.interpretation_ref];
    const needed = [...chain, inv, ...(interp ? [interp] : [])];
    if ("intent_ref" in inv) {
      const it = objs[inv.intent_ref];
      check(!it || it.kind !== "intent", "unresolved", "I7", "cited intent not found");
      needed.push(it);
    }
    check(needed.some(o => !verify(o)), "unresolved", "I7", "missing or invalid signature, or signer lacks the role");
    check((inv.derived_from || []).some(j => (order.get(j) ?? order.get(id)) >= order.get(id)), "unresolved", "I7", "lineage reference not found among earlier invocations");
    check(!interp || !["curated", "customer"].includes(interp.source), "unresolved", "I3", "no approved interpretation");
    const pinned = pk.pinned_adapters || {};
    check(Object.keys(pinned).length > 0 && pinned[interp.adapter] !== interp.version, "unresolved", "I3", "adapter revision not approved (pin mismatch)");
    for (let i = 1; i < chain.length; i++) { const [ok, why] = narrower(chain[i].claims, chain[i - 1].claims); check(!ok, "violated", "I1", `${chain[i].id}: ${why}`); }
    // liveness (spec 5.12)
    const ids = new Set(chain.map(c => c.id));
    const revs = revocations.filter(r => ids.has(r.target));
    check(revs.some(r => verify(r) && toTime(r.t) <= tInv), "violated", "I6", "ancestor revoked before invocation");
    const sts = statuses.filter(s => ids.has(s.target) && verify(s));
    check(sts.some(s => s.revoked_at != null && toTime(s.revoked_at) <= tInv), "violated", "I6", "status shows ancestor revoked before invocation");
    check(revs.some(r => !verify(r)), "unresolved", "I7", "unverifiable revocation on the chain");
    for (const c of chain) if (c.revocation && c.revocation.status_ref)
      check(!sts.some(s => s.target === c.id && toTime(s.as_of) >= tInv), "unresolved", "I7", `no signed revocation status for ${c.id} as of the invocation`);
    check(isGuardrail(inv.declared.resource, extraProtected), "violated", "I9", "targets guardrail/evidence store");
    // influence (spec 5.11): trusted only if the finding exists, is signed and is labelled trusted
    const mine = effects.filter(e => e.invocation === id);
    const untrusted = (inv.influenced_by || []).filter(f => !(objs[f] && verify(objs[f]) && objs[f].integrity_label === "trusted"));
    check(untrusted.length > 0 && inv.declared.effect !== "read" && !inv.principal_confirmed, mine.length ? "violated" : "unresolved", "I4", "mutation shaped by untrusted content");
    check(!mine.length, "unresolved", "I7", "no executed-effect receipt");
    const highImpact = CEILING.indexOf(inv.declared.effect) >= CEILING.indexOf("write_shared");
    let claims = chain[0].claims; for (const c of chain.slice(1)) claims = meet(c.claims, claims);
    if ("intent_ref" in inv) claims = meet(objs[inv.intent_ref].claims, claims);
    const ap = "approval_ref" in inv ? objs[inv.approval_ref] : undefined;
    const bodies = new Map();
    for (const e of mine) {
      check(!verify(e), "unresolved", "I7", "effect receipt unsigned or signer lacks the role");
      if (highImpact) {
        check(!inv.actor, "unresolved", "I10", "actor not recorded; observer independence cannot be shown");
        check(e.observed_by === inv.actor || e.assurance === "L0", "unresolved", "I10", "high-impact effect only self-reported");
      }
      const x = e.executed;
      if ("mediated" in inv) check(canon(x) !== canon(inv.mediated), "violated", "I2", "executed differs from mediated effect");
      else check(x.action !== inv.declared.action || x.resource !== inv.declared.resource, "violated", "I2", "declared != executed");
      check(isGuardrail(x.resource, extraProtected), "violated", "I9", "executed effect targets guardrail/evidence store");
      const [ok, why] = effectOk(x, claims);
      check(!ok, "violated", why.startsWith("released") ? "I5" : "I2", why);
      // spec 5.9.1: data classes carried in through lineage (or read by this effect) reach the recipient too
      if ("recipient" in x) {
        const inherited = new Set(x.accessed || []);
        for (const j of inv.derived_from || []) for (const c of taint.get(j) || []) inherited.add(c);
        const leaked = [...inherited].map(c => `${c}->${x.recipient}`).filter(f => !(claims.data || []).includes(f)).sort();
        check(leaked.length > 0, "violated", "I5", `derived data released: ${leaked.join(", ")}`);
      }
      const d = approvalDigest(x); if (!bodies.has(d)) bodies.set(d, x);
    }
    if ("approval_ref" in inv) {
      check(!ap || !verify(ap), "unresolved", "I7", "approval missing, unsigned or not signed by an approver");
      for (const [d, x] of bodies) {
        check(ap.effect_digest !== d, "violated", "I8", "approval not bound to the executed effect");
        check(!!ap.consumed, "violated", "I8", "approval already consumed");
        check("expiry" in ap && toTime(ap.expiry) < Math.max(tInv, toTime(x.t)), "violated", "I8", "approval expired");
        check("nbf" in ap && toTime(ap.nbf) > tInv, "violated", "I8", "approval not yet valid");
        const first = approvalUse[ap.id] ??= [id, d];
        check(first[0] !== id || first[1] !== d, "violated", "I8", `approval already used by ${first[0]}`);
      }
    }
    const c = [...bodies.values()].reduce((s, x) => s + cost(x), 0);
    check("budget_spent" in inv && inv.budget_spent !== c, "violated", "I7", "recorded budget spend does not match receipts");
    const over = chain.find(n => "budget" in n.claims && (spent[n.id] || 0) + c > n.claims.budget);
    check(!!over && !ap, "violated", "I2", `risk budget of ${over && over.id} exceeded without approval`);
    for (const n of chain) spent[n.id] = (spent[n.id] || 0) + c;
  }

  // spec 10.3 decision reconciliation: only PRE-execution decisions can be contradicted or confirm a block
  const effInv = new Set(effects.map(e => e.invocation));
  for (const d of decisions) {
    if (!["deny", "hold"].includes(d.mode) || d.phase !== "pre_execution") continue;
    const en = d.enforcement || {};
    if (effInv.has(d.invocation)) { out = out.filter(r => r.id !== d.invocation); out.push({ id: d.invocation, outcome: "violated", invariant: "I11", reason: "effect despite deny" }); }
    else if (en.fail_mode === "closed" || en.applied === "confirmed") { out = out.filter(r => r.id !== d.invocation); out.push({ id: d.invocation, outcome: "preserved", invariant: "-", reason: "denied; no effect" }); }
  }
  // spec 10.4 orphan effects
  const invIds = new Set((pk.invocations || []).map(i => i.id));
  for (const e of effects) if (!invIds.has(e.invocation)) out.push({ id: e.id ?? "?", outcome: "violated", invariant: "I11", reason: "effect without any authorized invocation (bypass)" });
  state.spent = spent;
  state.approvals_used = approvalUse;
  return out;
}

// spec 10.5
export function verdict(results) {
  for (const o of ["violated", "unresolved"]) { const r = results.find(x => x.outcome === o); if (r) return r; }
  return results[0] || { id: "-", outcome: "unresolved", invariant: "I7", reason: "empty packet" };
}
