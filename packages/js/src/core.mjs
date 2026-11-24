// AMEP v0.3 evaluation core (spec/amep-v0.2.md section 10). Pure JavaScript, no I/O and no platform crypto:
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
  call_statement: ["observer"],
};
const DISPOSITIONS = ["completed", "not_executed", "failed_after_effects"];
const COST_BASE = { read: 0, write_local: 1, write_shared: 3, external_send: 5, destructive: 10, financial: 20 };
const DATA_MULT = { public: 1, internal: 1, source: 1, confidential: 2, secret: 5, phi: 5, pci: 5 };

class Malformed extends Error {}
// spec 10.5 (v0.3): a violation names the party whose own signed record departs from authority; an unresolved result
// names the one piece of evidence that would let the evaluation continue
class Stop {
  constructor(outcome, invariant, reason, { blame, need, ref, cause } = {}) {
    Object.assign(this, { outcome, invariant, reason, blame: outcome === "violated" ? blame ?? null : null,
      gaps: outcome === "unresolved" && need ? [{ need, ref: String(ref), ...(cause ? { cause } : {}) }] : [] });
  }
}
const check = (cond, outcome, invariant, reason, tags) => { if (cond) throw new Stop(outcome, invariant, reason, tags); };
const result = (id, outcome, invariant, reason, blame = null, gaps = []) => ({ id, outcome, invariant, reason, blame, gaps });

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
// denotes, so two distinct literals can never share one canonical form or approval digest. Duplicate member names
// are rejected (I-JSON, RFC 7493 2.3): parsers disagree on them (first wins, last wins, error), so a packet with
// `"amount":"10.00", "amount":"840000.00"` could verify as one value and be displayed as another. Integers are
// checked against the I-JSON range by evaluate(). The text is scanned after JSON.parse has accepted it, so it is
// valid JSON, which works on every engine without JSON.parse source-text access.
const NUMBER = /-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
export function parseStrict(text) {
  const value = JSON.parse(text);
  const stack = []; // one entry per open container: { keys: Set } for objects, null for arrays
  let expectKey = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      const start = i;
      for (i++; i < text.length && text[i] !== '"'; i++) if (text[i] === "\\") i++;
      const top = stack[stack.length - 1];
      if (top && expectKey) {
        const name = JSON.parse(text.slice(start, i + 1)); // decoded, so "a" and "a" are the same name
        if (top.keys.has(name)) throw new Malformed(`duplicate member name ${JSON.stringify(name)}`);
        top.keys.add(name);
        expectKey = false;
      }
      continue;
    }
    if (c === "{") { stack.push({ keys: new Set() }); expectKey = true; continue; }
    if (c === "[") { stack.push(null); expectKey = false; continue; }
    if (c === "}" || c === "]") { stack.pop(); expectKey = false; continue; }
    if (c === ",") { expectKey = !!stack[stack.length - 1]; continue; }
    if (c === ":") { expectKey = false; continue; }
    if (c !== "-" && (c < "0" || c > "9")) continue;
    NUMBER.lastIndex = i;
    const lit = NUMBER.exec(text)[0];
    i += lit.length - 1;
    if (/[.eE]/.test(lit) && normDec(lit) !== normDec(String(Number(lit))))
      throw new Malformed(`number literal ${lit} is not exactly representable as an IEEE 754 double`);
  }
  return value;
}

// ---- well-formedness (spec 12.1, v0.3). Bounds keep a hostile packet from exhausting a verifier; every verifier
// applies the same ones. String sizes are counted in UTF-8 bytes, which all languages agree on. ----
export const MAX_DEPTH = 32, MAX_ARRAY = 4096, MAX_STRING = 8192, MAX_NAME = 256;
const utf8Len = s => new TextEncoder().encode(s).length;
function badChar(s) {
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (c >= 0xD800 && c <= 0xDFFF) return "a lone surrogate";
    if ((c >= 0xFDD0 && c <= 0xFDEF) || (c & 0xFFFE) === 0xFFFE) return "a noncharacter";
  }
  return null;
}
// Canonical identifiers (spec 6.2, v0.3): already in NFC and without control characters, so two identifiers that
// look the same always compare the same. The verifier never normalizes silently.
function identProblem(s) {
  if (typeof s !== "string") return null;
  for (const ch of s) { const c = ch.codePointAt(0); if (c < 0x20 || (c >= 0x7F && c <= 0x9F)) return "a control character"; }
  if (s.normalize("NFC") !== s) return "a form that is not NFC";
  return null;
}
export function malformedReason(v, path = "$", depth = 0) {
  if (depth > MAX_DEPTH) return `nesting deeper than ${MAX_DEPTH} at ${path}`;
  if (typeof v === "string") {
    if (utf8Len(v) > MAX_STRING) return `string longer than ${MAX_STRING} bytes at ${path}`;
    const bad = badChar(v); return bad ? `${bad} at ${path}` : null;
  }
  if (Array.isArray(v)) {
    if (v.length > MAX_ARRAY) return `array longer than ${MAX_ARRAY} at ${path}`;
    for (let i = 0; i < v.length; i++) { const r = malformedReason(v[i], `${path}[${i}]`, depth + 1); if (r) return r; }
    return null;
  }
  if (v && typeof v === "object") {
    for (const [k, x] of Object.entries(v)) {
      if (utf8Len(k) > MAX_NAME) return `member name longer than ${MAX_NAME} bytes at ${path}`;
      const bad = badChar(k); if (bad) return `${bad} in a member name at ${path}`;
      if ((k === "action" || k === "resource")) { const p = identProblem(x); if (p) return `identifier with ${p} at ${path}.${k}`; }
      if (["actions", "resources", "deny_actions", "deny_resources"].includes(k) && Array.isArray(x)) {
        const p = x.map(identProblem).find(Boolean); if (p) return `identifier pattern with ${p} at ${path}.${k}`;
      }
      const r = malformedReason(x, `${path}.${k}`, depth + 1); if (r) return r;
    }
  }
  return null;
}

// ---- signatures (spec 12.2). One exact Ed25519 acceptance rule (v0.3), applied before the platform check, because
// libraries disagree on edge cases (Chalkias et al., "Taming the many EdDSAs", 2020). Measured: OpenSSL 3.6 accepts
// the signature (R = identity, S = 0) for EVERY message under the identity public key; OpenSSL 4.1 rejects it.
// AMEP rejects S >= L, and a public key A or commitment R that is non-canonical (y >= p) or of small order. ----
const P25519 = (1n << 255n) - 19n;
const L25519 = (1n << 252n) + 27742317777372353535851937790883648493n;
const leInt = b => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]); return n; };
const fromHex = h => Uint8Array.from(h.match(/../g) || [], x => parseInt(x, 16));
const SMALL_ORDER_Y = new Set([0n, 1n, P25519 - 1n,
  ...["26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"].map(h => leInt(fromHex(h)))]);
const pointOk = b => { if (b.length !== 32) return false; const y = leInt(b) & ((1n << 255n) - 1n); return y < P25519 && !SMALL_ORDER_Y.has(y); };
export const HEX64 = /^[0-9a-f]{64}$/, HEX128 = /^[0-9a-f]{128}$/;
export function ed25519StrictOk(xHex, sigHex) {
  if (typeof xHex !== "string" || typeof sigHex !== "string" || !HEX64.test(xHex) || !HEX128.test(sigHex)) return false;
  const sig = fromHex(sigHex);
  return pointOk(fromHex(xHex)) && pointOk(sig.slice(0, 32)) && leInt(sig.slice(32)) < L25519;
}
// A version-2 proof signs a domain-separated input, so a signature the same key made for another object kind, or for
// another system entirely, can never be presented as this AMEP object:  "AMEP-v0.3" 0x00 kind 0x00 canon(object
// without proof). A proof without "v" (version 1, AMEP v0.2) signs canon(object without proof), exactly as before.
export const SIG_CONTEXT = "AMEP-v0.3";
export function signingInput(o) {
  const body = canon(stripProof(o));
  return o.proof && o.proof.v === 2 ? `${SIG_CONTEXT}\u0000${o.kind ?? ""}\u0000${body}` : body;
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
// The executed-effect body without what only the observer knows at execution: its time `t`, and the observer's own
// running totals `value.period_spent` (spec 5.10, 7.6). Approvals bind this, so they can be issued in advance.
export function effectIdentity(x) {
  const out = Object.fromEntries(Object.entries(x).filter(([k]) => k !== "t"));
  if (out.value && typeof out.value === "object" && !Array.isArray(out.value) && "period_spent" in out.value)
    out.value = Object.fromEntries(Object.entries(out.value).filter(([k]) => k !== "period_spent"));
  return out;
}
export const approvalDigest = x => digest(effectIdentity(x));

// ---- claim algebra (spec 6.3, 7) ----
const patMatch = (v, p) => p === "*" || v === p || (p.endsWith("*") && v.startsWith(p.slice(0, -1)));
const subsumed = (cs, ps) => cs.every(c => ps.some(p => p === "*" || c === p || (p.endsWith("*") && c.replace(/\*+$/, "").startsWith(p.slice(0, -1)))));
// grants (spec 5.3, v0.3): authority as a union of (actions x resources) products instead of one product. Plain
// actions and resources are one grant. Used only in v0.3 packets; elsewhere the original single-product rules apply.
const usesGrants = (c, v03) => v03 && "grants" in c;
const grantsOf = (c, v03) => (usesGrants(c, v03) ? c.grants : [{ actions: c.actions, resources: c.resources }]);
function narrower(c, p, v03 = false) {
  if (usesGrants(c, v03) || usesGrants(p, v03)) {
    // every child grant must lie within one parent grant (sound: it never accepts a widening)
    const pg = grantsOf(p, v03);
    if (!grantsOf(c, v03).every(g => pg.some(G => subsumed(g.actions, G.actions) && subsumed(g.resources, G.resources))))
      return [false, "grants widened"];
  } else {
    if (!subsumed(c.actions, p.actions)) return [false, "actions widened"];
    if (!subsumed(c.resources, p.resources)) return [false, "resources widened"];
  }
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
function meet(a, b, v03 = false) {
  const authority = (usesGrants(a, v03) || usesGrants(b, v03))
    ? { grants: grantsOf(a, v03).flatMap(g => grantsOf(b, v03).map(G => ({ actions: g.actions.filter(x => subsumed([x], G.actions)),
        resources: g.resources.filter(x => subsumed([x], G.resources)) }))).filter(p => p.actions.length && p.resources.length) }
    : { actions: a.actions.filter(x => subsumed([x], b.actions)), resources: a.resources.filter(x => subsumed([x], b.resources)) };
  const m = { ...authority,
    data: (a.data || []).filter(d => (b.data || []).includes(d)).sort(),
    ceiling: CEILING[Math.min(CEILING.indexOf(a.ceiling), CEILING.indexOf(b.ceiling))], exp: Math.min(toTime(a.exp), toTime(b.exp)) };
  const nbfs = [a, b].filter(c => "nbf" in c).map(c => toTime(c.nbf)); if (nbfs.length) m.nbf = Math.max(...nbfs);
  if ("purpose" in a || "purpose" in b) m.purpose = a.purpose ?? b.purpose;
  for (const key of ["deny_actions", "deny_resources"]) // denies are unioned: no hop or intent can lift one
    if (key in a || key in b) m[key] = [...new Set([...(a[key] || []), ...(b[key] || [])])].sort();
  return m;
}
function effectOk(x, c, v03 = false) {
  const act = grantsOf(c, v03).filter(g => g.actions.some(p => patMatch(x.action, p)));
  if (!act.length) return [false, "action outside claims"];
  if ((c.deny_actions || []).some(p => patMatch(x.action, p))) return [false, "action denied"];
  // with grants, the action and the resource must fall within the same grant
  if (!act.some(g => g.resources.some(p => patMatch(x.resource, p)))) return [false, "resource outside claims"];
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

// ---- quantities and limits (spec 5.9, 7.6, v0.3). An executed effect may carry value = {amount, unit}: an exact
// decimal string and a unit such as "iso4217:EUR", "caip19:…", "count:records" or "bytes". Claims may carry limits
// that cap it per call and per period. Amounts are compared as exact decimals (scaled BigInts), never as floats. ----
const AMOUNT = /^(0|[1-9][0-9]{0,38})(\.[0-9]{1,18})?$/, UNIT = /^[a-z][a-z0-9-]{0,31}:[!-~]{1,128}$/;
const SCALE = 10n ** 18n;
const MONEY_UNITS = ["iso4217:", "caip19:"];
export const CLAIM_MEMBERS = new Set(["actions", "resources", "grants", "data", "ceiling", "exp", "nbf", "purpose", "deny_actions", "deny_resources", "depth", "budget", "limits"]);
const LIMIT_MEMBERS = new Set(["unit", "per_effect", "per_call", "per_period", "period", "actions", "counted_by"]);
const INTEGER_AMOUNT = /^(0|[1-9][0-9]{0,38})$/, PERIOD_KEY = /^[1-9][0-9]{0,15}$/;
// Amounts in caip19: units are integers in the asset's smallest unit, as the chain records them (spec 5.9.2).
export function amountUnits(s, unit) {
  if (unit !== undefined && unit.startsWith("caip19:") && !(typeof s === "string" && INTEGER_AMOUNT.test(s)))
    throw new Malformed(`amount ${JSON.stringify(s)} in ${unit} must be an integer in the asset's smallest unit`);
  if (typeof s !== "string" || !AMOUNT.test(s)) throw new Malformed(`malformed amount ${JSON.stringify(s)} (a decimal string such as "1200.00" is required)`);
  if (unit !== undefined && unit.startsWith("caip19:") && !INTEGER_AMOUNT.test(s))
    throw new Malformed(`amount ${JSON.stringify(s)} in ${unit} must be an integer in the asset's smallest unit`);
  const [ip, fp = ""] = s.split(".");
  return BigInt(ip) * SCALE + BigInt((fp + "0".repeat(18)).slice(0, 18));
}
// value.period_spent: the observer's own totals, keyed by period length in seconds (spec 5.9.2). Each is
// {"from": <window start>, "total": <amount>}, or a bare amount, which names no window and so never counts as a limit's
// total (amep#10). Returns period -> [window start or null, amount].
function periodSpentOf(v, unit) {
  const ps = "period_spent" in v ? v.period_spent : {};
  if (!ps || typeof ps !== "object" || Array.isArray(ps) || !Object.keys(ps).every(k => PERIOD_KEY.test(k)))
    throw new Malformed('period_spent must map period lengths in seconds to totals, for example {"2592000": {"from": 0, "total": "300.00"}}');
  return new Map(Object.entries(ps).map(([k, a]) => {
    if (a && typeof a === "object" && !Array.isArray(a)) {
      if (Object.keys(a).sort().join() !== "from,total") throw new Malformed("a period_spent total must be {from, total}");
      return [k, [toTime(a.from), amountUnits(a.total, unit)]];
    }
    return [k, [null, amountUnits(a, unit)]];
  }));
}
const unitOf = u => { if (typeof u !== "string" || !UNIT.test(u)) throw new Malformed(`malformed unit ${JSON.stringify(u)}`); return u; };
const unitsStr = u => { const ip = u / SCALE, fp = (u % SCALE).toString().padStart(18, "0").replace(/0+$/, ""); return fp ? `${ip}.${fp}` : `${ip}`; };
export const isExtensionMember = name => name.startsWith("x-") || name.includes(".");
function checkLimits(lims) {
  if (!Array.isArray(lims) || !lims.length) throw new Malformed("limits must be a non-empty array");
  for (const lim of lims) {
    if (!lim || typeof lim !== "object" || Array.isArray(lim)) throw new Malformed("limit must be an object");
    const unit = unitOf(lim.unit);
    for (const k of ["per_effect", "per_call"]) if (k in lim) amountUnits(lim[k], unit);
    if (("per_period" in lim) !== ("period" in lim)) throw new Malformed("per_period and period go together");
    if ("counted_by" in lim && !(typeof lim.counted_by === "string" && lim.counted_by)) throw new Malformed("counted_by must name an observer");
    if ("per_period" in lim) {
      amountUnits(lim.per_period, unit);
      if (!Number.isInteger(lim.period) || lim.period <= 0) throw new Malformed("period must be a positive integer number of seconds");
    }
    if ("actions" in lim && !(Array.isArray(lim.actions) && lim.actions.every(p => typeof p === "string")))
      throw new Malformed("limit actions must be an array of action patterns");
  }
  return lims;
}
// The running-total key of one limit window (spec 7.6): one total per limit, so limits that differ only in their actions
// are separate caps (amep#10).
// Start time of the limit window that contains t (spec 7.6): windows of `period` seconds from the node's nbf, or 0.
function windowStart(node, lim, t) {
  const anchor = "nbf" in node.claims ? toTime(node.claims.nbf) : 0;
  return anchor + Math.floor((toTime(t) - anchor) / lim.period) * lim.period;
}
function periodKey(node, lim, unit, t) {
  const anchor = "nbf" in node.claims ? toTime(node.claims.nbf) : 0;
  const window = Math.floor((toTime(t) - anchor) / lim.period);
  return `${node.id}|${unit}|${lim.period}|${window}` + ("actions" in lim ? `|${[...lim.actions].sort().join(",")}` : "");
}
// An invocation's reserve (spec 5.8, v0.3): {amount, unit}, the most the call can move in the unit.
function checkReserve(r) {
  if (!r || typeof r !== "object" || Array.isArray(r) || Object.keys(r).sort().join() !== "amount,unit")
    throw new Malformed("reserve must be an object with exactly amount and unit");
  amountUnits(r.amount, unitOf(r.unit));
  return r;
}
// Verifier state's holds (spec 10.7, v0.3): invocation digest -> {invocation, amounts: {period key: amount | null}}.
function heldOf(state) {
  const h = "held" in state ? state.held : {};
  const ok = h && typeof h === "object" && !Array.isArray(h) && Object.values(h).every(v =>
    v && typeof v === "object" && typeof v.invocation === "string" && v.amounts && typeof v.amounts === "object" && !Array.isArray(v.amounts)
    && Object.values(v.amounts).every(a => a === null || (typeof a === "string" && AMOUNT.test(a))));
  if (!ok) throw new Malformed("state.held must map invocation digests to {invocation, amounts}");
  return h;
}
// Verifier state's approval holds (spec 5.10, held approvals, v0.3): approval id -> {invocation, digest} of the earlier
// invocation that cited it and whose outcome is still unknown.
function approvalsHeldOf(state) {
  const h = "approvals_held" in state ? state.approvals_held : {};
  const ok = h && typeof h === "object" && !Array.isArray(h) && Object.values(h).every(v =>
    v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).sort().join() === "digest,invocation"
    && typeof v.invocation === "string" && typeof v.digest === "string" && /^[0-9a-f]{64}$/.test(v.digest));
  if (!ok) throw new Malformed("state.approvals_held must map approval ids to {invocation, digest}");
  return h;
}
// A limit with `actions` applies to effects whose action matches; without, to every financial effect.
const limitApplies = (lim, x) => ("actions" in lim) ? lim.actions.some(p => patMatch(x.action, p)) : x.effect === "financial";
// I1 for limits: a child may add limits, but never raise one the parent sets for the same unit and period.
function limitsNarrower(c, p) {
  for (const pl of p.limits || []) for (const cl of c.limits || []) {
    if (cl.unit !== pl.unit || JSON.stringify(cl.actions) !== JSON.stringify(pl.actions)) continue;
    for (const k of ["per_effect", "per_call"])
      if (k in pl && k in cl && amountUnits(cl[k]) > amountUnits(pl[k])) return `${k.replace("_", "-")} limit raised for ${pl.unit}`;
    if ("per_period" in pl && cl.period === pl.period && "per_period" in cl && amountUnits(cl.per_period) > amountUnits(pl.per_period))
      return `per-period limit raised for ${pl.unit}`;
  }
  return null;
}
function revocationWindow(node) {
  const w = (node.revocation || {}).window ?? 0;
  if (typeof w !== "number" || !Number.isFinite(w) || w < 0) throw new Malformed("revocation window must be a non-negative number of seconds");
  return w;
}
const fmt = n => String(n); // Python's :g for the integer and short decimal times used in reasons

// ---- evaluation (spec 10) ----
// state (spec 10.6): { approvals_used: {id: [invocation, digest]}, spent: {node: points}, period_totals: {key: amount} },
// read on entry and updated on exit, so approval single use, risk budgets and period limits hold across packets.
const allUnresolved = (pk, reason) => {
  const ids = (pk.invocations || []).map(i => (i && typeof i === "object" && i.id) || "?");
  return (ids.length ? ids : ["-"]).map(id => result(id, "unresolved", "I7", reason, null, [{ need: "well_formed_packet", ref: "-" }]));
};
export function evaluateText(text, keys, sigOk, extraProtected = [], state = {}) {
  let pk;
  try { pk = parseStrict(text); } catch (e) { return [result("-", "unresolved", "I7", `malformed packet text: ${e.message}`, null, [{ need: "well_formed_packet", ref: "-" }])]; }
  return evaluate(pk, keys, sigOk, extraProtected, state);
}
export function evaluate(pk, keys, sigOk, extraProtected = [], state = {}) {
  if (!pk || typeof pk !== "object" || Array.isArray(pk)) return [result("-", "unresolved", "I7", "packet is not a JSON object", null, [{ need: "well_formed_packet", ref: "-" }])];
  let bad = unsafeNumber(pk);
  if (bad) return allUnresolved(pk, `number outside the I-JSON range at ${bad}`); // spec 12.1
  bad = malformedReason(pk);
  if (bad) return allUnresolved(pk, `malformed packet: ${bad}`); // spec 12.1 (v0.3)
  const version = pk.amep_version ?? null;
  if (![null, "0.2", "0.3"].includes(version)) return allUnresolved(pk, `unsupported amep_version ${JSON.stringify(version)}`); // spec 16
  const v03 = version === "0.3";
  // Object ids are unique within a packet (spec 5.2, v0.3): two objects with one id would let a receipt or a
  // statement be read as evidence for the wrong one.
  const seenIds = new Set();
  for (const kind of ["mandates", "delegations", "intents", "interpretations", "invocations", "effects", "approvals", "findings", "call_statements"])
    for (const o of pk[kind] || []) if (o && typeof o === "object" && "id" in o) {
      if (seenIds.has(o.id)) return allUnresolved(pk, `malformed packet: duplicate object id ${JSON.stringify(o.id)}`);
      seenIds.add(o.id);
    }
  // signature valid AND the signing key holds a role allowed for this object kind (spec 12.5), under the exact
  // Ed25519 acceptance rule; AMEP 0.3 packets must use domain-separated (version 2) proofs
  const verify = o => {
    if (!o || typeof o !== "object" || !o.proof || o.proof.alg !== "Ed25519") return false;
    const pv = "v" in o.proof ? o.proof.v : 1;
    if (![1, 2].includes(pv) || (v03 && pv !== 2)) return false;
    const k = keys[o.proof.kid]; if (!k || k.alg !== "Ed25519") return false;
    if (!(k.roles || []).some(r => (SIGNER_ROLES[o.kind] || []).includes(r))) return false;
    if (!ed25519StrictOk(k.x, o.proof.sig)) return false;
    try { return sigOk(o, k); } catch { return false; }
  };
  // spec 12.5 (v0.3): a key may name the operator that controls it. Two keys with the same operator are one party for
  // observer independence (I10), whatever identifiers their records use.
  const operatorOf = o => { const kid = o && o.proof ? o.proof.kid : undefined;
    const k = typeof kid === "string" && Object.hasOwn(keys, kid) ? keys[kid] : null;
    return k && typeof k.operator === "string" ? k.operator : null; };
  const sameOperator = (a, b) => { const x = operatorOf(a); return x !== null && x === operatorOf(b); };
  // spec 10.5.1 (v0.3): why a refused signature was refused, in a fixed order every verifier shares
  const sigCause = o => {
    if (!o || typeof o !== "object" || Array.isArray(o) || !o.proof || typeof o.proof !== "object" || Array.isArray(o.proof)) return "missing";
    const kid = o.proof.kid;
    const k = typeof kid === "string" && Object.hasOwn(keys, kid) ? keys[kid] : null;
    if (!k || typeof k !== "object" || Array.isArray(k)) return "unknown_key";
    const roles = Array.isArray(k.roles) ? k.roles.filter(r => typeof r === "string") : [];
    if (!roles.some(r => (SIGNER_ROLES[o.kind] || []).includes(r))) return "role";
    return "invalid";
  };
  const firstCause = os => { const o = os.find(x => !verify(x)); return os.some(x => !verify(x)) ? sigCause(o) : undefined; };
  const objs = {};
  for (const kind of ["mandates", "delegations", "intents", "interpretations", "invocations", "effects", "approvals", "findings"])
    for (const o of pk[kind] || []) if (o && typeof o === "object" && "id" in o) objs[o.id] = o;
  const revocations = pk.revocations || [], statuses = pk.statuses || [], effects = pk.effects || [];
  const spent = { ...(state.spent || {}) };
  const totals = new Map(Object.entries(state.period_totals || {}).map(([k, v]) => [k, amountUnits(v)]));
  const priorWindows = new Set(totals.keys());
  // spec 7.6 rule 6 (v0.3): holds for earlier invocations whose outcome was unknown. A packet that contains a held
  // invocation decides it afresh, so its hold is set aside while this packet is evaluated, and never counted twice.
  let heldIn, apprHeldIn;
  try { heldIn = heldOf(state); apprHeldIn = approvalsHeldOf(state); } catch (e) { return allUnresolved(pk, `malformed verifier state: ${e.message}`); }
  const present = new Set();
  for (const i of pk.invocations || []) { try { present.add(digest(i)); } catch { /* reported by its own evaluation */ } }
  const held = Object.fromEntries(Object.entries(heldIn).filter(([d]) => !present.has(d))), newHeld = {};
  // spec 5.10, held approvals (v0.3): approvals held for earlier invocations whose outcome is unknown; one held by an invocation
  // in this packet is set aside, since this packet decides that invocation afresh
  const apprHeld = Object.fromEntries(Object.entries(apprHeldIn).filter(([, h]) => !present.has(h.digest)));
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
      check(leaked.length > 0 && !inv.principal_confirmed, "violated", "I4", `quarantined content reached the agent (${leaked.join(", ")})`, { blame: "host" });
      const why = evalInvocation(inv);
      out.push(result(id, "preserved", "-", why || "continuity preserved"));
    } catch (e) {
      if (e instanceof Stop) out.push(result(id, e.outcome, e.invariant, e.reason, e.blame, e.gaps));
      else out.push(result(id, "unresolved", "I7", `malformed evidence: ${e.message}`, null, [{ need: "well_formed_evidence", ref: String(id) }]));
    }
  }

  function evalInvocation(inv) {
    const id = inv.id, tInv = toTime(inv.t);
    const chain = []; const seen = new Set(); let n = objs[inv.authority_ref];
    while (n && !seen.has(n.id)) { seen.add(n.id); chain.unshift(n); n = objs[n.parent]; }
    check(!chain.length || chain[0].kind !== "mandate", "unresolved", "I7", "no root mandate", { need: "root_mandate", ref: inv.authority_ref ?? "-" });
    const interp = objs[inv.interpretation_ref];
    const needed = [...chain, inv, ...(interp ? [interp] : [])];
    let intent = null;
    if ("intent_ref" in inv) {
      intent = objs[inv.intent_ref];
      check(!intent || intent.kind !== "intent", "unresolved", "I7", "cited intent not found", { need: "intent", ref: inv.intent_ref ?? "-" });
      needed.push(intent);
    }
    check(needed.some(o => !verify(o)), "unresolved", "I7", "missing or invalid signature, or signer lacks the role", { need: "signature", ref: id, cause: firstCause(needed) });
    check((inv.derived_from || []).some(j => (order.get(j) ?? order.get(id)) >= order.get(id)), "unresolved", "I7", "lineage reference not found among earlier invocations", { need: "lineage", ref: id });
    // claim members (spec 16, v0.3): an unknown claim member may be a constraint this verifier cannot enforce, so it
    // is never ignored. Limits are validated wherever they appear.
    const nodes = [...chain, ...(intent ? [intent] : [])];
    const limited = nodes.filter(x => "limits" in x.claims);
    for (const x of limited) checkLimits(x.claims.limits);
    // grants are an AMEP 0.3 member. Ignored, as v0.2 ignores unknown members, they could widen authority the
    // producer meant to narrow, so an unversioned packet that uses them is malformed instead.
    if (!v03) for (const x of nodes)
      check("grants" in x.claims, "unresolved", "I7", `${x.id}: grants require amep_version 0.3`, { need: "well_formed_evidence", ref: x.id });
    if (v03 && "reserve" in inv) {
      try { checkReserve(inv.reserve); }
      catch (e) { if (!(e instanceof Malformed)) throw e; check(true, "unresolved", "I7", `${id}: ${e.message}`, { need: "reserve", ref: id }); }
    }
    if (v03) for (const x of nodes) {
      let unknown = Object.keys(x.claims).filter(k => !CLAIM_MEMBERS.has(k) && !isExtensionMember(k)).sort();
      check(unknown.length > 0, "unresolved", "I7", `${x.id}: claim member not understood (${unknown.join(", ")})`, { need: "verifier_support", ref: x.id });
      if ("grants" in x.claims) {
        const g = x.claims.grants;
        const ok = Array.isArray(g) && g.length > 0 && !("actions" in x.claims) && !("resources" in x.claims)
          && g.every(e => e && typeof e === "object" && !Array.isArray(e) && Object.keys(e).sort().join() === "actions,resources"
            && ["actions", "resources"].every(k => Array.isArray(e[k]) && e[k].length > 0 && e[k].every(p => typeof p === "string")));
        check(!ok, "unresolved", "I7", `${x.id}: grants must be a non-empty list of {actions, resources}, without actions or resources beside it`,
          { need: "well_formed_evidence", ref: x.id });
      }
      for (const lim of x.claims.limits || []) {
        unknown = Object.keys(lim).filter(k => !LIMIT_MEMBERS.has(k) && !isExtensionMember(k)).sort();
        check(unknown.length > 0, "unresolved", "I7", `${x.id}: limit member not understood (${unknown.join(", ")})`, { need: "verifier_support", ref: x.id });
      }
    }
    check(!interp || !["curated", "customer"].includes(interp.source), "unresolved", "I3", "no approved interpretation", { need: "interpretation", ref: inv.interpretation_ref ?? "-" });
    const pinned = pk.pinned_adapters || {};
    check(Object.keys(pinned).length > 0 && pinned[interp.adapter] !== interp.version, "unresolved", "I3", "adapter revision not approved (pin mismatch)", { need: "interpretation_pin", ref: inv.interpretation_ref ?? "-" });
    for (let i = 1; i < chain.length; i++) {
      const [ok, why] = narrower(chain[i].claims, chain[i - 1].claims, v03); check(!ok, "violated", "I1", `${chain[i].id}: ${why}`, { blame: "delegator" });
      const lw = limitsNarrower(chain[i].claims, chain[i - 1].claims); check(!!lw, "violated", "I1", `${chain[i].id}: ${lw}`, { blame: "delegator" });
    }
    // liveness (spec 5.12), at the invocation and at each effect's own time. A revocation still inside the revoked
    // node's declared propagation window is unresolved, not violated (spec 5.12.1, v0.3).
    const ids = new Set(chain.map(c => c.id)), byId = new Map(chain.map(c => [c.id, c]));
    const revs = revocations.filter(r => ids.has(r.target));
    const sts = statuses.filter(s => ids.has(s.target) && verify(s));
    const revokedAt = [...revs.filter(r => verify(r)).map(r => [toTime(r.t), r.target, "ancestor revoked"]),
      ...sts.filter(s => s.revoked_at != null).map(s => [toTime(s.revoked_at), s.target, "status shows ancestor revoked"])]
      .sort((a, b) => a[0] - b[0] || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) || (a[2] < b[2] ? -1 : a[2] > b[2] ? 1 : 0));
    const liveness = (t, what) => {
      for (const [rT, target, why] of revokedAt) if (rT <= t) {
        const w = revocationWindow(byId.get(target));
        check(t < rT + w, "unresolved", "I6", `${why} ${fmt(t - rT)}s before ${what}, inside its ${fmt(w)}s propagation window`, { blame: "agent", need: "revocation_settled", ref: target });
        check(true, "violated", "I6", `${why} before ${what}`, { blame: "agent" });
      }
    };
    const freshStatus = (t, what) => {
      for (const c of chain) if (c.revocation && c.revocation.status_ref)
        check(!sts.some(s => s.target === c.id && toTime(s.as_of) >= t), "unresolved", "I7", `no signed revocation status for ${c.id} as of ${what}`, { need: "revocation_status", ref: c.id });
    };
    liveness(tInv, "invocation");
    check(revs.some(r => !verify(r)), "unresolved", "I7", "unverifiable revocation on the chain", { need: "revocation_signature", ref: id, cause: firstCause(revs) });
    freshStatus(tInv, "the invocation");
    check(isGuardrail(inv.declared.resource, extraProtected), "violated", "I9", "targets guardrail/evidence store", { blame: "agent" });
    // influence (spec 5.11): trusted only if the finding exists, is signed and is labelled trusted
    const mine = effects.filter(e => e.invocation === id);
    const untrusted = (inv.influenced_by || []).filter(f => !(objs[f] && verify(objs[f]) && objs[f].integrity_label === "trusted"));
    check(untrusted.length > 0 && inv.declared.effect !== "read" && !inv.principal_confirmed, mine.length ? "violated" : "unresolved", "I4", "mutation shaped by untrusted content", { blame: "agent", need: "principal_confirmation", ref: id });
    // call statements (spec 5.14, v0.3): the observer's signed account of the whole call. It binds the call to this
    // exact signed invocation and to the arguments the server received, says whether anything was executed, and how
    // many receipts to expect, so that "no receipt" is no longer ambiguous.
    const invDigest = digest(inv);
    const stmts = (pk.call_statements || []).filter(c => c && typeof c === "object" && c.invocation === id);
    for (const c of stmts) {
      check(!verify(c), "unresolved", "I7", "call statement unsigned or signer lacks the role", { need: "call_statement_signature", ref: c.id ?? "?", cause: firstCause([c]) });
      check(!DISPOSITIONS.includes(c.disposition), "unresolved", "I7", "call statement with an unknown disposition", { need: "call_statement", ref: c.id ?? "?" });
      check(!Number.isInteger(c.effect_count) || c.effect_count < 0, "unresolved", "I7", "call statement effect_count must be a non-negative integer", { need: "call_statement", ref: c.id ?? "?" });
      check(c.disposition === "not_executed" && c.effect_count !== 0, "unresolved", "I7", "call statement says not executed but counts effects", { need: "call_statement", ref: c.id ?? "?" });
      check("invocation_digest" in c && c.invocation_digest !== invDigest, "unresolved", "I7", "call statement is bound to a different invocation (invocation_digest mismatch)", { need: "call_statement_binding", ref: c.id ?? "?" });
    }
    const notExecuted = stmts.some(c => c.disposition === "not_executed");
    const sentArgs = inv.args_digest;
    const rewritten = stmts.filter(c => sentArgs !== undefined && sentArgs !== null && "args_digest" in c && c.args_digest !== sentArgs);
    check(rewritten.length > 0 && !notExecuted, "violated", "I2", "the arguments the server received differ from those the host signed (changed in transit)", { blame: "transport" });
    check(rewritten.length > 0, "unresolved", "I7", "the arguments were changed in transit; the server executed nothing", { need: "unaltered_call", ref: id });
    check(notExecuted && mine.length > 0, "violated", "I11", "effect receipts contradict a signed not_executed statement", { blame: "server" });
    if (!mine.length && notExecuted) {
      // provably nothing was executed; for a high-impact call the statement must come from a party other than the actor (I10)
      const hi = CEILING.indexOf(inv.declared.effect) >= CEILING.indexOf("write_shared");
      check(hi && stmts.filter(c => c.disposition === "not_executed").every(c => c.observed_by === inv.actor || sameOperator(c, inv)),
        "unresolved", "I10", "high-impact call reported not executed only by the actor itself, or by a key of the host's own operator", { need: "independent_observer", ref: id });
      // say why it is preserved: nothing ran, on the observer's signed word, not "within authority"
      const who = [...new Set(stmts.filter(c => c.disposition === "not_executed").map(c => String(c.observed_by)))].sort().join(", ");
      return `nothing executed: ${who} signed a not_executed call statement`;
    }
    // effect receipts. With none and no not_executed statement, the call may still have moved value: hold its reserve (or
    // an unknown amount) against every period limit on its chain that applies to it (spec 7.6 rule 6).
    if (!mine.length) {
      const reserve = v03 ? inv.reserve : undefined, amounts = {};
      for (const node of limited) for (const lim of node.claims.limits)
        if ("per_period" in lim && limitApplies(lim, inv.declared))
          amounts[periodKey(node, lim, lim.unit, inv.t)] = reserve !== undefined && reserve.unit === lim.unit ? reserve.amount : null;
      if (Object.keys(amounts).length) newHeld[invDigest] = { invocation: id, amounts };
      // spec 5.10, held approvals (v0.3): the call may have run under its approval, so the approval is held for it until its
      // outcome is known (from Takao Sato's VATE case 2)
      const ref = inv.approval_ref;
      if (typeof ref === "string" && !Object.hasOwn(apprHeld, ref)) apprHeld[ref] = { invocation: id, digest: invDigest };
    }
    check(!mine.length, "unresolved", "I7", "no executed-effect receipt", { need: "receipt", ref: id });
    const highImpact = CEILING.indexOf(inv.declared.effect) >= CEILING.indexOf("write_shared");
    let claims = chain[0].claims; for (const c of chain.slice(1)) claims = meet(c.claims, claims, v03);
    if (intent) claims = meet(intent.claims, claims, v03);
    const ap = "approval_ref" in inv ? objs[inv.approval_ref] : undefined;
    const byObserver = new Map();   // observer -> effect identity digest -> its receipts, in packet order
    for (const e of mine) {
      check(!verify(e), "unresolved", "I7", "effect receipt unsigned or signer lacks the role", { need: "receipt_signature", ref: e.id ?? "?", cause: firstCause([e]) });
      check(typeof e.observed_by !== "string", "unresolved", "I7", `receipt ${e.id ?? "?"} names no observer`, { need: "receipt_observer", ref: e.id ?? "?" });
      check("invocation_digest" in e && e.invocation_digest !== invDigest, "unresolved", "I7", `receipt ${e.id ?? "?"} is bound to a different invocation (invocation_digest mismatch)`, { need: "receipt_binding", ref: e.id ?? "?" });
      if (highImpact) {
        check(!inv.actor, "unresolved", "I10", "actor not recorded; observer independence cannot be shown", { need: "actor", ref: id });
        check(e.observed_by === inv.actor || e.assurance === "L0", "unresolved", "I10", "high-impact effect only self-reported", { need: "independent_observer", ref: e.id ?? "?" });
        check(sameOperator(e, inv), "unresolved", "I10", "high-impact effect observed only by a key of the host's own operator", { need: "independent_observer", ref: e.id ?? "?" });
      }
      const x = e.executed;
      // liveness at each effect's own time (spec 8 I6, v0.3): authority must still be in force when the effect occurs,
      // not only when it was invoked. Proposed by Cliff Singletary on audit@ietf.org, 19 Nov 2026.
      liveness(toTime(x.t), `effect ${e.id ?? "?"}`);
      freshStatus(toTime(x.t), `effect ${e.id ?? "?"}`);
      if ("mediated" in inv) check(canon(x) !== canon(inv.mediated), "violated", "I2", "executed differs from mediated effect", { blame: "server" });
      else check(x.action !== inv.declared.action || x.resource !== inv.declared.resource, "violated", "I2", "declared != executed", { blame: "server" });
      check(isGuardrail(x.resource, extraProtected), "violated", "I9", "executed effect targets guardrail/evidence store", { blame: "agent" });
      const [ok, why] = effectOk(x, claims, v03);
      check(!ok, "violated", why.startsWith("released") ? "I5" : "I2", why, { blame: "agent" });
      // spec 5.9.1: data classes carried in through lineage (or read by this effect) reach the recipient too
      if ("recipient" in x) {
        const inherited = new Set(x.accessed || []);
        for (const j of inv.derived_from || []) for (const c of taint.get(j) || []) inherited.add(c);
        const leaked = [...inherited].map(c => `${c}->${x.recipient}`).filter(f => !(claims.data || []).includes(f)).sort();
        check(leaked.length > 0, "violated", "I5", `derived data released: ${leaked.join(", ")}`, { blame: "agent" });
      }
      if ("value" in x) { // validate wherever present, so a malformed amount is never silently ignored
        const v = x.value;
        check(!v || typeof v !== "object" || Array.isArray(v), "unresolved", "I7", "value must be an object", { need: "value", ref: e.id ?? "?" });
        unitOf(v.unit); amountUnits(v.amount, v.unit); periodSpentOf(v, v.unit);
      }
      const d = approvalDigest(x);
      if (!byObserver.has(e.observed_by)) byObserver.set(e.observed_by, new Map());
      const m = byObserver.get(e.observed_by); if (!m.has(d)) m.set(d, []); m.get(d).push(e);
    }
    // spec 10.2 (v0.3): the same effect recorded by several observers counts once, but within one observer every receipt
    // is its own effect. An effect occurs as often as the most any one observer recorded it, taken from that observer's
    // receipts. Raised by Carlos Vendrell Felici (stafordtituss/amep#10): two identical payments in one call counted as one.
    const effectsOf = [];   // [executed body, identity digest, observer]
    const digests = [...new Set([...byObserver.values()].flatMap(m => [...m.keys()]))];
    for (const d of digests) {
      const holders = [...byObserver.keys()].filter(o => byObserver.get(o).has(d)).sort();
      let obs = holders[0];
      for (const o of holders) if (byObserver.get(o).get(d).length > byObserver.get(obs).get(d).length) obs = o;
      for (const e of byObserver.get(obs).get(d)) effectsOf.push([e.executed, d, obs]);
    }
    const bodies = new Map(effectsOf.map(([x, d]) => [d, x]));
    // every receipt a statement promises must be present, and no more (spec 5.14)
    for (const c of stmts) {
      const k = mine.filter(e => e.observed_by === c.observed_by).length;
      check(k > c.effect_count, "violated", "I7", `${k} receipts from ${c.observed_by} but its call statement counts ${c.effect_count}`, { blame: "server" });
      check(k < c.effect_count, "unresolved", "I7", `call statement promises ${c.effect_count} receipts from ${c.observed_by}, ${k} present (lost or withheld)`, { need: "receipt", ref: id });
    }
    if ("approval_ref" in inv) {
      check(!ap || !verify(ap), "unresolved", "I7", "approval missing, unsigned or not signed by an approver", { need: "approval", ref: inv.approval_ref ?? "-" });
      // An operation approval (spec 5.10, v0.3) lists the digests of the effects of one call instead of one digest.
      // From Takao Sato's VATE case 1 (openid/authzen#795): one admission covering an operation that writes two files.
      const listed = "effect_digests" in ap ? ap.effect_digests : null;
      let opUse = null;
      if ("effect_digests" in ap) {
        check("effect_digest" in ap || !Array.isArray(listed) || !listed.length || !listed.every(x => typeof x === "string" && /^[0-9a-f]{64}$/.test(x)),
          "unresolved", "I7", "an operation approval needs a non-empty effect_digests list of digests, and no effect_digest",
          { need: "approval", ref: ap.id ?? "?" });
        opUse = "set:" + sha256Hex(canon([...listed].sort()));
      } else { // neither form: malformed (spec 5.10), the same result in every verifier
        check(!("effect_digest" in ap), "unresolved", "I7", "approval has no effect_digest or effect_digests",
          { need: "approval", ref: ap.id ?? "?" });
      }
      for (const [d, x] of bodies) {
        const nExec = effectsOf.filter(([, dd]) => dd === d).length;
        if (listed === null) {
          check(ap.effect_digest !== d, "violated", "I8", "approval not bound to the executed effect", { blame: "agent" });
          check(nExec > 1, "violated", "I8", `one approval, but the approved effect was executed ${nExec} times`, { blame: "agent" });
        } else {
          const nOk = listed.filter(y => y === d).length;
          check(nExec > nOk, "violated", "I8", nOk === 0 ? "the operation approval does not cover the executed effect"
            : `the operation approval covers this effect ${nOk} time(s), but it was executed ${nExec} times`, { blame: "agent" });
        }
        check(!!ap.consumed, "violated", "I8", "approval already consumed", { blame: "agent" });
        check("expiry" in ap && toTime(ap.expiry) < Math.max(tInv, toTime(x.t)), "violated", "I8", "approval expired", { blame: "agent" });
        check("nbf" in ap && toTime(ap.nbf) > tInv, "violated", "I8", "approval not yet valid", { blame: "agent" });
      }
      // spec 5.10, held approvals: after every check that decides violated, so a hold never hides a violation
      const holder = Object.hasOwn(apprHeld, ap.id) && bodies.size ? apprHeld[ap.id] : null;
      check(holder !== null && holder.invocation !== id, "unresolved", "I7",
        `approval ${ap.id} is held for ${holder?.invocation}, whose outcome is unknown`, { need: "held_outcome", ref: holder?.invocation });
      for (const d of bodies.keys()) {
        const use = listed === null ? d : opUse;
        const first = approvalUse[ap.id] ??= [id, use];
        check(first[0] !== id || first[1] !== use, "violated", "I8", `approval already used by ${first[0]}`, { blame: "agent" });
      }
    }
    // quantity limits (spec 7.6, v0.3), on every node of the chain and on the intent. An approval that passed I8
    // authorizes going over a limit; the amount still counts toward the period total. Every applicable limit is checked
    // before the result is decided, and a violation beats an unresolved check, so the verdict doesn't depend on the
    // order the limits are listed in (amep#10, vendrell46).
    const deferred = [];
    const defer = f => { try { f(); } catch (e) { if (e instanceof Stop) deferred.push(e); else throw e; } };
    for (const node of limited) {
      const callSum = new Map();   // limit index -> amount moved by this call so far
      for (const [x, , obs] of effectsOf) {
        const applicable = node.claims.limits.map((lim, i) => [i, lim]).filter(([, lim]) => limitApplies(lim, x));
        if (!applicable.length) continue;
        let v, unit, amt, matching, ok = false;
        defer(() => {
          v = x.value;
          check(v === undefined, "unresolved", "I7", `${node.id} limits this effect but the receipt records no value`, { need: "value", ref: node.id });
          unit = v.unit; amt = amountUnits(v.amount, unit);
          matching = applicable.filter(([, lim]) => lim.unit === unit);
          if (!matching.length) {
            const money = MONEY_UNITS.some(m => unit.startsWith(m)) || x.effect === "financial";
            check(money, "violated", "I2", `${unit} is not an asset ${node.id} authorizes`, { blame: "agent" });
            check(true, "unresolved", "I7", `${node.id} limits this effect in another unit than ${unit}`, { need: "value", ref: node.id });
          }
          ok = true;
        });
        if (!ok) continue;
        for (const [i, lim] of matching) defer(() => checkLimit(node, i, lim, x, v, unit, amt, obs, callSum));
      }
    }
    for (const o of ["violated", "unresolved"]) { const d = deferred.find(e => e.outcome === o); if (d) throw d; }
    // One applicable limit of node for one effect x (spec 7.6 rules 3 to 6). Throws Stop on the first failed check.
    function checkLimit(node, i, lim, x, v, unit, amt, obs, callSum) {
      check("per_effect" in lim && amt > amountUnits(lim.per_effect) && !ap, "violated", "I2",
        `amount ${v.amount} ${unit} exceeds the per-effect limit ${lim.per_effect} of ${node.id}`, { blame: "agent" });
      callSum.set(i, (callSum.get(i) ?? 0n) + amt);
      check("per_call" in lim && callSum.get(i) > amountUnits(lim.per_call) && !ap, "violated", "I2",
        `this call moves ${unitsStr(callSum.get(i))} ${unit}, over the per-call limit ${lim.per_call} of ${node.id}`, { blame: "agent" });
      if (!("per_period" in lim)) return;
      const key = periodKey(node, lim, unit, x.t), start = windowStart(node, lim, x.t);
      let total = (totals.get(key) ?? 0n) + amt;
      // An observer's total is the principal's total only when that observer sees all of this node's spending in the
      // unit (the limit names it in counted_by, amep#10), and only for this limit's own window: the figure must say the
      // window starts where the limit's does (amep#10, vendrell46). Other figures never count.
      const entry = lim.counted_by === obs ? periodSpentOf(v, unit).get(String(lim.period)) : undefined;
      const counted = entry !== undefined && entry[0] !== null && entry[0] === start ? entry[1] : undefined;
      if (counted !== undefined) {
        check(counted < total, "violated", "I7", `${obs}'s period total ${unitsStr(counted)} ${unit} is below the payments recorded for ${node.id}`, { blame: "server" });
        total = counted;
      }
      check(total > amountUnits(lim.per_period) && !ap, "violated", "I2",
        `period total ${unitsStr(total)} ${unit} exceeds the per-period limit ${lim.per_period} of ${node.id}`, { blame: "agent" });
      check(counted === undefined && !priorWindows.has(key), "unresolved", "I7",
        `period total for ${node.id} cannot be established: no total from its counting observer for this window and no earlier state`, { need: "period_total", ref: node.id });
      // holds (spec 7.6 rule 6): an earlier call with an unknown outcome may already have spent part of this window. An
      // approval that passed I8 authorizes going over the limit for its effect, so holds don't block it.
      const holds = Object.values(held).filter(h => key in h.amounts).map(h => [h.invocation, h.amounts[key]]);
      if (holds.length && !ap) {
        const unknown = holds.filter(([, a]) => a === null).map(([h]) => h);
        check(unknown.length > 0, "unresolved", "I7",
          `the outcome of ${unknown[0] ?? ""} is unknown, so the period total of ${node.id} cannot be bounded`,
          { need: "held_outcome", ref: unknown[0] ?? "-" });
        const heldSum = holds.reduce((s, [, a]) => s + amountUnits(a, unit), 0n);
        check(total + heldSum > amountUnits(lim.per_period), "unresolved", "I7",
          `period total ${unitsStr(total)} ${unit} plus ${unitsStr(heldSum)} held for ${holds.map(([h]) => h).join(", ")} would exceed the per-period limit ${lim.per_period} of ${node.id}`,
          { need: "held_outcome", ref: holds[0][0] });
      }
      totals.set(key, total);
    }
    const c = effectsOf.reduce((s, [x]) => s + cost(x), 0);
    check("budget_spent" in inv && inv.budget_spent !== c, "violated", "I7", "recorded budget spend does not match receipts", { blame: "host" });
    const over = chain.find(n => "budget" in n.claims && (spent[n.id] || 0) + c > n.claims.budget);
    check(!!over && !ap, "violated", "I2", `risk budget of ${over && over.id} exceeded without approval`, { blame: "agent" });
    for (const n of chain) spent[n.id] = (spent[n.id] || 0) + c;
  }

  // spec 10.3 decision reconciliation: only PRE-execution decisions can be contradicted or confirm a block
  const effInv = new Set(effects.map(e => e.invocation));
  for (const d of decisions) {
    if (!["deny", "hold"].includes(d.mode) || d.phase !== "pre_execution") continue;
    const en = d.enforcement || {};
    if (effInv.has(d.invocation)) { out = out.filter(r => r.id !== d.invocation); out.push(result(d.invocation, "violated", "I11", "effect despite deny", "host")); }
    else if (en.fail_mode === "closed" || en.applied === "confirmed") {
      // both fields are declared by the host that signed the deny, so they never settle "nothing executed": only a
      // not_executed statement from an observer does, which the call's own evaluation already honours. They change
      // nothing for read and write_local; for a high-impact call, the missing independent record is named (I10).
      const inv = (pk.invocations || []).find(i => i.id === d.invocation);
      const low = !!inv && ["read", "write_local"].includes((inv.declared || {}).effect);
      const cur = out.find(r => r.id === d.invocation);
      if (inv && !low) {
        if (cur && cur.outcome === "unresolved") {
          out = out.filter(r => r.id !== d.invocation);
          out.push(result(d.invocation, "unresolved", "I10", "denied, but only the host says it held; a high-impact call needs an independent not_executed statement",
            { need: "independent_observer", ref: d.invocation }));
        }
      }
    }
  }
  // spec 10.4 orphan effects
  const invIds = new Set((pk.invocations || []).map(i => i.id));
  for (const e of effects) if (!invIds.has(e.invocation)) out.push(result(e.id ?? "?", "violated", "I11", "effect without any authorized invocation (bypass)", "host"));
  state.spent = spent;
  state.approvals_used = approvalUse;
  if (totals.size) state.period_totals = Object.fromEntries([...totals].map(([k, v]) => [k, unitsStr(v)]));
  if (Object.keys(apprHeld).length || "approvals_held" in state) state.approvals_held = apprHeld;
  const heldOut = { ...held, ...newHeld };
  if (Object.keys(heldOut).length || "held" in state) state.held = heldOut;
  return out;
}

// spec 10.5
export function verdict(results) {
  for (const o of ["violated", "unresolved"]) { const r = results.find(x => x.outcome === o); if (r) return r; }
  return results[0] || result("-", "unresolved", "I7", "empty packet", null, [{ need: "invocation", ref: "-" }]);
}
