// Import profile for Google's Agent Payments Protocol (AP2), read from the specification at ap2-protocol.org on
// 2026-11-23 (specification, payment mandate and checkout mandate pages).
//
// AP2 checks a payment BEFORE it happens: the credential provider, network and processor evaluate the closed payment
// mandate against the user's open mandate's constraints. Its dispute procedure re-verifies the artifacts and their hash
// links, and states that how they are used for dispute resolution is outside its scope. Nothing in AP2 decides,
// afterwards, whether what was actually processed stayed within the mandate. This profile builds that question as AMEP
// evidence: the open payment mandate becomes the authority, each closed payment mandate an invocation, and each signed
// payment receipt either an executed effect (status Success) or a signed "nothing executed" (status Error).
//
// Formats, aligned with AP2's Python SDK (github.com/google-agentic-commerce/AP2, code/sdk/python, commit e1ea56d):
//   - a payment mandate chain is a delegate SD-JWT chain (draft-gco-oauth-delegate-sd-jwt-00): the open mandate's
//     SD-JWT and the closed mandate's KB-SD-JWT joined by "~~" ("<open>~~<closed_jwt>~<disclosures>~");
//   - disclosures are base64url JSON arrays [salt, value] or [salt, name, value], referenced from `delegate_payload` by
//     {"...": digest}; digests and the hop binding are base64url(SHA-256) over ASCII. A closed hop binds the open one by
//     exactly one of `sd_hash` (over the open SD-JWT with its disclosures and trailing "~") or `issuer_jwt_hash`;
//   - a receipt's `reference` is base64url(SHA-256) of the closed mandate's issuer JWT alone (the SDK's
//     MandateClient.get_closed_mandate_jwt). The specification page says "calculated in the same manner as the sd_hash";
//     the profile accepts either and reports which rule matched.
// The open mandate's key is the one the verifier trusts for the user (AP2 resolves it by kid or x5c); the closed
// mandate is signed by the open mandate's `cnf` key; a receipt by the processor key the verifier trusts.
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

export const b64u = buf => Buffer.from(buf).toString("base64url");
const unb64u = s => Buffer.from(s, "base64url");
export const sha256b64u = text => b64u(createHash("sha256").update(text, "ascii").digest());

// ISO 4217 minor units for the currencies the profile maps; anything else is a gap, never guessed.
export const MINOR_UNITS = { USD: 2, EUR: 2, GBP: 2, AED: 2, INR: 2, SGD: 2, CHF: 2, JPY: 0, KRW: 0 };
/** A major-unit number (AP2's budget max, e.g. 300.0) as an exact decimal string, or null if it isn't exact. */
export function majorDecimal(major, currency) {
  const d = MINOR_UNITS[currency];
  if (d === undefined || typeof major !== "number" || !Number.isFinite(major) || major < 0) return null;
  const s = major.toFixed(d);
  return Number(s) === major ? s : null;
}
export function majorUnits(minor, currency) {
  const d = MINOR_UNITS[currency];
  if (d === undefined || !Number.isSafeInteger(minor) || minor < 0) return null;
  const s = String(minor).padStart(d + 1, "0");
  return d === 0 ? s : `${s.slice(0, -d)}.${s.slice(-d)}`;
}

function jwsParts(jwt) {
  const [h, p, s] = String(jwt).split(".");
  return { header: JSON.parse(unb64u(h)), payload: JSON.parse(unb64u(p)), signingInput: `${h}.${p}`, sig: unb64u(s ?? "") };
}
function es256ok(jwk, signingInput, sig) {
  try {
    return sig.length === 64 && cryptoVerify("sha256", Buffer.from(signingInput, "ascii"),
      { key: createPublicKey({ key: jwk, format: "jwk" }), dsaEncoding: "ieee-p1363" }, sig);
  } catch { return false; }
}

/** Split a delegate SD-JWT chain into its hops ("<hop>~~<hop>~"), each returned as "<jwt>~<disclosures>~". */
export function splitChain(token) {
  return String(token).split("~~").map((h, i, all) => (i < all.length - 1 ? `${h}~` : h));
}

/** Parse and check one SD-JWT presentation. Returns { header, claims, presentation, checks: [[name, ok, note]] }. */
export function readSdJwt(token, issuerJwk, expectTyp) {
  const checks = [];
  const parts = String(token).split("~");
  const jwt = parts[0], disclosures = parts.slice(1).filter(Boolean);
  let header, payload, signingInput, sig;
  try { ({ header, payload, signingInput, sig } = jwsParts(jwt)); } catch {
    return { claims: null, checks: [["well-formed SD-JWT", false, "the issuer JWT does not parse"]] };
  }
  checks.push(["alg ES256", header.alg === "ES256", `alg ${header.alg}`]);
  if (expectTyp) checks.push([`typ ${expectTyp}`, header.typ === expectTyp, `typ ${header.typ}`]);
  checks.push(["signature", es256ok(issuerJwk, signingInput, sig), "ES256 over the issuer JWT"]);
  checks.push(["_sd_alg sha-256", (payload._sd_alg ?? "sha-256") === "sha-256", `_sd_alg ${payload._sd_alg}`]);
  // resolve disclosures referenced from delegate_payload (and _sd, if present)
  const byDigest = new Map(disclosures.map(d => [sha256b64u(d), JSON.parse(unb64u(d))]));
  // SD-JWT: an array element {"...": digest} is replaced by its disclosure's value (or dropped when not disclosed);
  // an object's "_sd" digests add the disclosed [salt, name, value] members. Applied recursively.
  let hidden = 0;
  const resolve = v => {
    if (Array.isArray(v)) return v.flatMap(e => {
      if (e && typeof e === "object" && !Array.isArray(e) && Object.keys(e).length === 1 && "..." in e) {
        const d = byDigest.get(e["..."]);
        if (!d || d.length !== 2) { hidden++; return []; }
        return [resolve(d[1])];
      }
      return [resolve(e)];
    });
    if (v && typeof v === "object") {
      const out = {};
      for (const [k, x] of Object.entries(v)) if (k !== "_sd" && k !== "_sd_alg") out[k] = resolve(x);
      for (const dg of Array.isArray(v._sd) ? v._sd : []) {
        const d = byDigest.get(dg);
        if (d && d.length === 3) out[d[1]] = resolve(d[2]); else hidden++;
      }
      return out;
    }
    return v;
  };
  const claims = {}, extra = [];
  const top = [...(payload.delegate_payload ?? []).map(x => x?.["..."]), ...(payload._sd ?? [])].filter(Boolean);
  let unresolved = 0;
  for (const ref of top) {
    const d = byDigest.get(ref);
    if (!d) { unresolved++; continue; }
    const value = resolve(d.length === 3 ? { [d[1]]: d[2] } : d[1]);
    if (value && typeof value === "object" && !Array.isArray(value)) Object.assign(claims, value); else extra.push(value);
  }
  checks.push(["every referenced disclosure present", unresolved === 0, `${unresolved} digest(s) without a disclosure`]);
  if (hidden) checks.push(["nested selective disclosures", true, `${hidden} nested element(s) not disclosed in this presentation`]);
  for (const k of ["iat", "exp", "aud", "nonce", "sd_hash", "issuer_jwt_hash"]) if (k in payload && !(k in claims)) claims[k] = payload[k];
  const presentation = `${jwt}~${disclosures.join("~")}${disclosures.length ? "~" : ""}`;
  return { header, claims, extra, presentation, issuerJwt: jwt, checks };
}

/** A signed AP2 receipt (a plain ES256 JWT). */
export function readReceipt(jwt, processorJwk) {
  try {
    const { header, payload, signingInput, sig } = jwsParts(jwt);
    return { claims: payload, checks: [["alg ES256", header.alg === "ES256", `alg ${header.alg}`],
      ["signature", es256ok(processorJwk, signingInput, sig), "ES256 by the processor key the verifier trusts"]] };
  } catch { return { claims: null, checks: [["well-formed receipt JWT", false, "does not parse"]] }; }
}

/**
 * Analyse an AP2 payment bundle: { chains: ["<open>~~<closed>~", ...], receipts: [jwt...] } with trust
 * { userJwk, processorJwk }. Every chain must share one open mandate. Returns the AP2-side checks and, for each closed
 * mandate, what AMEP can build from it.
 */
export function analyseBundle(bundle, trust) {
  const gaps = new Set();
  const hops = (bundle.chains ?? []).map(splitChain);
  const opens = new Set(hops.map(h => h[0]));
  const open = readSdJwt(hops[0]?.[0] ?? "", trust.userJwk);
  if (opens.size !== 1) open.checks.push(["one open mandate across the bundle", false, `${opens.size} different open mandates`]);
  const oc = open.claims ?? {};
  if (oc.vct !== "mandate.payment.open.1") open.checks.push(["vct mandate.payment.open.1", false, `vct ${oc.vct}`]);
  const agentJwk = oc.cnf?.jwk;
  const constraints = Array.isArray(oc.constraints) ? oc.constraints : [];
  const payments = hops.map((h, n) => {
    const r = readSdJwt(h[h.length - 1], agentJwk);
    const c = r.claims ?? {};
    r.checks.push(["typ kb+sd-jwt (terminal hop)", ["kb+sd-jwt", "kb-sd-jwt"].includes(r.header?.typ), `typ ${r.header?.typ}`]);
    r.checks.push(["two hops: open, then closed", h.length === 2, `${h.length} hop(s); intermediate delegation hops are not read`]);
    r.checks.push(["vct mandate.payment.1", c.vct === "mandate.payment.1", `vct ${c.vct}`]);
    const bound = ("sd_hash" in c) !== ("issuer_jwt_hash" in c) && (c.sd_hash === sha256b64u(open.presentation) || c.issuer_jwt_hash === sha256b64u(open.issuerJwt ?? ""));
    r.checks.push(["binds the open mandate (exactly one of sd_hash, issuer_jwt_hash)", bound, "base64url(SHA-256) over ASCII"]);
    const refs = { sdk: sha256b64u(r.issuerJwt ?? ""), spec: sha256b64u(r.presentation ?? "") };
    const receipts = (bundle.receipts ?? []).map(j => readReceipt(j, trust.processorJwk))
      .filter(x => [refs.sdk, refs.spec].includes(x.claims?.reference))
      .map(x => ({ ...x, referenceRule: x.claims.reference === refs.sdk ? "closed issuer JWT (AP2 SDK)" : "closed presentation (spec text)" }));
    return { n, closed: r, hash: refs.sdk, refs, receipts };
  });
  const orphanReceipts = (bundle.receipts ?? []).map(j => readReceipt(j, trust.processorJwk))
    .filter(x => !payments.some(p => [p.refs.sdk, p.refs.spec].includes(x.claims?.reference)));
  // constraint coverage: what AMEP can express exactly, and what it can't
  for (const k of constraints) {
    if (k.type === "payment.amount_range" && k.min) gaps.add("payment.amount_range min: AMEP limits are ceilings; a minimum is not evaluated");
    if (k.type === "payment.agent_recurrence") gaps.add("payment.agent_recurrence: frequency and max_occurrences are not mapped (AMEP limits amounts, not counts per frequency)");
    if (k.type === "payment.allowed_payment_instruments") gaps.add("payment.allowed_payment_instruments: the instrument is not part of the AMEP resource");
    if (k.type === "payment.allowed_pisps") gaps.add("payment.allowed_pisps: not mapped");
    if (k.type === "payment.execution_date") gaps.add("payment.execution_date: not mapped");
    if (k.type === "payment.reference") gaps.add("payment.reference (conditional_transaction_id) binds the checkout mandate, which this profile does not read");
  }
  gaps.add("AP2 payment receipts carry no amount: the executed value is the closed mandate's, on the processor's signed word that it processed that mandate (its reference)");
  return { open, payments, orphanReceipts, constraints, gaps: [...gaps] };
}

/** The open mandate's constraints as AMEP claims, only where AMEP expresses them exactly. */
export function claimsFromOpen(oc, constraints) {
  const out = { actions: ["payments.send"], resources: ["payee:*"], ceiling: "financial", limits: [] };
  const problems = [];
  if (Number.isInteger(oc.iat)) out.nbf = oc.iat;
  if (Number.isInteger(oc.exp)) out.exp = oc.exp; else problems.push("the open mandate has no exp; AMEP needs an expiry");
  for (const k of constraints) {
    if (k.type === "payment.allowed_payees" && Array.isArray(k.allowed))
      out.resources = k.allowed.map(p => `payee:${p.id}`);
    if (k.type === "payment.amount_range") {
      const max = majorUnits(k.max, k.currency);
      if (max === null) problems.push(`amount_range max ${k.max} ${k.currency} is not an integer amount in a known currency's minor units`);
      else out.limits.push({ unit: `iso4217:${k.currency}`, per_call: max });
    }
    if (k.type === "payment.budget") {
      // unlike amount_range (integer minor units), AP2's budget max is a major-unit number (SDK: Budget.max: float)
      const max = majorDecimal(k.max, k.currency);
      if (max === null) problems.push(`budget max ${k.max} ${k.currency} is not an exact amount in a known currency's units`);
      else if (!out.exp || !out.nbf) problems.push("a budget needs the open mandate's iat and exp to fix its window");
      else out.limits.push({ unit: `iso4217:${k.currency}`, per_period: max, period: out.exp - out.nbf });
    }
  }
  if (!out.limits.length) delete out.limits;
  return { claims: out, problems };
}

export const ap2 = { id: "ap2", analyseBundle, claimsFromOpen, readSdJwt, readReceipt, majorUnits, majorDecimal, splitChain };
