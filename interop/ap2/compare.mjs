// AMEP evaluates AP2 (Agent Payments Protocol) payments after the fact, and writes COMPARISON.md.
//
// AP2 checks each payment before it happens: the closed payment mandate against the user's open mandate. This script
// takes AP2 bundles (an open payment mandate, closed payment mandates, signed payment receipts), checks them by AP2's
// own rules with the ap2 profile, builds AMEP evidence from them, and reports AMEP's verdict afterwards, next to what
// AP2's per-payment check would have said. The bundles are synthetic, written to the field names of the AP2
// specification (ap2-protocol.org, read 2026-11-23); see the profile for what is assumed where the text is silent.
//
// Run from the repo root:  node interop/ap2/compare.mjs            (rewrite fixtures if missing, and COMPARISON.md)
//                          node interop/ap2/compare.mjs --check    (exit 1 if COMPARISON.md is out of date)
import { createECDH, createHash, createPrivateKey, sign as cryptoSign } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { digest, evaluate, verdict } from "../../packages/js/src/core.mjs";
import { Key, keyset, sigOk } from "../../packages/js/src/node.mjs";
import { analyseBundle, b64u, claimsFromOpen, majorUnits, sha256b64u } from "../../packages/conformance/src/profiles/ap2.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "..", "packages", "conformance", "test", "fixtures", "ap2");
const OUT = join(HERE, "COMPARISON.md");
const seed = label => createHash("sha256").update(`amep-test-vector-key-v1:${label}`).digest();

// deterministic TEST keys: P-256 for the AP2 side, Ed25519 for the AMEP importer
function p256(label) {
  const ecdh = createECDH("prime256v1"); ecdh.setPrivateKey(seed(label));
  const pub = ecdh.getPublicKey(null, "uncompressed");
  const jwk = { kty: "EC", crv: "P-256", x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33)) };
  return { jwk, priv: createPrivateKey({ key: { ...jwk, d: b64u(ecdh.getPrivateKey()) }, format: "jwk" }) };
}
const ed = (kid, roles) => new Key(kid, roles, createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed(kid)]), format: "der", type: "pkcs8" }));
const USER = p256("ap2-user"), AGENT = p256("ap2-agent"), PROCESSOR = p256("ap2-processor");
const I = ed("ap2-importer-issuer", ["issuer"]), H = ed("ap2-importer-host", ["host"]), O = ed("ap2-importer-observer", ["observer"]);
const AMEP_KEYS = keyset(I, H, O);
const TRUST = { userJwk: USER.jwk, processorJwk: PROCESSOR.jwk };

const jws = (header, payload, key) => {
  const si = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  return `${si}.${b64u(cryptoSign("sha256", Buffer.from(si), { key, dsaEncoding: "ieee-p1363" }))}`;
};
let saltN = 0;
const disclose = value => b64u(JSON.stringify([`salt-${++saltN}`, value]));
function sdJwt(header, extra, claimObjects, key) {
  const ds = claimObjects.map(disclose);
  const jwt = jws(header, { delegate_payload: ds.map(d => ({ "...": sha256b64u(d) })), _sd_alg: "sha-256", ...extra }, key);
  return `${jwt}~${ds.join("~")}~`;
}

const T0 = 1795400000, MERCHANT = { id: "merchant_1", name: "Demo Merchant", website: "https://demo-merchant.example" };
const OTHER = { id: "merchant_2", name: "Other Merchant", website: "https://other-merchant.example" };
const CONSTRAINTS = [
  { type: "payment.amount_range", currency: "USD", max: 20000, min: 0 },
  { type: "payment.allowed_payees", allowed: [MERCHANT] },
  { type: "payment.budget", currency: "USD", max: 300.0 },
];
const openMandate = () => sdJwt({ alg: "ES256", typ: "example+sd-jwt", kid: "ap2-user" }, {},
  [{ vct: "mandate.payment.open.1", constraints: CONSTRAINTS, cnf: { jwk: AGENT.jwk }, iat: T0, exp: T0 + 3600 }], USER.priv);
// a payment mandate chain as AP2 serializes it: "<open>~~<closed_jwt>~<disclosures>~"
function closedMandate(open, n, { amount = 19900, payee = MERCHANT, iat = T0 + 60 * n } = {}) {
  const closed = sdJwt({ alg: "ES256", typ: "kb+sd-jwt" }, { iat, aud: "credential-provider", nonce: `nonce-${n}`, sd_hash: sha256b64u(open) },
    [{ vct: "mandate.payment.1", transaction_id: `txn-${n}`, payee, payment_amount: { amount, currency: "USD" },
       payment_instrument: { id: "stub", type: "card", description: "Card ••••4242" } }], AGENT.priv);
  return `${open}~${closed}`;
}
// AP2 SDK rule: the reference is the SHA-256 of the closed mandate's issuer JWT (the leaf of the chain)
const leafJwt = chain => chain.split("~~").pop().split("~")[0];
const receipt = (chain, n, status = "Success", reference = sha256b64u(leafJwt(chain))) => jws({ alg: "ES256", typ: "JWT" }, {
  status, iss: "processor.example", iat: T0 + 60 * n + 5, reference, payment_id: `pay-${n}`,
  ...(status === "Success" ? { psp_confirmation_id: `psp-${n}`, network_confirmation_id: `net-${n}` } : { error: "declined", error_description: "issuer declined" }) },
  PROCESSOR.priv);

/** The scenarios: [id, title, bundle builder, AMEP outcome expected]. */
const SCENARIOS = [
  ["s1-within", "One payment within the mandate, processed", o => { const c = closedMandate(o, 1); return { closed: [c], receipts: [receipt(c, 1)] }; }],
  ["s2-over-range", "Closed mandate above amount_range max (250.00 > 200.00), processed anyway", o => { const c = closedMandate(o, 1, { amount: 25000 }); return { closed: [c], receipts: [receipt(c, 1)] }; }],
  ["s3-wrong-payee", "Payee not in allowed_payees, processed anyway", o => { const c = closedMandate(o, 1, { payee: OTHER }); return { closed: [c], receipts: [receipt(c, 1)] }; }],
  ["s4-declined", "The processor returns a signed Error receipt", o => { const c = closedMandate(o, 1); return { closed: [c], receipts: [receipt(c, 1, "Error")] }; }],
  ["s5-lost-receipt", "The receipt never arrives", o => ({ closed: [closedMandate(o, 1)], receipts: [] })],
  ["s6-budget", "Two payments, each within amount_range, together over the budget (199.00 + 150.00 > 300.00)", o => {
    const a = closedMandate(o, 1), b = closedMandate(o, 2, { amount: 15000 }); return { closed: [a, b], receipts: [receipt(a, 1), receipt(b, 2)] }; }],
  ["s7-receipt-for-another-mandate", "The only receipt references a different mandate", o => {
    const c = closedMandate(o, 1); return { closed: [c], receipts: [receipt(c, 1, "Success", sha256b64u("some other mandate"))] }; }],
  ["s8-altered-amount", "The closed mandate's amount was changed after the agent signed it", o => {
    const c = closedMandate(o, 1); const [head, leaf] = c.split("~~"); const [jwt, d] = leaf.split("~");
    const claims = JSON.parse(Buffer.from(d, "base64url"));
    claims[1].payment_amount.amount = 9900;
    const forged = `${head}~~${jwt}~${b64u(JSON.stringify(claims))}~`;
    return { closed: [forged], receipts: [receipt(forged, 1)] }; }],
  ["s9-unknown-then-second", "The first payment's outcome is unknown; a second (150.00) would take the budget over if the first went through", o => {
    const a = closedMandate(o, 1), b = closedMandate(o, 2, { amount: 15000 }); return { closed: [a, b], receipts: [receipt(b, 2)] }; }],
];

function fixtures() {
  if (!existsSync(FIX)) mkdirSync(FIX, { recursive: true });
  const path = join(FIX, "bundles.json");
  if (existsSync(path) && !process.argv.includes("--regenerate")) return JSON.parse(readFileSync(path, "utf8"));
  const out = { trust: TRUST, bundles: {} };
  for (const [id, , build] of SCENARIOS) { const b = build(openMandate()); out.bundles[id] = { chains: b.closed, receipts: b.receipts }; }
  writeFileSync(path, JSON.stringify(out, null, 1) + "\n");
  return out;
}

/** What AP2's own per-payment check says (credential provider / network, before payment): constraints of the open
 *  mandate evaluated for one closed mandate alone. Whether earlier payments count toward the budget is up to the
 *  provider; AP2 does not specify that state, so this check sees one payment. */
function ap2PrePayment(open, c) {
  const why = [];
  for (const k of open.claims?.constraints ?? []) {
    if (k.type === "payment.amount_range" && (c.payment_amount?.amount > k.max || c.payment_amount?.amount < (k.min ?? 0))) why.push("amount outside amount_range");
    if (k.type === "payment.allowed_payees" && !k.allowed.some(p => p.id === c.payee?.id)) why.push("payee not allowed");
    if (k.type === "payment.budget" && c.payment_amount?.amount > Math.round(k.max * 100)) why.push("over budget (this payment alone)");
  }
  return why.length ? `reject: ${why.join("; ")}` : "accept";
}

/** AMEP evidence from an analysed bundle, signed by the importer; verdict and per-invocation results. */
export function amepOf(an) {
  const oc = an.open.claims ?? {};
  const { claims, problems } = claimsFromOpen(oc, an.constraints);
  const openOk = an.open.checks.every(c => c[1]);
  const objs = { mandates: [], interpretations: [H.sign({ id: "a-1", kind: "interpretation", source: "curated", adapter: "ap2-payment-mandate", version: "1" }, { v: 2 })],
    invocations: [], effects: [], call_statements: [] };
  if (openOk && !problems.length) objs.mandates.push(I.sign({ id: "m-1", kind: "mandate", principal: "ap2-user", claims }, { v: 2 }));
  for (const p of an.payments) {
    const c = p.closed.claims ?? {};
    const value = { amount: majorUnits(c.payment_amount?.amount, c.payment_amount?.currency), unit: `iso4217:${c.payment_amount?.currency}` };
    const inv = { id: `i-${p.n + 1}`, kind: "invocation", authority_ref: "m-1", interpretation_ref: "a-1", actor: "ap2-agent", t: c.iat ?? T0,
      declared: { action: "payments.send", resource: `payee:${c.payee?.id}`, effect: "financial" },
      ...(value.amount ? { reserve: value } : {}), "x-ap2": { transaction_id: c.transaction_id, closed_hash: p.hash } };
    // the importer signs only what passed AP2's own checks; anything else stays unsigned, so AMEP can't rely on it
    const signedOk = p.closed.checks.every(x => x[1]);
    const invObj = signedOk ? H.sign(inv, { v: 2 }) : inv;
    objs.invocations.push(invObj);
    for (const [k, r] of p.receipts.entries()) {
      if (!r.checks.every(x => x[1])) continue;
      if (r.claims.status === "Success" && value.amount)
        objs.effects.push(O.sign({ id: `e-${p.n + 1}-${k + 1}`, kind: "effect", invocation: inv.id, observed_by: `ap2-processor:${r.claims.iss}`,
          assurance: "L2", invocation_digest: digest(invObj), executed: { action: "payments.send", resource: `payee:${c.payee?.id}`,
            effect: "financial", released: [], t: r.claims.iat, value }, "x-ap2": { payment_id: r.claims.payment_id, reference: r.claims.reference } }, { v: 2 }));
      if (r.claims.status === "Error")
        objs.call_statements.push(O.sign({ id: `c-${p.n + 1}`, kind: "call_statement", invocation: inv.id, observed_by: `ap2-processor:${r.claims.iss}`,
          disposition: "not_executed", effect_count: 0, t: r.claims.iat, invocation_digest: digest(invObj) }, { v: 2 }));
    }
  }
  // A budget window needs a starting total. The importer asserts that the bundle holds every payment under this open
  // mandate, so the window starts at zero; without that assertion AMEP would answer unresolved (spec 7.6 rule 5).
  const budget = (claims.limits ?? []).find(l => l.per_period);
  const state = budget ? { period_totals: { [`m-1|${budget.unit}|${budget.period}|0`]: "0.00" } } : {};
  // Payments are evaluated as they settle: one packet per payment, in order, with verifier state carried between them
  // (spec 10.7), so an earlier payment's total, or its hold when its outcome is unknown, counts for the later ones.
  const packets = objs.invocations.map(inv => ({ amep_version: "0.3", delegations: [], mandates: objs.mandates,
    interpretations: objs.interpretations, invocations: [inv], effects: objs.effects.filter(e => e.invocation === inv.id),
    call_statements: objs.call_statements.filter(c => c.invocation === inv.id) }));
  const results = packets.flatMap(pk => evaluate(pk, AMEP_KEYS, sigOk, [], state));
  return { packets, problems, results, verdict: verdict(results) };
}

export function compare() {
  const fx = fixtures();
  return SCENARIOS.map(([id, title]) => {
    const an = analyseBundle(fx.bundles[id], fx.trust);
    const failed = [an.open, ...an.payments.map(p => p.closed)].flatMap(x => x.checks.filter(c => !c[1]).map(c => c[0]));
    const pre = an.payments.map(p => p.closed.checks.every(c => c[1]) ? ap2PrePayment(an.open, p.closed.claims ?? {}) : "reject: the closed mandate fails AP2's artifact checks");
    const amep = amepOf(an);
    return { id, title, ap2Checks: failed, pre, receipts: an.payments.map(p => p.receipts.map(r => r.claims.status).join("+") || "none"),
      orphans: an.orphanReceipts.length, gaps: an.gaps, amep };
  });
}

function render(rows) {
  const fmt = r => `${r.outcome} ${r.invariant}${r.blame ? ` (blame ${r.blame})` : ""}${r.gaps?.length ? ` (${r.gaps.map(g => `${g.need} ${g.ref}${g.cause ? `, ${g.cause}` : ""}`).join("; ")})` : ""}`;
  const lines = [
    "# AMEP evaluates AP2 payments afterwards",
    "",
    "Generated by `node interop/ap2/compare.mjs`; do not edit by hand.",
    "",
    "AP2 (Agent Payments Protocol) checks each payment **before** it happens: the credential provider, network and processor evaluate the closed payment mandate against the user's open mandate. Its dispute procedure re-verifies the artifacts and their hash links, and says how they are used for dispute resolution is out of its scope. AMEP decides **afterwards**, from the same signed artifacts, whether what was processed stayed within the mandate, and says what is missing when it can't.",
    "",
    "Open mandate in every scenario: payee `merchant_1` only, `amount_range` max 200.00 USD, `budget` 300.00 USD, valid one hour.",
    "",
    "| Scenario | AP2 artifact checks | AP2 constraint check, this payment alone (before) | Receipts | AMEP afterwards (worst result) | Per payment, in order |",
    "|---|---|---|---|---|---|",
  ];
  for (const r of rows) {
    lines.push(`| \`${r.id}\`: ${r.title} | ${r.ap2Checks.length ? `fail: ${r.ap2Checks.join("; ")}` : "pass"} | ${r.pre.join("<br>")} | ${r.receipts.join("<br>")}${r.orphans ? ` (+${r.orphans} for another mandate)` : ""} | ${fmt(r.amep.verdict)} | ${r.amep.results.map(x => `${x.id}: ${fmt(x)}`).join("<br>")} |`);
  }
  lines.push("", "## What the profile can't evaluate", "", ...rows[0].gaps.map(g => `- ${g}`), "");
  return lines.join("\n");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const text = render(compare());
  if (process.argv.includes("--check")) {
    const cur = existsSync(OUT) ? readFileSync(OUT, "utf8") : "";
    if (cur !== text) { console.error("interop/ap2/COMPARISON.md is out of date: run node interop/ap2/compare.mjs"); process.exit(1); }
    console.log("interop/ap2/COMPARISON.md is up to date");
  } else { writeFileSync(OUT, text); console.log(text); }
}
