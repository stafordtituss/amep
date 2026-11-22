// Compares AMEP with EMILIA Protocol's own published vectors (emiliaprotocol/emilia-protocol at 611483b, Apache-2.0;
// see the fixture's NOTICE.md) and writes COMPARISON.md:
//  - receipts.v1: EP's receipt format, checked by AMEP's clean-room reading of EP's rules, against EP's expected result;
//  - outcome-binding.v1, predicate vectors: EP's three outcomes (in_bounds, divergent, incomparable) beside AMEP's
//    (preserved, violated, unresolved), with EP's predictions re-expressed as AMEP claims where AMEP has an exact form.
//
// Run from the repo root:  node interop/ep/compare.mjs            (rewrite COMPARISON.md)
//                          node interop/ep/compare.mjs --check    (exit 1 if COMPARISON.md is out of date)
import { readFileSync, writeFileSync } from "node:fs";
import { createHash, createPrivateKey } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { evaluate, verdict } from "../../packages/js/src/core.mjs";
import { Key, keyset, sigOk } from "../../packages/js/src/node.mjs";
import { checkReceipt, predictedEffects } from "../../packages/conformance/src/profiles/ep.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "..", "packages", "conformance", "test", "fixtures", "ep");
const OUT = join(HERE, "COMPARISON.md");
const testKey = (kid, roles) => {
  const seed = createHash("sha256").update(`amep-test-vector-key-v1:${kid}`).digest();
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  return new Key(kid, roles, createPrivateKey({ key: der, format: "der", type: "pkcs8" }));
};
const I = testKey("ep-importer-issuer", ["issuer"]), H = testKey("ep-importer-host", ["host"]), O = testKey("ep-importer-observer", ["observer"]);
const KEYS = keyset(I, H, O);
const T0 = "2026-07-19T16:00:00Z", T1 = "2026-07-19T16:01:00Z";
const load = f => JSON.parse(readFileSync(join(FIX, f), "utf8"));

/** AMEP's verdict on one EP predicate vector, or { na } when AMEP has no exact form for it. */
export function amepOnPredicate(v) {
  const m = predictedEffects(v.predicted_effects, v.observed_effects);
  if (m.na) return m;
  const objs = [I.sign({ id: "m-1", kind: "mandate", principal: "ep-approver",
    claims: { ...m.claims, nbf: "2026-07-19T00:00:00Z", exp: "2026-07-20T00:00:00Z" } }, { v: 2 })];
  objs.push(H.sign({ id: "a-1", kind: "interpretation", source: "curated", adapter: "ep-predicted-effects", version: "1.0" }, { v: 2 }));
  // EP attests effects, not calls. Each observed effect becomes one call (invocation) declaring exactly that effect, and
  // the executor's receipt for it. With no observed effect, the approved (predicted) call has no receipt.
  const { value: _v, ...firstPredicted } = m.predictedCall ?? {};
  const calls = m.effects.length ? m.effects : [null];
  calls.forEach((e, n) => {
    const declared = e ? (({ value, ...d }) => d)(e) : firstPredicted;
    objs.push(H.sign({ id: `i-${n + 1}`, kind: "invocation", authority_ref: "m-1", interpretation_ref: "a-1", actor: "ep-agent", t: T0, declared }, { v: 2 }));
    if (e) objs.push(O.sign({ id: `e-${n + 1}`, kind: "effect", invocation: `i-${n + 1}`, observed_by: "ep-executor",
      assurance: "L1", executed: { ...e, released: [], t: T1 } }, { v: 2 }));
  });
  const by = k => objs.filter(o => o.kind === k);
  const packet = { amep_version: "0.3", mandates: by("mandate"), interpretations: by("interpretation"), invocations: by("invocation"), effects: by("effect") };
  const results = evaluate(packet, KEYS, sigOk);
  return { result: verdict(results), reason: results.find(r => r.outcome !== "preserved")?.reason ?? "", effects: m.effects.length };
}

const MATCH = { in_bounds: "preserved", divergent: "violated", incomparable: "unresolved" };

export function compare() {
  const receipts = load("receipts.v1.json").vectors.map(v => {
    const r = checkReceipt(v.document, v.public_key);
    return { id: v.id, expected: v.expect.valid, got: r.valid, problems: r.problems };
  });
  const predicates = load("outcome-binding.v1.json").vectors.filter(v => v.kind === "predicate").map(v => {
    const amep = amepOnPredicate(v);
    const ep = v.expect.outcome;
    let relation;
    if (amep.na) relation = "not comparable";
    else if (MATCH[ep] === amep.result.outcome) relation = "agree";
    else relation = "differ";
    return { id: v.id, ep, reason: v.expect.reason_contains, amep, relation };
  });
  return { receipts, predicates };
}

const NOTE = {
  absent_pass: "EP checks only the predicted effects, so an unpredicted payment passes. AMEP's claims are an allowlist: a payment the approver didn't grant is outside authority",
  missing_observed_effect_incomparable: "EP requires the predicted payment to have happened. AMEP judges what executed, and nothing did, so nothing exceeded authority",
};

function render({ receipts, predicates }) {
  const ra = receipts.filter(r => r.expected === r.got).length;
  const cell = r => r.amep.na ? "" : `\`${r.amep.result.outcome}\`${r.amep.result.invariant !== "-" ? " " + r.amep.result.invariant : ""}${r.amep.result.blame ? `, blame \`${r.amep.result.blame}\`` : ""}`;
  const comparable = predicates.filter(r => !r.amep.na), agree = comparable.filter(r => r.relation === "agree").length;
  const why = r => r.amep.na ? r.amep.na : r.relation === "differ" ? (NOTE[r.id] || "see the README") : r.amep.reason ? `AMEP: ${r.amep.reason}` : "";
  return [
    "# AMEP beside EMILIA Protocol's own vectors",
    "",
    "Generated by `node interop/ep/compare.mjs` from EP's published conformance vectors (emiliaprotocol/emilia-protocol at `611483b`, Apache-2.0; see `packages/conformance/test/fixtures/ep/NOTICE.md`). `--check` fails if this file is out of date.",
    "",
    "## EP receipts (`receipts.v1.json`)",
    "",
    `AMEP's profile checks EP-RECEIPT-v1 by EP's rules, written clean-room from what the vectors and EP's verifier README state, without EP's code. **It agrees with EP's expected result on ${ra} of ${receipts.length} vectors.**`,
    "",
    "| Vector | EP expects | AMEP profile | Reason given |",
    "|---|---|---|---|",
    ...receipts.map(r => `| \`${r.id}\` | ${r.expected ? "valid" : "invalid"} | ${r.got ? "valid" : "invalid"}${r.expected === r.got ? "" : " **(differs)**"} | ${r.problems.join("; ")} |`),
    "",
    "## Outcome binding (`outcome-binding.v1.json`, predicate vectors)",
    "",
    "EP approves **predicted** effects with bounds, and an executor attests the **observed** effects. EP's three outcomes match AMEP's three: `in_bounds` ↔ `preserved`, `divergent` ↔ `violated`, `incomparable` ↔ `unresolved`. Here each prediction is re-expressed as an AMEP claim, signed by the importer, only where AMEP has an exact form. Each observed effect becomes an effect observed by the executor (L1).",
    "",
    "| Vector | EP | AMEP | Relation | Why |",
    "|---|---|---|---|---|",
    ...predicates.map(r => `| \`${r.id}\` | \`${r.ep}\` | ${cell(r)} | ${r.relation} | ${why(r)} |`),
    "",
    `**Summary:** AMEP can express ${comparable.length} of the ${predicates.length} predicate vectors exactly, and agrees with EP on ${agree} of those ${comparable.length}. The one difference, \`absent_pass\`, is a design choice, explained in the README. Of the other ${predicates.length - comparable.length}, ${predicates.filter(r => r.amep.na && /importer refuses/.test(r.amep.na)).length} are malformed inputs the importer refuses, as EP does. The rest use predicates AMEP has no exact form for: exact values, sets, minimums, ranges and counts.`,
  ].join("\n") + "\n";
}

if (fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const text = render(compare());
  if (process.argv.includes("--check")) {
    const ok = readFileSync(OUT, "utf8") === text;
    console.log(ok ? "COMPARISON.md is up to date" : "COMPARISON.md is out of date: run node interop/ep/compare.mjs");
    process.exit(ok ? 0 : 1);
  }
  writeFileSync(OUT, text);
  console.log(`wrote ${OUT}`);
}
