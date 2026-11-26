#!/usr/bin/env node
// AMEP profile run over the Agent Receipts cross-SDK vectors (agent-receipts/obsigna#1204).
//
//   node interop/agent-receipts/run.mjs <path to an obsigna checkout> [--json out.json]
//
// Reads the vector files as data; runs no code from the obsigna repository. Part A checks the receipts by the Agent
// Receipts format rules, with AMEP's own canonicalizer and verifier. Part B imports them as AMEP evidence through the
// example tool map. Part C evaluates worked AMEP packets built around three of the receipts: the receipts are the
// effect evidence; the mandate, the invocations and the deployment mode are the verifier's inputs, stated as such.
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, createPrivateKey, sign as edSign } from "node:crypto";
import { canon, digest, evaluate, verdict } from "../../packages/js/src/core.mjs";
import { Key, sigOk } from "../../packages/js/src/index.mjs";
import { importRecord } from "../../packages/conformance/src/import.mjs";
import { agentReceipts, checkChain, receiptHash } from "../../packages/conformance/src/profiles/agent-receipts.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const root = process.argv[2];
if (!root) { console.error("usage: run.mjs <obsigna checkout> [--json FILE]"); process.exit(3); }
const jsonOut = process.argv.includes("--json") ? process.argv[process.argv.indexOf("--json") + 1] : null;
const V = f => JSON.parse(readFileSync(join(root, "cross-sdk-tests", f), "utf8"));
const map = JSON.parse(readFileSync(join(HERE, "toolmap.json"), "utf8"));
const out = { commit: null, A: {}, B: [], C: [] };
try { out.commit = readFileSync(join(root, ".git", "HEAD"), "utf8").trim(); } catch { /* not a git checkout */ }

// ---------- A. format checks with AMEP's code ----------
const cv = V("canonicalization_vectors.json");
let canonOk = 0; const canonMiss = [];
for (const v of cv.canonicalization_vectors) {
  let got; try { got = canon(v.input); } catch (e) { got = `error: ${e.message}`; }
  if (got === v.canonical) canonOk++; else canonMiss.push({ name: v.name, got, want: v.canonical });
}
out.A.canonicalization = { agree: canonOk, of: cv.canonicalization_vectors.length, misses: canonMiss };
const hv = cv.receipt_hash_vectors.filter(v => v.receipt && v.expectedHash);
// Three vectors are schema-invalid emitter input (preNormalizationInput): they test the SDKs' null->absent sweep
// before serialization (ADR-0009, Rule 2), not a verifier. A conformant receipt never carries those nulls; the sweep
// is applied here only to reproduce the expected hashes, and the profile does not apply it to received receipts.
const sweep = (o, path = "") => Array.isArray(o) ? o.map(x => sweep(x, path)) : o && typeof o === "object"
  ? Object.fromEntries(Object.entries(o).filter(([k, v]) => v !== null || `${path}.${k}` === ".credentialSubject.chain.previous_receipt_hash").map(([k, v]) => [k, sweep(v, `${path}.${k}`)])) : o;
// "SAME_AS_<name>" asserts equality with that vector's hash (notes_for_implementers).
const want = v => v.expectedHash.startsWith("SAME_AS_") ? hv.find(b => b.name === v.expectedHash.slice(8)).expectedHash : v.expectedHash;
const hashMiss = hv.filter(v => receiptHash(v.preNormalizationInput ? sweep(v.receipt) : v.receipt) !== want(v)).map(v => v.name);
out.A.receipt_hashes = { agree: hv.length - hashMiss.length, of: hv.length, misses: hashMiss, swept: hv.filter(v => v.preNormalizationInput).map(v => v.name) };

// every signed receipt outside the malformed set, with the key from its own file
const signed = [];
const go = V("go_vectors.json"), py = V("py_vectors.json");
signed.push(["go_vectors.signing.signed", go.signing.signed, go.keys.publicKey], ["py_vectors.signing.signed", py.signing.signed, py.keys.publicKey]);
const v020 = V("v020_vectors.json"), v030 = V("v030_vectors.json"), v040 = V("v040_vectors.json"), v050 = V("v050_vectors.json");
v020.terminalChain.receipts.forEach((r, i) => signed.push([`v020.terminalChain[${i}]`, r, v020.keys.publicKey]));
signed.push(["v020.parametersDisclosureReceipt", v020.parametersDisclosureReceipt.receipt, v020.keys.publicKey]);
for (const k of ["parametersDisclosureEnvelopeReceipt", "peerCredentialEmitterMetadataReceipt", "peerCredentialRootReceipt"]) signed.push([`v030.${k}`, v030[k].receipt, v030.keys.publicKey]);
signed.push(["v040.idempotencyKeyReceipt", v040.idempotencyKeyReceipt.receipt, v040.keys.publicKey]);
v040.duplicateIdempotencyChain.receipts.forEach((r, i) => signed.push([`v040.duplicateIdempotencyChain[${i}]`, r, v040.keys.publicKey]));
for (const k of ["runtimeReceipt", "extendedRuntimeReceipt", "rootAgentReceipt"]) signed.push([`v050.${k}`, v050[k].receipt, v050.keys.publicKey]);
const checked = signed.map(([name, r, pk]) => ({ name, r, pk, c: agentReceipts.check(r, { publicKey: pk }) }));
out.A.signed = { pass: checked.filter(x => x.c.verdict === "pass").length, of: checked.length,
  fail: checked.filter(x => x.c.verdict !== "pass").map(x => ({ name: x.name, verdict: x.c.verdict })) };

const mal = V("malformed_vectors.json");
const malR = mal.receipts.map(m => ({ name: m.name, verdict: agentReceipts.check(m.receipt, { publicKey: mal.keys.publicKey }).verdict }));
const malChains = mal.chains.map(ch => {
  const sigs = ch.receipts.map(r => agentReceipts.check(r, { publicKey: mal.keys.publicKey }).verdict);
  const c = checkChain(ch.receipts);
  return { name: ch.name, signatures_valid: sigs.filter(s => s === "pass").length, of: sigs.length, chain_valid: c.valid,
    broken: c.links.filter(l => !(l.link && l.sequence)).map(l => `link ${l.index}${l.link ? "" : " hash"}${l.sequence ? "" : " sequence"}`) };
});
out.A.malformed = { receipts_rejected: malR.filter(x => x.verdict !== "pass").length, of: malR.length, receipts: malR,
  chains_rejected: malChains.filter(c => !c.chain_valid).length, chains: malChains,
  set_rejected: malR.every(x => x.verdict !== "pass") && malChains.every(c => !c.chain_valid) };
const goodChains = { "v020.terminalChain": checkChain(v020.terminalChain.receipts), "v040.duplicateIdempotencyChain": checkChain(v040.duplicateIdempotencyChain.receipts) };
out.A.chains = Object.fromEntries(Object.entries(goodChains).map(([k, c]) => [k, { valid: c.valid, duplicate_idempotency_keys: c.duplicate_idempotency_keys }]));

// ---------- B. import as AMEP evidence ----------
for (const x of checked) {
  const imp = importRecord(x.r, { profile: "agent-receipts", map, publicKey: x.pk });
  out.B.push({ name: x.name, type: x.r.credentialSubject.action.type, risk: x.r.credentialSubject.action.risk_level,
    outcome: x.r.credentialSubject.outcome.status, imported: !!imp.effect,
    mapped: imp.effect ? `${imp.effect.executed.action} ${imp.effect.executed.resource} (${imp.effect.executed.effect})` : null,
    not_imported: imp.not_imported, gaps: imp.gaps.filter(g => !["present", "map"].includes(g.status)).map(g => `${g.need}: ${g.status}`) });
}

// ---------- C. worked AMEP verdicts ----------
// The verifier's inputs: one mandate from the principal named in the receipts, and one invocation per receipt, signed
// by the agent's host. The receipt's issuer is the observer. Its AMEP key is re-expressed by the importer and given the
// operator the deployment declares, so that the independence rule (I10, spec 12.5) sees the deployment as declared.
const issuerKey = Key.generate("principal-issuer", ["issuer"]);
const hostKey = Key.generate("agent-host", ["host"]);
function keysFor(observerOperator) {
  const obs = Key.generate("receipt-issuer", ["observer"]);
  const ks = { [issuerKey.kid]: issuerKey.publicEntry(), [hostKey.kid]: { ...hostKey.publicEntry(), operator: "agent-operator" },
    [obs.kid]: { ...obs.publicEntry(), operator: observerOperator } };
  return { obs, ks };
}
const MANDATE = issuerKey.sign({ id: "m-1", kind: "mandate", principal: "did:user:test",
  claims: { actions: ["command.execute", "api.read"], resources: ["host:commands", "api:data"], ceiling: "write_shared",
    exp: "2026-12-31T00:00:00Z" } }, { v: 2 });
const INTERP = hostKey.sign({ id: "a-1", kind: "interpretation", source: "curated", adapter: "agent-receipts-toolmap", version: "1" }, { v: 2 });

function packetFor(receipts, { actor, observerOperator, observedBy }) {
  const { obs, ks } = keysFor(observerOperator);
  const invocations = [], effects = [];
  receipts.forEach((r, i) => {
    const a = r.credentialSubject.action, m = map.tools[a.type];
    const inv = hostKey.sign({ id: `i-${i}`, kind: "invocation", authority_ref: "m-1", interpretation_ref: "a-1", t: a.timestamp,
      actor, declared: { action: m.action, resource: m.resource, effect: m.effect }, operation: a.idempotency_key }, { v: 2 });
    invocations.push(inv);
    const imp = importRecord(r, { profile: "agent-receipts", map, publicKey: v040.keys.publicKey });
    if (imp.effect) effects.push(obs.sign({ ...imp.effect, invocation: inv.id, invocation_digest: digest(inv),
      observed_by: observedBy ?? imp.effect.observed_by }, { v: 2 }));
  });
  const pk = { amep_version: "0.3", mandates: [MANDATE], interpretations: [INTERP], invocations, effects };
  const res = evaluate(pk, ks, sigOk);
  return { verdict: verdict(res), results: res.map(x => ({ invocation: x.id, outcome: x.outcome, invariant: x.invariant, reason: x.reason, blame: x.blame })) };
}

const hi = v040.idempotencyKeyReceipt.receipt;
const C1 = [
  ["client-side mode (ADR-0020): the agent signs its own receipt", { actor: hi.issuer.id, observerOperator: "agent-operator" }],
  ["daemon mode (ADR-0010), daemon run by the agent's own operator", { actor: "agent:runtime", observerOperator: "agent-operator" }],
  ["daemon mode, daemon run by an operator other than the agent's", { actor: "agent:runtime", observerOperator: "receipts-operator" }],
];
for (const [mode, o] of C1) out.C.push({ case: "one high-risk command (v040.idempotencyKeyReceipt)", mode, ...packetFor([hi], o) });

const dup = v040.duplicateIdempotencyChain.receipts;
out.C.push({ case: "timeout, then a retry under the same idempotency_key (v040.duplicateIdempotencyChain)",
  mode: "any: the first receipt says failure, which does not show the call was not executed", ...packetFor(dup, { actor: "agent:runtime", observerOperator: "receipts-operator" }) });

// The double-counting case spec 7.3.6 leaves to an auditor: two successes under one key. The second receipt is
// constructed for this run: a copy of the retry with a new id and sequence 3, signed with the published test key.
const testPriv = createPrivateKey(v040.keys.privateKey);
const second = structuredClone(dup[1]);
second.id = "urn:receipt:amep-constructed-0003";
second.credentialSubject.action.id = "act_amep-constructed-0003";
second.credentialSubject.chain = { ...second.credentialSubject.chain, sequence: 3, previous_receipt_hash: receiptHash(dup[1]) };
delete second.proof;
second.proof = { ...dup[1].proof, proofValue: "u" + edSign(null, Buffer.from(canon(second), "utf8"), testPriv).toString("base64url") };
out.C.push({ case: "two successes under one idempotency_key (constructed: the chain above plus a second success)",
  mode: "daemon run by another operator", chain_valid: checkChain([...dup, second]).valid,
  ...packetFor([dup[1], second], { actor: "agent:runtime", observerOperator: "receipts-operator" }) });

// ---------- print ----------
const A = out.A;
console.log(`obsigna ${out.commit ?? "(no git HEAD)"}`);
console.log(`A. canonicalization ${A.canonicalization.agree}/${A.canonicalization.of}; receipt hashes ${A.receipt_hashes.agree}/${A.receipt_hashes.of} (${A.receipt_hashes.swept.length} after the emitter null sweep); signed receipts pass ${A.signed.pass}/${A.signed.of}`);
console.log(`   malformed: ${A.malformed.receipts_rejected}/${A.malformed.of} receipts rejected, ${A.malformed.chains_rejected}/${A.malformed.chains.length} chains rejected, set rejected: ${A.malformed.set_rejected}`);
for (const c of A.malformed.chains) console.log(`     ${c.name}: signatures ${c.signatures_valid}/${c.of}, broken at ${c.broken.join(", ") || "(none)"}`);
for (const [k, c] of Object.entries(A.chains)) console.log(`   ${k}: valid ${c.valid}, duplicate keys ${JSON.stringify(c.duplicate_idempotency_keys)}`);
if (A.canonicalization.misses.length) console.log("   canon misses:", JSON.stringify(A.canonicalization.misses));
console.log(`B. imported ${out.B.filter(b => b.imported).length}/${out.B.length}`);
for (const b of out.B) console.log(`   ${b.imported ? "in " : "out"} ${b.name}: ${b.type} ${b.risk} ${b.outcome} -> ${b.mapped ?? b.not_imported}`);
console.log("C. worked verdicts");
for (const c of out.C) { console.log(`   ${c.case} | ${c.mode}: ${c.verdict.outcome} ${c.verdict.invariant ?? ""}`); for (const r of c.results) console.log(`       ${r.invocation}: ${r.outcome} ${r.invariant ?? ""} ${r.reason}`); }
if (jsonOut) writeFileSync(jsonOut, JSON.stringify(out, null, 1) + "\n");
