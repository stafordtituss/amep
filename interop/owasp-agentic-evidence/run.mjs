#!/usr/bin/env node
// AMEP verdicts for the OWASP Agentic Evidence authorization-to-outcome scenarios (OWASP/Agentic-Evidence#2 and #21):
// A1-A3, B1, B2, C, D1-D3 and E1, E2, each evidence variant encoded as an AMEP packet and evaluated by the reference
// verifier. Run from the repo root:  node interop/owasp-agentic-evidence/run.mjs [--json out.json]
//
// The mapping is AMEP's reading of the scenario text, not the project's. The shared setup is #2's: a scripted PDP, an
// agent stub, and a mock tool with its own store, which the runner reads afterwards as the effect oracle.
//   grant (authority source)      -> AMEP mandate, signed by the principal's issuer key; its window -> revocation.window
//   authz.decision allow / deny   -> AMEP decision (pre_execution), signed by the host
//   tool.invocation               -> AMEP invocation, signed by the host; files.write is declared write_shared, so the
//                                    observer-independence rule (I10) applies, as it does to "no asserted record
//                                    satisfies an effect requirement" in #2
//   tool.result (asserted)        -> the executing side's own record: a key under the host's operator
//   independent effect observation (the oracle) -> an effect, or a not_executed statement, signed by a key under
//                                    another operator
//   revocation                    -> AMEP revocation, signed by the issuer
// Signing is how AMEP carries trust levels; the OWASP project defers signed evidence (OD-3), so the mapping reads its
// trust levels as AMEP keys and operators, nothing more.
import { writeFileSync } from "node:fs";
import { createHash, createPrivateKey } from "node:crypto";
import { digest, evaluate, verdict } from "../../packages/js/src/core.mjs";
import { Key, sigOk } from "../../packages/js/src/index.mjs";

const key = (kid, roles) => {
  const seed = createHash("sha256").update(`amep-test-vector-key-v1:${kid}`).digest();
  return new Key(kid, roles, createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" }));
};
const authority = key("authority-source", ["issuer"]), host = key("host-pdp", ["host"]);
const tool = key("tool-self", ["observer"]), oracle = key("effect-oracle", ["observer"]), resource = key("resource-store", ["observer"]);
// unordered-revocation: the authority source and the oracle each declare a 2 s clock skew (spec 5.12.2)
const authoritySkewed = key("authority-source-clocked", ["issuer"]), oracleSkewed = key("effect-oracle-clocked", ["observer"]);
const keys = {
  [authority.kid]: authority.publicEntry(),
  [host.kid]: { ...host.publicEntry(), operator: "agent-platform" },
  [tool.kid]: { ...tool.publicEntry(), operator: "agent-platform" },
  [oracle.kid]: { ...oracle.publicEntry(), operator: "effect-oracle" },
  [resource.kid]: { ...resource.publicEntry(), operator: "store-operator" },
  [authoritySkewed.kid]: { ...authoritySkewed.publicEntry(), operator: "authority-source", clock_skew: 2 },
  [oracleSkewed.kid]: { ...oracleSkewed.publicEntry(), operator: "effect-oracle", clock_skew: 2 },
};
const S = o => ({ ...o });   // plain copy
const WRITE = { action: "files.write", resource: "store:docs/report.txt", effect: "write_shared" };

function packet({ window, revokeAt, invocations, effects = [], statements = [], decisions = [] }) {
  const m = { id: "m-1", kind: "mandate", principal: "user:alice", claims: { actions: ["files.write"], resources: ["store:docs/*"], ceiling: "write_shared", exp: 1000 } };
  if (window !== undefined) m.revocation = { window };
  const pk = { amep_version: "0.3", mandates: [authority.sign(m, { v: 2 })],
    interpretations: [host.sign({ id: "a-1", kind: "interpretation", source: "curated", adapter: "mock-tool", version: "1" }, { v: 2 })],
    invocations, effects, call_statements: statements, decisions };
  if (revokeAt !== undefined) pk.revocations = [authority.sign({ id: "r-1", kind: "revocation", target: "m-1", t: revokeAt }, { v: 2 })];
  return pk;
}
const inv = (id = "i-1", t = 10, extra = {}) => host.sign({ id, kind: "invocation", authority_ref: "m-1", interpretation_ref: "a-1", t,
  actor: "agent:stub", declared: WRITE, ...extra }, { v: 2 });
const effect = (signer, by, i, t = 12) => signer.sign({ id: `e-${i.id}-${by}`, kind: "effect", invocation: i.id, observed_by: by,
  assurance: signer === tool ? "L1" : "L3", invocation_digest: digest(i), executed: { ...WRITE, released: [], t } }, { v: 2 });
const stmt = (signer, by, i, disposition, t = 12) => signer.sign({ id: `c-${i.id}-${by}`, kind: "call_statement", invocation: i.id,
  observed_by: by, disposition, effect_count: 0, t, invocation_digest: digest(i) }, { v: 2 });
const decision = (i, mode, reason, extra = {}) => host.sign({ id: `d-${i.id}-${mode}-${reason.slice(0, 8)}`, kind: "decision", invocation: i.id,
  outcome: mode === "deny" ? "violated" : "preserved", mode, phase: "pre_execution", reason, ...extra }, { v: 2 });

const cases = [];
const add = (scenario, variant, records, pk, state) => {
  const res = evaluate(pk, keys, sigOk, [], state ?? {});
  const v = verdict(res);
  cases.push({ scenario, variant, records, outcome: v.outcome, invariant: v.invariant, reason: v.reason, gaps: v.gaps ?? [], packet_sha256: digest(pk) });
};

// A. Authorized and executed
{ const i = inv();
  add("A1", "oracle present", "tool.result (asserted) + independent effect observation", packet({ invocations: [i], effects: [effect(tool, "tool:mock", i), effect(oracle, "runner:oracle", i)] }));
  add("A2", "oracle removed", "tool.result (asserted) only", packet({ invocations: [i], effects: [effect(tool, "tool:mock", i)] }));
  add("A3", "claim absent", "no tool.result, no observation", packet({ invocations: [i] })); }

// B. Dispatched, response lost (injected timeout). B1: the write committed; B2: it didn't.
{ const i = inv();
  add("B1", "oracle present", "independent observation shows the write", packet({ invocations: [i], effects: [effect(oracle, "runner:oracle", i)] }));
  add("B1", "oracle removed", "no tool.result, no observation", packet({ invocations: [i] }));
  add("B2", "oracle present", "independent observation shows no write", packet({ invocations: [i], statements: [stmt(oracle, "runner:oracle", i, "not_executed")] }));
  add("B2", "oracle removed", "no tool.result, no observation", packet({ invocations: [i] })); }

// C. Replay rejected: the original call took effect; a replay of the same operation is refused before dispatch.
{ const i0 = inv("i-0", 5, { operation: "op-1" }), i1 = inv("i-1", 10, { operation: "op-1" });
  add("C", "with the original invocation", "original: effect observed; replay: deny (replay rejected) + observation of no write",
    packet({ invocations: [i0, i1], effects: [effect(oracle, "runner:oracle", i0, 6)],
      statements: [stmt(oracle, "runner:oracle", i1, "not_executed")], decisions: [decision(i1, "deny", "replay rejected: operation op-1 already took effect")] }));
  add("C", "without the original invocation", "replay only: deny (replay rejected) + observation of no write",
    packet({ invocations: [i1], statements: [stmt(oracle, "runner:oracle", i1, "not_executed")], decisions: [decision(i1, "deny", "replay rejected: operation op-1 already took effect")] }));
  add("C", "control: the replay took effect", "original and replay both observed taking effect",
    packet({ invocations: [i0, i1], effects: [effect(oracle, "runner:oracle", i0, 6), effect(oracle, "runner:oracle", i1, 11)] })); }

// D. Authority withdrawn between decision and effect: invocation at 10, revocation at 15, the write lands at 20.
{ const i = inv(), late = effect(oracle, "runner:oracle", i, 20);
  add("D1", "grant declares no window", "allow; revocation at 15; write observed at 20", packet({ revokeAt: 15, invocations: [i], effects: [late], decisions: [decision(i, "allow", "policy allows files.write")] }));
  add("D1", "grant declares a 10 s window", "as above; the grant declares a 10 s propagation window", packet({ window: 10, revokeAt: 15, invocations: [i], effects: [late], decisions: [decision(i, "allow", "policy allows files.write")] }));
  add("D2", "second allow at dispatch", "allow; second allow at dispatch; revocation at 15; write observed at 20",
    packet({ revokeAt: 15, invocations: [i], effects: [late], decisions: [decision(i, "allow", "policy allows files.write"), decision(i, "allow", "re-check at dispatch")] }));
  add("D3", "resource-side check rejects the write", "allow; revocation at 15; the resource's own signed record that nothing was written",
    packet({ revokeAt: 15, invocations: [i], statements: [stmt(resource, "store:docs", i, "not_executed", 20)], decisions: [decision(i, "allow", "policy allows files.write")] }));
  // unordered-revocation: the revocation (19) and the write (20) are timed by different operators' clocks, each within 2 s
  { const pk = packet({ invocations: [i], effects: [oracleSkewed.sign({ id: "e-i-1-oracle", kind: "effect", invocation: i.id, observed_by: "runner:oracle",
      assurance: "L3", invocation_digest: digest(i), executed: { ...WRITE, released: [], t: 20 } }, { v: 2 })], decisions: [decision(i, "allow", "policy allows files.write")] });
    pk.revocations = [authoritySkewed.sign({ id: "r-1", kind: "revocation", target: "m-1", t: 19 }, { v: 2 })];
    add("D1", "unordered-revocation", "revocation at 19 and write at 20, on clocks of different operators with a 2 s skew each", pk); }
  add("D3", "no resource-side record", "allow; revocation at 15; nothing from the resource", packet({ revokeAt: 15, invocations: [i], decisions: [decision(i, "allow", "policy allows files.write")] })); }

// E. The tool reports failure. E1: it committed the write anyway; E2: it didn't.
{ const i = inv();
  add("E1", "oracle present", "tool.result failure (asserted) + independent observation of the write", packet({ invocations: [i], effects: [effect(oracle, "runner:oracle", i)] }));
  add("E1", "oracle present, tool signs 'not executed'", "the tool's own signed 'not executed' + independent observation of the write",
    packet({ invocations: [i], effects: [effect(oracle, "runner:oracle", i)], statements: [stmt(tool, "tool:mock", i, "not_executed")] }));
  add("E2", "oracle present", "tool.result failure (asserted) + independent observation of no write", packet({ invocations: [i], statements: [stmt(oracle, "runner:oracle", i, "not_executed")] }));
  add("E1/E2", "oracle removed", "tool.result failure (asserted) only", packet({ invocations: [i] })); }

const w = s => s.padEnd;
for (const c of cases) console.log(`${c.scenario.padEnd(6)} ${c.variant.padEnd(44)} ${(c.outcome + " " + c.invariant).padEnd(16)} ${c.reason}${c.gaps.length ? `  [gap: ${c.gaps.map(g => g.need).join(", ")}]` : ""}`);
const same = (a, b) => cases.find(c => c.scenario === a[0] && c.variant === a[1]).packet_sha256 === cases.find(c => c.scenario === b[0] && c.variant === b[1]).packet_sha256;
console.log(`\nB1 and B2 with the oracle removed are the same packet: ${same(["B1", "oracle removed"], ["B2", "oracle removed"])}`);
if (process.argv.includes("--json")) writeFileSync(process.argv[process.argv.indexOf("--json") + 1], JSON.stringify({ amep: "0.3.1", cases }, null, 1) + "\n");
