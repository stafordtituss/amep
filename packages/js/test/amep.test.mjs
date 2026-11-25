// Tests for the amep npm package. Run: node --test packages/js/test/
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, writeFileSync, statSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { execFileSync, spawnSync } from "node:child_process";
import { verifyPacket, Key, keyset, sdk, canon, parseStrict, evaluate, verdict, sigOk, verdicts } from "../src/index.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(here, "..", "..", "..", "vectors");
const BIN = join(here, "..", "bin", "amep-protocol.mjs");
const T = 1767225600;

function build({ executed } = {}) {
  const issuer = Key.generate("issuer-1", ["issuer", "approver"]);
  const host = Key.generate("host-1", ["host"]);
  const observer = Key.generate("observer-1", ["observer"]);
  const m = issuer.sign(sdk.mandate("m-1", "user:alice", sdk.claims(["fs.*"], ["repo:app/*"], "write_local", T + 3600,
    { denyResources: ["repo:app/secrets/*"], depth: 1 })));
  const d = issuer.sign(sdk.delegation("d-1", "m-1", sdk.claims(["fs.write"], ["repo:app/src/*"], "write_local", T + 1800,
    { denyResources: ["repo:app/secrets/*"], depth: 0 })));
  const a = host.sign(sdk.interpretation("a-1", "host_shell", "r9"));
  const i = host.sign(sdk.invocation("i-1", "d-1", "a-1", T + 10, "fs.write", "repo:app/src/auth.ts", "write_local"));
  const e = observer.sign(sdk.effect("e-1", "i-1", "hook:host", "L1",
    sdk.effectBody("fs.write", executed || "repo:app/src/auth.ts", "write_local", T + 11)));
  return { packet: sdk.packet([m, d, a, i, e]), keys: keyset(issuer, host, observer) };
}

test("signed chain built with the SDK is preserved", () => {
  const { packet, keys } = build();
  assert.equal(verifyPacket(packet, keys).verdict.outcome, "preserved");
});

test("retargeted effect is violated I2", () => {
  const { packet, keys } = build({ executed: "repo:app/.env" });
  const v = verifyPacket(packet, keys).verdict;
  assert.deepEqual([v.outcome, v.invariant], ["violated", "I2"]);
});

test("tampering is unresolved I7", () => {
  const { packet, keys } = build();
  packet.effects[0].executed.resource = "repo:app/src/other.ts";
  const v = verifyPacket(packet, keys).verdict;
  assert.deepEqual([v.outcome, v.invariant], ["unresolved", "I7"]);
});

test("a key refuses kinds its roles may not sign", () => {
  const host = Key.generate("host-1", ["host"]);
  assert.throws(() => host.sign(sdk.mandate("m-x", "user:alice", sdk.claims(["*"], ["*"], "read", T))));
});

test("builders validate values", () => {
  assert.throws(() => sdk.claims(["fs.read"], ["*"], "unbounded", T));
  assert.throws(() => sdk.invocation("i", "m", "a", T, "mail.send", "mail:x", "external_send"));
});

test("PEM round trip keeps the public key", () => {
  const k = Key.generate("k", ["host"]);
  assert.deepEqual(Key.fromPem(k.toPem(), "k", ["host"]).publicEntry(), k.publicEntry());
});

test("CLI passes the conformance suite", { skip: !existsSync(VECTORS) }, () => {
  const out = execFileSync(process.execPath, [BIN, "check-suite", VECTORS], { encoding: "utf8" });
  assert.match(out, /agrees with expected outcomes on (\d+)\/\1 vectors/);
});

test("CLI verify exit codes and keygen file mode", () => {
  const dir = mkdtempSync(join(tmpdir(), "amep-"));
  for (const [name, executed, code] of [["ok", undefined, 0], ["bad", "repo:app/.env", 1]]) {
    const { packet, keys } = build({ executed });
    writeFileSync(join(dir, `${name}.json`), JSON.stringify(packet));
    writeFileSync(join(dir, `${name}-keys.json`), JSON.stringify(keys));
    const r = spawnSync(process.execPath, [BIN, "verify", join(dir, `${name}.json`), "--keys", join(dir, `${name}-keys.json`)]);
    assert.equal(r.status, code);
  }
  const r = spawnSync(process.execPath, [BIN, "keygen", "--kid", "issuer-1", "--roles", "issuer", "--out", join(dir, "issuer-1")]);
  assert.equal(r.status, 0);
  assert.equal(statSync(join(dir, "issuer-1.key.pem")).mode & 0o777, 0o600);
});

test("I-JSON number rules (spec 12.1)", () => {
  assert.equal(canon({ n: 2 ** 53 - 1 }), '{"n":9007199254740991}');
  assert.throws(() => canon({ n: 2 ** 53 }));
  assert.throws(() => parseStrict('{"amount": 1200.0000000000000001}'));
  assert.throws(() => parseStrict('{"amount": 1e400}'));
  assert.deepEqual(parseStrict('{"a": 1200.00, "b": 0.1, "c": 1.5e3}'), { a: 1200, b: 0.1, c: 1500 });
  const { packet, keys } = build();
  packet.invocations[0]["x-ticket"] = 9007199254740993;
  const v = verdict(evaluate(packet, keys, sigOk));
  assert.equal(v.outcome, "unresolved");
  assert.equal(v.invariant, "I7");
  assert.match(v.reason, /I-JSON range/);
});

// Spec 10.8: verdict records as in-toto statements in DSSE envelopes.
test("verdict statement: names the packet, verdict and blame; envelope round-trips; tampering fails", (t) => {
  const f = join(VECTORS, "must-reject", "payment-over-the-per-call-limit-without-approval.json");
  if (!existsSync(f)) return t.skip("conformance vectors not present");
  const v = JSON.parse(readFileSync(f, "utf8"));
  const keys = JSON.parse(readFileSync(join(VECTORS, "keys.json"), "utf8"));
  const bytes = Buffer.from(JSON.stringify(v.packet), "utf8");
  const st = verdicts.statement(bytes, keys, evaluate(JSON.parse(bytes.toString()), keys, sigOk));
  assert.equal(st._type, "https://in-toto.io/Statement/v1");
  assert.equal(st.predicateType, verdicts.PREDICATE_TYPE);
  assert.equal(st.subject[0].digest.sha256, createHash("sha256").update(bytes).digest("hex"));
  assert.deepEqual(st.predicate.verdict, { outcome: "violated", invariant: "I2", blame: "agent", gaps: [] });

  const k = Key.generate("verifier-1", ["observer"]);
  const env = verdicts.signEnvelope(st, k.keyObject, k.kid);
  const pub = { [k.kid]: k.publicEntry().x };
  assert.equal(verdicts.verifyEnvelope(env, pub).predicate.verdict.outcome, "violated");
  const bad = { ...env, payload: Buffer.from(Buffer.from(env.payload, "base64").toString().replace("violated", "preserved")).toString("base64") };
  assert.throws(() => verdicts.verifyEnvelope(bad, pub));
  assert.throws(() => verdicts.verifyEnvelope(env, { [k.kid]: Key.generate("x", ["observer"]).publicEntry().x }));

  // the Python implementation verifies the JavaScript signature
  const py = spawnSync("python3", ["--version"]);
  if (py.status !== 0) return;
  const d = mkdtempSync(join(tmpdir(), "amep-env-"));
  writeFileSync(join(d, "env.json"), JSON.stringify(env)); writeFileSync(join(d, "pub.json"), JSON.stringify(pub));
  const r = spawnSync("python3", [join(here, "..", "..", "..", "tools", "verify_verdict.py"), join(d, "env.json"), join(d, "pub.json")], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /verified: violated I2/);
});

test("SVR statement: preserved gets AMEP_VERDICT_PRESERVED, others none; signs and verifies; spec version matches", async (t) => {
  if (!existsSync(join(VECTORS, "keys.json"))) return t.skip("conformance vectors not present");
  const { readdirSync } = await import("node:fs");
  const { SPEC_VERSION } = await import("../src/index.mjs");
  const keys = JSON.parse(readFileSync(join(VECTORS, "keys.json"), "utf8"));
  const cases = [["positive", readdirSync(join(VECTORS, "positive")).sort()[0], [verdicts.SVR_PRESERVED]],
    ["must-reject", "payment-over-the-per-call-limit-without-approval.json", []],
    ["must-reject", "missing-effect-receipt.json", []]];
  for (const [sub, name, props] of cases) {
    const bytes = Buffer.from(JSON.stringify(JSON.parse(readFileSync(join(VECTORS, sub, name), "utf8")).packet), "utf8");
    const res = evaluate(JSON.parse(bytes.toString()), keys, sigOk);
    const s = verdicts.svrStatement(bytes, keys, res, "https://example.com/v", "2026-11-22T00:00:00Z");
    assert.equal(s.predicateType, "https://in-toto.io/attestation/svr/v0.2");
    assert.deepEqual(s.predicate.properties, props, name);
    assert.equal(s.predicate.verifier.policies[0].digest.sha256, createHash("sha256").update(canon(keys), "utf8").digest("hex"));
    assert.equal(s.predicate.verifier.policies[1].name, `amep-${SPEC_VERSION}`);
    assert.deepEqual(s.subject, verdicts.statement(bytes, keys, res).subject);
  }
  const bytes = Buffer.from("{}", "utf8");
  const s = verdicts.svrStatement(bytes, keys, evaluate({}, keys, sigOk), "https://example.com/v");
  assert.match(s.predicate.timeCreated, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  const k = Key.generate("verifier-1", ["observer"]);
  const env = verdicts.signEnvelope(s, k.keyObject, k.kid), pub = { [k.kid]: k.publicEntry().x };
  assert.throws(() => verdicts.verifyEnvelope(env, pub)); // by default only AMEP verdict statements are accepted
  assert.equal(verdicts.verifyEnvelope(env, pub, [verdicts.PREDICATE_TYPE, verdicts.SVR_TYPE]).predicateType, verdicts.SVR_TYPE);
});

// Spec 7.6 rule 6 (v0.3): a call with an unknown outcome is held in verifier state until a later packet resolves it.
test("holds: a lost instruction is held at its reserve, released when resolved, unknown without a reserve", () => {
  const CASE = join(here, "..", "..", "..", "interop", "finos-aigf", "case-421-family-office");
  const load = f => JSON.parse(readFileSync(join(CASE, f), "utf8"));
  const keys = load("keys.json");
  const st = load("state.json");
  evaluate(load("4-lost-response.packet.json"), keys, sigOk, [], st);
  assert.deepEqual(st, load("8.state.json"));   // the same state the Python verifier writes
  const st9 = load("9.state.json");
  const r = verdict(evaluate(load("9-next-batch-reconciled.packet.json"), keys, sigOk, [], st9));
  assert.deepEqual([r.outcome, r.invariant], ["preserved", "-"]);
  assert.deepEqual(st9.held, {});
  const v = JSON.parse(readFileSync(join(VECTORS, "must-reject", "period-limit-carried-across-packets-in-verifier-state.json"), "utf8"));
  const sv = structuredClone(v.state);
  evaluate({ ...v.packet, effects: [] }, JSON.parse(readFileSync(join(VECTORS, "keys.json"), "utf8")), sigOk, [], sv);
  assert.deepEqual(Object.values(sv.held), [{ invocation: "i-1", amounts: { "m-1|iso4217:EUR|2592000|0": null } }]);
  const bad = verdict(evaluate(load("1-within-mandate.packet.json"), keys, sigOk, [], { ...load("state.json"), held: { d: { invocation: "i-x", amounts: { k: 5 } } } }));
  assert.deepEqual([bad.outcome, bad.invariant], ["unresolved", "I7"]);
});

test("a signature gap says why the signature was refused (spec 10.5.1)", () => {
  const keys = JSON.parse(readFileSync(join(VECTORS, "keys.json"), "utf8"));
  const gaps = p => evaluate(p, keys, sigOk).flatMap(r => r.gaps);
  const cases = {
    "must-reject/unsigned-invocation.json": ["signature", "missing"],
    "must-reject/forged-mandate--attacker-key.json": ["signature", "unknown_key"],
    "must-reject/mandate-minted-by-host-key.json": ["signature", "role"],
    "must-reject/receipt-signature-with-s----l--malleated.json": ["receipt_signature", "invalid"],
    "must-reject/call-statement-signed-by-a-host-key.json": ["call_statement_signature", "role"],
    "must-reject/unsigned-revocation-on-the-chain.json": ["revocation_signature", "missing"],
  };
  for (const [name, [need, cause]] of Object.entries(cases)) {
    const g = gaps(JSON.parse(readFileSync(join(VECTORS, name), "utf8")).packet);
    assert.ok(g.some(x => x.need === need && x.cause === cause), name);
  }
  const v = JSON.parse(readFileSync(join(VECTORS, "must-reject/payment-over-the-per-call-limit-without-approval.json"), "utf8"));
  const p = structuredClone(v.packet); p.mandates[0].principal = "user:mallory";
  assert.deepEqual(gaps(p), [{ need: "signature", ref: "i-1", cause: "invalid" }]);
  const s = JSON.parse(readFileSync(join(VECTORS, "must-reject/self-approval-signed-by-host-key.json"), "utf8"));
  assert.ok(gaps(s.packet).every(x => !("cause" in x)));
});

test("verdict statement: the artifact as subject, the packet as an input (in-toto/attestation#625)", (t) => {
  const f = join(VECTORS, "must-reject", "payment-over-the-per-call-limit-without-approval.json");
  if (!existsSync(f)) return t.skip("conformance vectors not present");
  const v = JSON.parse(readFileSync(f, "utf8"));
  const keys = JSON.parse(readFileSync(join(VECTORS, "keys.json"), "utf8"));
  const bytes = Buffer.from(JSON.stringify(v.packet), "utf8");
  const res = evaluate(JSON.parse(bytes.toString()), keys, sigOk);
  const commit = { name: "git+https://example.com/app@refs/heads/main", digest: { gitCommit: "a".repeat(40) } };
  const st = verdicts.statement(bytes, keys, res, undefined, { subjects: [commit] });
  assert.deepEqual(st.subject, [commit]);
  assert.equal(st.predicate.packet.sha256, createHash("sha256").update(bytes).digest("hex"));
  // without subjects, unchanged: the packet is the subject, byte for byte as before
  assert.deepEqual(verdicts.statement(bytes, keys, res).subject, [{ name: "amep-packet", digest: { sha256: st.predicate.packet.sha256 } }]);
  assert.throws(() => verdicts.statement(bytes, keys, res, undefined, { subjects: [] }));
  assert.throws(() => verdicts.statement(bytes, keys, res, undefined, { subjects: [{ name: "x", digest: { sha256: "ZZ" } }] }));
});

test("a not_executed statement only the actor signed releases no hold (spec 5.8.1, from review of #24)", () => {
  const I = Key.generate("issuer-x", ["issuer"]), H = Key.generate("host-x", ["host"]), O = Key.generate("obs-x", ["observer"]);
  const keys = keyset(I, H, O);
  const m = I.sign(sdk.mandate("m-1", "user:x", sdk.claims(["tickets.update"], ["tickets:*"], "write_shared", 2000000000)), { v: 2 });
  const a = H.sign(sdk.interpretation("a-1", "tickets", "1"), { v: 2 });
  const inv = (id, t) => H.sign({ ...sdk.invocation(id, "m-1", "a-1", t, "tickets.update", "tickets:issue/1", "write_shared", { actor: "agent:x" }), operation: "op-1" }, { v: 2 });
  const i0 = inv("i-0", 5), i1 = inv("i-1", 10);
  const run = observedBy => {
    const c0 = O.sign(sdk.callStatement("c-0", "i-0", observedBy, "not_executed", 0, 6), { v: 2 });
    const e1 = O.sign(sdk.effect("e-1", "i-1", "server:tickets", "L1", sdk.effectBody("tickets.update", "tickets:issue/1", "write_shared", 11)), { v: 2 });
    const res = evaluate(sdk.packet([m, a, i0, i1, c0, e1], { amepVersion: "0.3" }), keys, sigOk);
    return Object.fromEntries(res.map(r => [r.id, [r.outcome, r.invariant]]));
  };
  // the actor's own word: i-0 stays unknown, so the retry is held
  assert.deepEqual(run("agent:x"), { "i-0": ["unresolved", "I10"], "i-1": ["unresolved", "I7"] });
  // an independent observer's statement: i-0 provably did nothing, so the retry proceeds
  assert.deepEqual(run("server:tickets"), { "i-0": ["preserved", "-"], "i-1": ["preserved", "-"] });
});

test("the actor's own key is the actor, whatever observed_by says (I10; found by the model check in formal/)", () => {
  const I = Key.generate("issuer-x", ["issuer"]), H = Key.generate("host-x", ["host", "observer"]), O = Key.generate("obs-x", ["observer"]);
  const keys = keyset(I, H, O);
  const m = I.sign(sdk.mandate("m-1", "user:x", sdk.claims(["tickets.update"], ["tickets:*"], "write_shared", 2000000000)), { v: 2 });
  const a = H.sign(sdk.interpretation("a-1", "tickets", "1"), { v: 2 });
  const inv = (id, t) => H.sign({ ...sdk.invocation(id, "m-1", "a-1", t, "tickets.update", "tickets:issue/1", "write_shared", { actor: "agent:x" }), operation: "op-1" }, { v: 2 });
  const i0 = inv("i-0", 5), i1 = inv("i-1", 10);
  const e1 = O.sign(sdk.effect("e-1", "i-1", "server:tickets", "L1", sdk.effectBody("tickets.update", "tickets:issue/1", "write_shared", 11)), { v: 2 });
  const run = (...objs) => Object.fromEntries(evaluate(sdk.packet([m, a, i0, i1, ...objs], { amepVersion: "0.3" }), keys, sigOk).map(r => [r.id, [r.outcome, r.invariant]]));
  const c0 = H.sign(sdk.callStatement("c-0", "i-0", "server:tickets", "not_executed", 0, 6), { v: 2 });
  assert.deepEqual(run(c0, e1), { "i-0": ["unresolved", "I10"], "i-1": ["unresolved", "I7"] });
  const e0 = H.sign(sdk.effect("e-0", "i-0", "server:tickets", "L1", sdk.effectBody("tickets.update", "tickets:issue/1", "write_shared", 6)), { v: 2 });
  assert.deepEqual(run(e0)["i-0"], ["unresolved", "I10"]);
});

// vectors/sequences: verifier state carried across packets; each step's verdict and the operation state it leaves
// (spec 5.8.1). From Andrii Akhtanin's review: rejected evidence must not release a hold or record an operation done.
test("operation-state sequences: verdict and carried state at every step", () => {
  const doc = JSON.parse(readFileSync(join(VECTORS, "sequences", "operation-state.json"), "utf8"));
  assert.equal(doc.sequences.length, 6);
  for (const seq of doc.sequences) {
    const state = {};
    seq.steps.forEach((step, n) => {
      const v = verdict(evaluate(step.packet, doc.keys, sigOk, [], state));
      const got = Object.fromEntries(["operations_held", "operations_done"].map(k =>
        [k, Object.fromEntries(Object.entries(state[k] || {}).map(([o, h]) => [o, h.invocation]))]));
      if ("approvals_used" in step.state_after) got.approvals_used = Object.fromEntries(Object.entries(state.approvals_used || {}).map(([a, u]) => [a, u[0]]));
      assert.deepEqual([v.outcome, v.invariant], [step.expect.outcome, step.expect.invariant], `${seq.name}, step ${n + 1}`);
      assert.deepEqual(got, step.state_after, `${seq.name}, step ${n + 1}`);
    });
  }
});
