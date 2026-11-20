// Tests for the amep npm package. Run: node --test packages/js/test/
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, writeFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { execFileSync, spawnSync } from "node:child_process";
import { verifyPacket, Key, keyset, sdk, canon, parseStrict, evaluate, verdict, sigOk } from "../src/index.mjs";

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
