// Tests for amep-conformance: the verify mode against real verifiers, and the import adapter on synthetic AER-1
// receipts built here from the draft's rules (no network).
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Key, keyset, sdk } from "@stafordtituss/amep";
import { loadSuite, verifyImplementation, splitCommand, markdownReport } from "../src/verify.mjs";
import { importRecord, evaluateImported } from "../src/import.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const sha = s => "sha256:" + createHash("sha256").update(s).digest("hex");

describe("verify mode", () => {
  const suites = [loadSuite(join(REPO, "vectors"))];

  test("the reference JavaScript verifier agrees on every vector", async () => {
    const r = await verifyImplementation({ suites, name: "amep-js",
      cmd: `${JSON.stringify(process.execPath)} ${JSON.stringify(join(REPO, "packages/js/bin/amep-protocol.mjs"))} verify {packet} --keys {keys} {state} --json` });
    assert.equal(r.totals.agree, r.totals.vectors);
    assert.equal(r.suites[0].sha256.length, 64);
    assert.match(markdownReport(r), /\*\*Overall:\*\* \d+\/\d+/);
  });

  test("a verifier that accepts everything is caught by the must-reject vectors", async () => {
    const dir = mkdtempSync(join(tmpdir(), "naive-"));
    const naive = join(dir, "naive.mjs");
    writeFileSync(naive, 'console.log(JSON.stringify({ outcome: "preserved", invariant: "-" }));');
    const r = await verifyImplementation({ suites, cmd: `${JSON.stringify(process.execPath)} ${JSON.stringify(naive)} {packet}` });
    assert.equal(r.suites[0].positive.agree, r.suites[0].positive.vectors);
    assert.equal(r.suites[0].must_reject.agree, 0);
  });

  test("a verifier that crashes or prints no JSON counts as a miss, never a pass", async () => {
    const r = await verifyImplementation({ suites: [{ ...suites[0], vectors: suites[0].vectors.slice(0, 3) }],
      cmd: `${JSON.stringify(process.execPath)} -e "process.exit(2)"` });
    assert.equal(r.totals.agree, 0);
    assert.equal(r.misses[0].got.outcome, "error");
  });

  test("command templates are split without a shell", () => {
    assert.deepEqual(splitCommand(`node '/a b/c.mjs' verify {packet} --keys {keys} {state}`),
      ["node", "/a b/c.mjs", "verify", "{packet}", "--keys", "{keys}", "{state}"]);
  });
});

// ---- AER-1 import ----
function aer1Receipt({ output = '{"price":"1621.82"}', tool = "live_price", provenance = "EXECUTED BY ZAMBO",
  created = "2026-11-21T01:15:11.630Z", side = ["none"], symbol = "ETH", inputHash, version = "0.4" } = {}) {
  const bytes = JSON.stringify({ output, side_effects: { declared: side } });
  const r = { id: "5497d6a7-49db-46ee-873f-54fdb28604ff", receipt_schema_version: version, created_at: created,
    tool: { name: tool, version: "4.1.4", scope: "public" }, provenance_class: provenance,
    canonical_bytes: Buffer.from(bytes).toString("base64"), output_hash: sha(bytes), verification_status: "verified",
    provenance: { request: { symbol } } };
  if (inputHash) r.input_hash = inputHash;
  // metadata block (AER-1 3.1): sorted members, no whitespace, every value a string (ASCII here, so JSON.stringify
  // escaping coincides with the draft's)
  const blk = { created_at: r.created_at, id: r.id, output_hash: r.output_hash, provenance_class: r.provenance_class,
    receipt_schema_version: r.receipt_schema_version, tool: { name: tool, scope: "public", version: "4.1.4" } };
  r.metadata_hash = sha(JSON.stringify(blk));
  return r;
}
const MAP = { tools: { live_price: { action: "market.read", resource: "market:price/{provenance.request.symbol}", effect: "read" },
  send_wire: { action: "payments.send", resource: "payee:{provenance.request.symbol}", effect: "financial" } } };

function gatewayPacket(allowed = "market:price/*", args = { symbol: "ETH" }) {
  const I = Key.generate("issuer-1", ["issuer"]), H = Key.generate("host-1", ["host"]);
  const m = I.sign(sdk.mandate("m-1", "user:alice", sdk.claims(["market.read"], [allowed], "read", "2026-12-31T00:00:00Z")), { v: 2 });
  const a = H.sign(sdk.interpretation("a-1", "mcp:zambo", "4.1.4"), { v: 2 });
  const inv = H.sign(sdk.invocation("i-1", "m-1", "a-1", "2026-11-21T01:15:09Z", "market.read", "market:price/ETH", "read",
    { argsDigest: sdk.argsDigest(args) }), { v: 2 });
  return { packet: sdk.packet([m, a, inv], { amepVersion: "0.3" }), keys: keyset(I, H), inv };
}
const importer = Key.generate("importer-1", ["observer"]);

describe("import adapter: AER-1 profile", () => {
  test("a well-formed receipt passes its own checks and maps through the tool map", () => {
    const out = importRecord(aer1Receipt(), { map: MAP, expectedId: "5497d6a7-49db-46ee-873f-54fdb28604ff" });
    assert.deepEqual([out.profile, out.integrity.verdict, out.integrity.id_verdict], ["aer1", "pass", "matched"]);
    assert.deepEqual(out.effect.executed, { action: "market.read", resource: "market:price/ETH", effect: "read", released: [], t: "2026-11-21T01:15:11.630Z" });
    assert.equal(out.effect.assurance, "L1");   // unsigned record: never more than a reconstruction
    assert.equal(out.gaps.find(g => g.need.startsWith("origin")).status, "missing");
  });

  test("bound by digest when the record's input commitment equals the invocation's args_digest", () => {
    const { packet, keys, inv } = gatewayPacket();
    const out = importRecord(aer1Receipt({ inputHash: "sha256:" + inv.args_digest }), { map: MAP, invocations: packet.invocations });
    assert.equal(out.mapping.binding, "digest");
    const ev = evaluateImported(packet, keys, [out], importer);
    assert.deepEqual([ev.verdict.outcome, ev.verdict.invariant], ["preserved", "-"]);
  });

  test("the same receipt under a mandate that only allows another resource: violated I2", () => {
    const { packet, keys } = gatewayPacket("market:price/BTC");
    const out = importRecord(aer1Receipt(), { map: MAP, invocations: packet.invocations, invocationId: "i-1" });
    assert.equal(out.mapping.binding, "asserted by the importer");
    const ev = evaluateImported(packet, keys, [out], importer);
    assert.deepEqual([ev.verdict.outcome, ev.verdict.invariant], ["violated", "I2"]);
  });

  test("a record that fails its own checks is never imported, so the call stays unresolved", () => {
    const r = aer1Receipt(); r.canonical_bytes = Buffer.from("{}").toString("base64");
    const out = importRecord(r, { map: MAP, invocationId: "i-1" });
    assert.equal(out.integrity.verdict, "verification failed");
    assert.equal(out.effect, null);
    const { packet, keys } = gatewayPacket();
    const ev = evaluateImported(packet, keys, [out], importer);
    assert.deepEqual([ev.verdict.outcome, ev.verdict.invariant], ["unresolved", "I7"]);
  });

  for (const [label, mutate, expect] of [
    ["metadata changed after hashing", r => { r.tool.version = "9.9.9"; }, /^verification failed/],
    // "YR==" decodes to "a" like the canonical "YQ==", but with non-zero pad bits
    ["non-canonical base64 (non-zero pad bits)", r => { r.canonical_bytes = "YR=="; r.output_hash = sha("a"); }, /^rejected: canonical_bytes/],
    ["leap-second timestamp", r => { r.created_at = "2026-06-30T23:59:60Z"; }, /^rejected: created_at: leap-second/],
    ["impossible calendar date", r => { r.created_at = "2026-02-30T00:00:00Z"; }, /^rejected: created_at: not a real/],
    ["unknown provenance class", r => { r.provenance_class = "TRUST ME"; }, /^rejected: provenance_class/],
    ["control character in the provenance class", r => { r.provenance_class = "LOGGED BY AGENT\u0007"; }, /^rejected: provenance_class/],
    ["nil id", r => { r.id = "00000000-0000-0000-0000-000000000000"; }, /^rejected: id/],
  ]) test(`AER-1 rules: ${label}`, () => {
    const r = aer1Receipt(); mutate(r);
    assert.match(importRecord(r, { map: MAP }).integrity.verdict, expect);
  });

  test("an id other than the one expected is reported mismatched", () => {
    assert.equal(importRecord(aer1Receipt(), { map: MAP, expectedId: "11111111-1111-4111-8111-111111111111" }).integrity.id_verdict, "mismatched");
  });

  test("committed side effects that contradict a 'read' mapping refuse the import (the map would understate the call)", () => {
    const out = importRecord(aer1Receipt({ side: ["write:external"] }), { map: MAP });
    assert.equal(out.effect, null);
    assert.match(out.not_imported, /contradict/);
  });

  test("an effect of class external_send or above is not imported without a declared release", () => {
    const out = importRecord(aer1Receipt({ tool: "send_wire", side: ["payment"] }), { map: MAP });
    assert.equal(out.effect, null);
    assert.match(out.not_imported, /declared release/);
  });

  test("a tool missing from the map, or a resource the record cannot fill, is a gap, never a guess", () => {
    assert.match(importRecord(aer1Receipt({ tool: "other_tool" }), { map: MAP }).not_imported, /not in the tool map/);
    const r = aer1Receipt(); delete r.provenance.request.symbol;
    assert.match(importRecord(r, { map: MAP }).not_imported, /resource template needs provenance.request.symbol/);
  });
});

test("the verify-by-hand recipe agrees with the reference verifier on a receipt, and catches the identity-key forgery", (t) => {
  const openssl = process.env.OPENSSL || "/opt/homebrew/bin/openssl";
  if (spawnSync(openssl, ["version"]).status !== 0 || !/OpenSSL [3-9]/.test(execFileSync(openssl, ["version"], { encoding: "utf8" })))
    return t.skip("needs OpenSSL 3 or later (set OPENSSL)");
  const run = (f, p) => spawnSync(join(REPO, "tools/verify_by_hand.sh"), [join(REPO, "vectors", f), p, join(REPO, "vectors/keys.json")],
    { env: { ...process.env, OPENSSL: openssl }, encoding: "utf8" });
  assert.equal(run("positive/call-statement-and-receipt-bound-to-the-signed-invocation.json", ".packet.effects[0]").status, 0);
  const forged = run("must-reject/receipt-under-a-small-order--identity--public-key.json", ".packet.effects[0]");
  assert.notEqual(forged.status, 0);
  assert.match(forged.stdout, /small order/);
});

// ---- OpenID DA execution layer action receipts: the AI travel agent of §9.1 ----
describe("import adapter: OpenID action receipt profile, travel-agent scenario (execution layer §9.1)", () => {
  const hashRef = s => ({ alg: "sha-256", digest: createHash("sha256").update(s).digest("hex") });
  const REQUEST = { subject: { id: "agent:travel-agent" }, action: { name: "create" }, resource: { type: "hotel_reservation" } };
  function receipt({ rs = "https://api.marriott.example", at = "2026-04-23T14:32:18Z", outcome = "success", decision = "permit" } = {}) {
    return {
      statement_class: "delegation:action-receipt", audit_id: "ai-9c5d1e3f4a6b",
      delegation: { relationship: { jti: "rel-1", hash: hashRef("rel") }, authority: { jti: "auth-1", hash: hashRef("auth") },
        task: { jti: "task-1", hash: hashRef("task") } },
      decision_attestation: { iss: "https://pdp.travel-co.example", iat: "2026-04-23T14:31:55Z", audit_id: "ai-9c5d1e3f4a6b",
        request_hash: { alg: "sha-256", digest: sdk.argsDigest(REQUEST) }, decision },
      action: { rs_identity: rs, verb: "create", resource_type: "hotel_reservation", action_time: at,
        result: { outcome, rs_identifier: "boston-7842" } },
      context: { constraint_state: { remaining_count: 4, accumulated_spend_usd: 350.00 } },
    };
  }
  const MAP = { tools: { "create:hotel_reservation": { action: "travel.reservation.create", effect: "financial", released: [],
    resource: "{action.rs_identity}/reservations/{action.result.rs_identifier}" } } };
  function taskPacket({ revokedAt } = {}) {
    // Bob's Task as an AMEP mandate: hotel bookings at Marriott or Hilton, until the end of April
    const I = Key.generate("bob-1", ["issuer"]), H = Key.generate("travel-co-host", ["host"]);
    const m = I.sign(sdk.mandate("task-1", "user:bob", sdk.claims(["travel.reservation.create"],
      ["https://api.marriott.example/*", "https://api.hilton.example/*"], "financial", "2026-04-30T23:59:59Z")), { v: 2 });
    const a = H.sign(sdk.interpretation("a-1", "da-execution-layer", "v0.2"), { v: 2 });
    const inv = H.sign(sdk.invocation("ai-9c5d1e3f4a6b", "task-1", "a-1", "2026-04-23T14:32:00Z", "travel.reservation.create",
      "https://api.marriott.example/reservations/boston-7842", "financial", { actor: "agent:travel-agent", argsDigest: sdk.argsDigest(REQUEST) }), { v: 2 });
    const objs = [m, a, inv];
    if (revokedAt) objs.push(I.sign(sdk.revocation("task-1", revokedAt), { v: 2 }));
    return { packet: sdk.packet(objs, { amepVersion: "0.3" }), keys: keyset(I, H) };
  }
  const run = (r, opts = {}) => {
    const { packet, keys } = taskPacket(opts);
    const out = importRecord(r, { map: MAP, invocations: packet.invocations, invocationId: "ai-9c5d1e3f4a6b" });
    return { out, ev: evaluateImported(packet, keys, [out], importer) };
  };
  const verdictOf = ({ ev }) => [ev.verdict.outcome, ev.verdict.invariant];

  test("a booking within the Task: preserved, bound to the call by the PDP's request_hash", () => {
    const res = run(receipt());
    assert.equal(res.out.profile, "oidf-action-receipt");
    assert.equal(res.out.mapping.binding, "digest");
    assert.deepEqual(verdictOf(res), ["preserved", "-"]);
  });
  test("a booking at a chain the Task does not allow: violated I2", () => {
    assert.deepEqual(verdictOf(run(receipt({ rs: "https://api.hyatt.example" }))), ["violated", "I2"]);
  });
  test("a booking after the Task expired: violated I2", () => {
    assert.deepEqual(verdictOf(run(receipt({ at: "2026-05-02T09:00:00Z" }))), ["violated", "I2"]);
  });
  test("a booking after the Task was revoked: violated I6", () => {
    assert.deepEqual(verdictOf(run(receipt(), { revokedAt: "2026-04-23T14:32:10Z" })), ["violated", "I6"]);
  });
  test("a network-error outcome establishes nothing: not imported, the call stays unresolved", () => {
    const res = run(receipt({ outcome: "network-error" }));
    assert.equal(res.out.effect, null);
    assert.deepEqual(verdictOf(res), ["unresolved", "I7"]);
  });
  test("an action executed under a deny is reported, never imported as authorized", () => {
    const res = run(receipt({ decision: "deny" }));
    assert.match(res.out.integrity.verdict, /verification failed/);
    assert.deepEqual(verdictOf(res), ["unresolved", "I7"]);
  });
  test("the gap report names what the receipt cannot show: the PEP signature and the action's amount", () => {
    const { out } = run(receipt());
    const amount = out.gaps.find(g => g.need === "the amount of the action");
    assert.equal(amount.status, "missing");
    assert.match(amount.detail, /accumulated_spend_usd/);
    assert.equal(out.effect.assurance, "L1");
  });
});
