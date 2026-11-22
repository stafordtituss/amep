// Tests for amep-conformance: the verify mode against real verifiers, and the import adapter on synthetic AER-1
// receipts built here from the draft's rules (no network).
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Key, keyset, sdk, sigOk } from "@stafordtituss/amep";
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

  test("the binding gap's wording follows input_hash_layout (wording only; binding is by digest either way)", () => {
    const { packet } = gatewayPacket();
    const inv = packet.invocations[0];
    const gap = r => importRecord(r, { map: MAP, invocations: packet.invocations }).gaps.find(g => g.need.startsWith("binding")).detail;
    const rfc = aer1Receipt({ inputHash: "sha256:" + inv.args_digest }); rfc.input_hash_layout = "rfc8785-jcs-utf8-v1";
    assert.match(gap(rfc), /^input_hash uses the RFC 8785 layout .* so the record is bound to that call$/);
    const other = aer1Receipt({ inputHash: "sha256:" + inv.args_digest }); other.input_hash_layout = "zambo-json-sorted-keys-utf8-v1";
    assert.match(gap(other), /not RFC 8785: .* bound to that call\. The rfc8785-jcs-utf8-v1 layout makes it hold/);
    const unbound = aer1Receipt({ inputHash: "sha256:" + "0".repeat(64) }); unbound.input_hash_layout = "rfc8785-jcs-utf8-v1";
    assert.match(gap(unbound), /not bound to a call$/);
  });

  test("a refused call (committed output says executed: false) produces no effect; uncommitted fields are ignored", () => {
    // the shape of a live gateway refusal record (Zambo, stafordtituss/amep#11): the refusal is inside canonical_bytes
    const refusal = JSON.stringify({ status: "payment_required", tool: "live_price", executed: false, reason: "daily_quota_exhausted" });
    const out = importRecord(aer1Receipt({ output: JSON.parse(refusal) }), { map: MAP });
    assert.equal(out.integrity.verdict, "pass");
    assert.equal(out.effect, null);
    assert.match(out.not_imported, /not executed \(status "payment_required"\).*not_executed call statement/);
    // a "not executed" outside the commitment (a hosted display field) must not suppress an executed record's effect
    const r = aer1Receipt({ output: { price: "1621.82" } });
    r.steps = [{ tool: "live_price", status: "payment_required" }]; r.result_preview = JSON.stringify({ executed: false });
    const ok = importRecord(r, { map: MAP });
    assert.equal(ok.not_imported, null);
    assert.equal(ok.effect.executed.resource, "market:price/ETH");
    // an output that says executed: true, or a string output, imports as before
    assert.ok(importRecord(aer1Receipt({ output: { executed: true, price: "1" } }), { map: MAP }).effect);
    assert.ok(importRecord(aer1Receipt(), { map: MAP }).effect);
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

// ---- Provared books (import-book) ----
import { importProvaredBook, fingerprint as provaredFingerprint } from "../src/profiles/provared.mjs";
import { evaluate as amepEvaluate } from "@stafordtituss/amep/core";
import { generateKeyPairSync } from "node:crypto";

describe("import-book: Provared", () => {
  const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "provared");
  const book = readFileSync(join(FIX, "office-supplies.jsonl"), "utf8");
  const expected = JSON.parse(readFileSync(join(FIX, "office-supplies.expected.json"), "utf8"));
  const mldsa = (() => { try { generateKeyPairSync("ml-dsa-87"); return true; } catch { return false; } })();
  const keys = { issuer: Key.generate("ii", ["issuer", "approver"]), host: Key.generate("ih", ["host"]), observer: Key.generate("io", ["observer"]) };
  const run = text => importProvaredBook(text, { keys });

  test("the sample book passes the format's own checks, with the format's own fingerprints and counts", () => {
    const out = run(book);
    assert.deepEqual(out.lines.flatMap(l => l.problems), []);
    // ML-DSA-87 needs Node 24.7 or later; without it the profile must say so, never pass the signature silently
    const unchecked = out.lines.flatMap(l => l.notChecked);
    if (mldsa) assert.deepEqual(unchecked, ["seal: signatures and tree root are not checked by this profile"]);
    else assert.ok(unchecked.some(u => u.includes("ML-DSA-87")));
    const L = book.trim().split("\n").map(l => JSON.parse(l));
    const main = e => e.stub ?? e[Object.keys(e).find(k => k !== "stamps")];
    assert.deepEqual(L.map(e => provaredFingerprint(main(e).payload)), expected.fingerprints);
    const stubs = out.lines.filter(l => l.stub);
    assert.equal(stubs.filter(l => l.stub.countersigned).length, expected.summary.counts.countersigned);
    assert.equal(stubs.filter(l => !l.stub.countersigned).length, expected.summary.counts.oneSided);
  });

  test("AMEP's verdicts on the sample book, line by line, beside the Provared checker's findings", (t) => {
    if (!mldsa) return t.skip("needs ML-DSA-87 (Node 24.7 or later) to verify the stubs");
    const out = run(book);
    const res = amepEvaluate(out.packet, out.keys, sigOk, [], structuredClone(out.state));
    const got = Object.fromEntries(res.map(r => [out.byInvocation[r.id], [r.outcome, r.invariant, r.blame]]));
    assert.deepEqual(got, {
      2: ["preserved", "-", null],         // Provared: no breach
      3: ["unresolved", "I10", null],      // Provared: no breach (AMEP needs an independent observer for external_send)
      4: ["preserved", "-", null],         // approved, countersigned
      5: ["unresolved", "I10", null],      // Provared: countersignature-missing
      6: ["violated", "I2", "agent"],      // Provared: over-limit, approval-missing
      8: ["unresolved", "I10", null],      // Provared: action-not-allowed (an AMEP gap: see interop/provared/README.md)
    });
    assert.deepEqual(expected.breaches[6], ["over-limit", "approval-missing"]);
  });

  test("tampered books fail closed", (t) => {
    if (!mldsa) return t.skip("needs ML-DSA-87 (Node 24.7 or later)");
    const b = s => Buffer.from(s, "base64url"), e = x => Buffer.from(x).toString("base64url");
    const base = book.trim().split("\n").map(l => JSON.parse(l));
    const problems = mutate => { const L = structuredClone(base); mutate(L); return run(L.map(x => JSON.stringify(x)).join("\n")).lines.flatMap(l => l.problems); };
    const flip = (rec, i, at) => { const s = b(rec.signatures[i].signature); s[at] ^= 1; rec.signatures[i].signature = e(s); };
    for (const [name, mutate, pattern] of [
      ["an amount changed", L => { const c = JSON.parse(b(L[6].stub.payload)); c.amount.value = 8;
        L[6].stub.payload = e(JSON.stringify(Object.fromEntries(Object.keys(c).sort().map(k => [k, c[k]])))); }, /Ed25519 signature does not check/],
      ["the ML-DSA-87 signature removed", L => L[2].stub.signatures.pop(), /exactly two signatures/],
      ["an Ed25519 signature flipped", L => flip(L[2].stub, 0, 5), /Ed25519 signature does not check/],
      ["an ML-DSA-87 signature flipped", L => flip(L[2].stub, 1, 100), /ML-DSA-87 signature does not check/],
      ["the slip's passkey signature flipped", L => flip(L[0].slip, 0, 60), /passkey signature does not check|malformed/],
      ["a stub deleted from the chain", L => L.splice(4, 1), /seq 3 where 2 was expected/],
      ["a countersignature moved to another stub", L => { L[3].countersignature = L[2].countersignature; }, /countersignature/],
      ["an approval moved to an unapproved stub", L => { L[6].approval = L[4].approval; }, /approval/],
      ["non-canonical content", L => { L[2].stub.payload = e(b(L[2].stub.payload).toString().replace(",", ", ")); }, /canonical form/],
    ]) assert.match(problems(mutate).join(" | "), pattern, name);
  });

  test("a gap, never an approximation: limits AMEP cannot express are reported, not mapped", () => {
    const out = run(book);
    assert.ok(out.gaps.some(g => g.need.startsWith("hard per-stub cap")));
    assert.ok(out.gaps.some(g => g.need.startsWith("count limit")));
    assert.ok(!out.mapping.limits.some(l => "per_effect" in l && l.per_effect === "100"));
  });
});

// ---- Delegation Receipt Protocol vectors ----
import { analyseVector, checkLegacyReceipt, claimsOf } from "../src/profiles/drp.mjs";
import { compare as drpCompare, amepIfExecuted } from "../../../interop/drp/compare.mjs";
import { readdirSync } from "node:fs";

describe("profile: Delegation Receipt Protocol", () => {
  const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "drp");
  const vectors = ["positive", "negative"].flatMap(d => readdirSync(join(FIX, d)).filter(f => f.endsWith(".json"))
    .map(f => JSON.parse(readFileSync(join(FIX, d, f), "utf8"))));
  const byId = id => vectors.find(v => v.id === id);

  test("DRP's own receipt checks agree with the vectors: only the invalid-signature vector fails them", () => {
    assert.equal(vectors.length, 14);
    const failing = vectors.filter(v => { const a = analyseVector(v); return [...a.checks.receipt.problems, ...a.checks.chain.flatMap(c => c.problems)].length; });
    assert.deepEqual(failing.map(v => v.id), ["invalid-signature"]);
  });

  test("a changed receipt fails the signature and the receipt id", () => {
    const v = byId("action-not-in-scope"), r = structuredClone(v.receipt);
    assert.deepEqual(checkLegacyReceipt(r, v.receiptId).problems, []);
    r.timeWindow.end = "2099-01-01T00:00:00.000Z";
    const p = checkLegacyReceipt(r, v.receiptId).problems.join(" | ");
    assert.match(p, /signature does not check/); assert.match(p, /receipt id/);
  });

  test("scope schemas: a product stays plain claims; other pairs become grants; what can't be exact is a gap", () => {
    const s = (allowed, denied = []) => ({ allowedActions: allowed.map(([operation, resource]) => ({ operation, resource })),
      deniedActions: denied.map(([operation, resource]) => ({ operation, resource })) });
    assert.deepEqual(claimsOf(s([["read", "a"], ["read", "b"]])).claims, { actions: ["drp.read"], resources: ["drp:a", "drp:b"], ceiling: "read" });
    assert.deepEqual(claimsOf(s([["read", "docs"], ["write", "reports"]])).claims.grants,
      [{ actions: ["drp.read"], resources: ["drp:docs"] }, { actions: ["drp.write"], resources: ["drp:reports"] }]);
    assert.deepEqual(claimsOf(s([["read", "a"]], [["delete", "*"]])).claims.deny_actions, ["drp.delete"]);
    assert.match(claimsOf(s([["read", "a"]], [["send", "email"]])).gap, /denied pair/);
    assert.match(claimsOf(s([["teleport", "a"]])).gap, /no AMEP effect class/);
  });

  test("AMEP beside DRP: agreement where both decide on signed or supplied scope; the rest is labelled", () => {
    const rel = Object.fromEntries(drpCompare().map(r => [r.id, r.amep.na ? "n/a" : `${r.amep.result.outcome} ${r.amep.result.invariant}`]));
    assert.deepEqual(rel, {
      "positive/authority-state-no-drift": "preserved -", "positive/delegation-chain": "preserved -", "positive/minimal-valid": "n/a",
      "positive/narrowed-sub-receipt": "preserved -", "positive/one-time-use-first-presentation": "preserved -",
      "negative/action-not-in-scope": "violated I2", "negative/chain-exceeds-max-depth": "n/a", "negative/expired": "n/a",
      "negative/invalid-signature": "n/a", "negative/one-time-use-already-consumed": "preserved -", // DRP: receipt already used
      "negative/one-time-use-no-store": "preserved -",                                                // DRP: no consumption store
      "negative/parent-scope-violation": "violated I1", "negative/replay-same-session": "n/a", "negative/tampered-action-hash": "n/a",
    });
  });

  test("grants don't widen: an action outside every allowed pair, though inside their product, is violated", () => {
    // narrowed-sub-receipt allows read documents, read reports, write reports. The product of those operations and
    // resources would also allow write documents; the grants do not.
    const v = structuredClone(byId("narrowed-sub-receipt"));
    v.action = { operation: "write", resource: "documents" };
    const out = amepIfExecuted(v, analyseVector(v));
    assert.equal(out.grants, true);
    assert.deepEqual([out.result.outcome, out.result.invariant, out.result.blame], ["violated", "I2", "agent"]);
  });
});
