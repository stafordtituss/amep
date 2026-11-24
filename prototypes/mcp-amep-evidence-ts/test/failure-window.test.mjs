// The failure window between an effect and recordEffect. Reported by Andrii (Radiolaria) on the openid-aiim list,
// 24 Nov 2026: with the effect done but the handler throwing before recordEffect, the producer signed not_executed,
// and both verifiers returned preserved. "No effect was recorded" must not become "no effect occurred".
// These are his four controls, plus an explicit refusal before acting, each with a backend counter.
// Run:  npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/server";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Key, keyset } from "@stafordtituss/amep";
import { z } from "zod";
import { AmepEvidenceExtension, NotExecuted, recordEffect, clientCapabilities } from "../src/extension.mjs";
import { Gateway } from "../src/gateway.mjs";

const UPDATE = { action: "saas.update", resource: "tickets:issue/1", effect: "write_shared" };

async function run(behaviour) {
  const observerKey = Key.generate("counter-observer-1", ["observer"]);
  const ext = new AmepEvidenceExtension({ observerKey, observedBy: "server:counter.example", keysUrl: "https://counter.example/k" });
  let counter = 0;
  const mcp = new McpServer({ name: "counter", version: "0" });
  ext.registerTool(mcp, "bump", { inputSchema: z.object({ ticket_id: z.string() }) }, async () => {
    if (behaviour === "refuse") throw new NotExecuted("ticket is locked");
    if (behaviour === "throw-before-effect") throw new Error("backend unavailable");
    counter++;                                                       // the effect happens here
    if (behaviour === "throw-before-record") throw new Error("crashed after the update");
    recordEffect(UPDATE.action, UPDATE.resource, UPDATE.effect);
    if (behaviour === "throw-after-record") throw new Error("crashed after recording");
    return { content: [{ type: "text", text: "ok" }] };
  });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await mcp.connect(a);
  const client = new Client({ name: "gateway", version: "0" }, { capabilities: clientCapabilities() });
  await client.connect(b);
  const gw = new Gateway(client, keyset(observerKey));
  await gw.call("bump", { ticket_id: "1" }, UPDATE).catch(() => {});
  await client.close();
  const { verdict } = gw.evaluate();
  return { counter, statements: gw.statements.map(s => [s.disposition, s.effect_count]), outcome: [verdict.outcome, verdict.invariant] };
}

test("1. exception before the effect: nothing ran, but the producer can't know that, so no statement: unresolved", async () => {
  const r = await run("throw-before-effect");
  assert.equal(r.counter, 0);
  assert.deepEqual(r.statements, []);
  assert.equal(r.outcome[0], "unresolved");
});

test("2. effect, then exception before recordEffect: never a signed not_executed; unresolved, not preserved", async () => {
  const r = await run("throw-before-record");
  assert.equal(r.counter, 1);
  assert.deepEqual(r.statements, []);                // formerly [["not_executed", 0]], which verified as preserved
  assert.equal(r.outcome[0], "unresolved");
});

test("3. effect recorded, then exception: failed_after_effects with one receipt", async () => {
  const r = await run("throw-after-record");
  assert.equal(r.counter, 1);
  assert.deepEqual(r.statements, [["failed_after_effects", 1]]);
});

test("4. effect recorded, successful return: completed with one receipt", async () => {
  const r = await run("ok");
  assert.equal(r.counter, 1);
  assert.deepEqual(r.statements, [["completed", 1]]);
});

test("an explicit refusal before acting (NotExecuted) is the one failure signed as not_executed", async () => {
  const r = await run("refuse");
  assert.equal(r.counter, 0);
  assert.deepEqual(r.statements, [["not_executed", 0]]);
});
