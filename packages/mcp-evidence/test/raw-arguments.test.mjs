// The extension API's tools/call middleware sees the raw request. The statement's args_digest therefore covers the
// arguments exactly as the client sent them, even when the tool's schema fills in defaults. (On SDK 2.4.0, wrapping
// each tool handler, the digest covered the arguments after validation, so a default made it differ.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/server";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Key, sdk } from "@stafordtituss/amep";
import { z } from "zod";
import { amepEvidence, amepEvidenceClient, recordEffect, INVOCATION_ID_KEY, CALL_STATEMENT_KEY } from "../src/extension.mjs";

test("args_digest covers the arguments as sent, not as the schema rewrote them", async () => {
  const observerKey = Key.generate("o-1", ["observer"]);
  const mcp = new McpServer({ name: "t", version: "0" },
    { extensions: [amepEvidence({ observerKey, observedBy: "server:t", keysUrl: "https://t.example/k" })] });
  let received;
  mcp.registerTool("close", { inputSchema: z.object({ ticket_id: z.string(), status: z.string().default("closed") }) },
    async (args) => {
      received = args;
      recordEffect("saas.update", `tickets:issue/${args.ticket_id}`, "write_shared");
      return { content: [{ type: "text", text: "ok" }] };
    });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await mcp.connect(a);
  const client = new Client({ name: "c", version: "0" }, { extensions: [amepEvidenceClient()] });
  await client.connect(b);
  const sent = { ticket_id: "4821" };
  const r = await client.callTool({ name: "close", arguments: sent, _meta: { [INVOCATION_ID_KEY]: "i-raw-1" } });
  await client.close();
  assert.deepEqual(received, { ticket_id: "4821", status: "closed" });         // the tool saw the default filled in
  assert.equal(r._meta[CALL_STATEMENT_KEY].args_digest, sdk.argsDigest(sent));  // the statement covers what was sent
  assert.notEqual(r._meta[CALL_STATEMENT_KEY].args_digest, sdk.argsDigest(received));
});
