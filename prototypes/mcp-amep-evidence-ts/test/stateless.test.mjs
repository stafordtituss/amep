// Documents a limit stated in the README: a 2025-era client served statelessly over HTTP gets no receipts,
// because no session holds its initialize-time capabilities. The 2026-07-28 era carries them on every request.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { INVOCATION_ID_KEY, RECEIPT_KEY, clientCapabilities } from "../src/extension.mjs";
import { ticketServer } from "../src/tickets-server.mjs";

for (const [mode, expectReceipt] of [["legacy", false], [{ pin: "2026-07-28" }, true]]) {
  test(`stateless HTTP, negotiation ${JSON.stringify(mode)}: receipt ${expectReceipt ? "sent" : "not sent"}`, async () => {
    const handler = createMcpHandler(ticketServer().factory);
    const client = new Client({ name: "gateway", version: "0" },
      { capabilities: clientCapabilities(), versionNegotiation: { mode } });
    await client.connect(new StreamableHTTPClientTransport(new URL("http://tickets.test/mcp"),
      { fetch: (url, init) => handler.fetch(new Request(url, init)) }));
    const r = await client.callTool({ name: "update_ticket", arguments: { ticket_id: "4821", status: "closed" },
      _meta: { [INVOCATION_ID_KEY]: "i-1" } });
    await client.close();
    assert.equal(r._meta?.[RECEIPT_KEY] !== undefined, expectReceipt);
  });
}
