// Example MCP server: a tiny ticket tracker whose tools report what they actually did.
//
// Run over stdio (serves both protocol eras):  node src/tickets-server.mjs
// The key is generated per process; a real server loads a persistent key and publishes it at KEYS_URL.
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/server";
import { Key } from "@stafordtituss/amep";
import { z } from "zod";
import { AmepEvidenceExtension, recordEffect } from "./extension.mjs";

export const KEYS_URL = "https://tickets.example/.well-known/amep-keys.json";

/**
 * A server factory for createMcpHandler / serveStdio, plus the observer key it signs with.
 * State and key are shared by every instance the factory makes. `buggy` makes update_ticket write to the wrong
 * ticket, which a receipt should expose.
 */
export function ticketServer({ observerKey = Key.generate("tickets-observer-1", ["observer"]), buggy = false } = {}) {
  const tickets = { 4821: { status: "open" }, 4822: { status: "open" } };
  const ext = new AmepEvidenceExtension({ observerKey, observedBy: "server:tickets.example", keysUrl: KEYS_URL });

  const factory = () => {
    const mcp = new McpServer({ name: "tickets", version: "0.1.0" });
    ext.registerTool(mcp, "get_ticket", { description: "Read a ticket.", inputSchema: z.object({ ticket_id: z.string() }) },
      async ({ ticket_id }) => {
        recordEffect("saas.read", `tickets:issue/${ticket_id}`, "read");
        return { content: [{ type: "text", text: JSON.stringify(tickets[ticket_id] ?? null) }] };
      });
    ext.registerTool(mcp, "update_ticket",
      { description: "Change a ticket's status.", inputSchema: z.object({ ticket_id: z.string(), status: z.string() }) },
      async ({ ticket_id, status }) => {
        const target = buggy ? "4822" : ticket_id;
        (tickets[target] ??= {}).status = status;
        recordEffect("saas.update", `tickets:issue/${target}`, "write_shared", { reversible: true });
        return { content: [{ type: "text", text: `ticket ${ticket_id} is now ${status}` }] };
      });
    ext.registerTool(mcp, "validate_only",
      { description: "Check a ticket id without changing anything.", inputSchema: z.object({ ticket_id: z.string() }) },
      async ({ ticket_id }) => ({ content: [{ type: "text", text: ticket_id in tickets ? "valid" : "unknown" }] }));
    return mcp;
  };
  return { factory, observerKey, tickets };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { serveStdio } = await import("@modelcontextprotocol/server/stdio");
  serveStdio(ticketServer().factory);
}
