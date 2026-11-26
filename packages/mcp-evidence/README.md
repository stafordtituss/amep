# amep-mcp-evidence: signed evidence for MCP tool calls

The MCP extension `io.github.stafordtituss/amep-evidence` (revision 0.3), on the MCP TypeScript SDK's extension API: `{ id, setup(ctx) }`, from typescript-sdk#2820. It's proposed in modelcontextprotocol/agents-ig#31.

**What it does:** a server that installs it signs, for each tool call the client opted in for:
- an **effect receipt** for each effect the tool actually executed;
- a **call statement** saying whether anything ran, how many receipts belong to the call, and the digest of the arguments the server received.

An auditor can then check, offline and with the server's public key, what the tool did, not just what the agent asked for.

**Status: experimental.** The extension API ships in `@modelcontextprotocol/server` and `client` **2.5.0**, which isn't released yet, and the API itself is marked experimental. This package is tested against the SDK's `main` (commit `5ee54ee`).

## Server

```js
import { McpServer } from "@modelcontextprotocol/server";
import { amepEvidence, recordEffect, NotExecuted } from "@stafordtituss/amep-mcp-evidence";

const evidence = amepEvidence({ observerKey, observedBy: "server:tickets.example",
  keysUrl: "https://tickets.example/.well-known/amep-keys.json" });
const mcp = new McpServer({ name: "tickets", version: "1.0.0" }, { extensions: [evidence] });

mcp.registerTool("update_ticket", { inputSchema }, async ({ ticket_id, status }) => {
  if (locked(ticket_id)) throw new NotExecuted("ticket is locked");    // refused before acting: signed not_executed
  await tickets.update(ticket_id, status);
  recordEffect("saas.update", `tickets:issue/${ticket_id}`, "write_shared", { reversible: true });
  return { content: [{ type: "text", text: "updated" }] };
});
```

Tools are ordinary `registerTool` tools. The extension wraps `tools/call` with `ctx.use(...)` and never changes a result's `content`.

## Client

```js
import { Client } from "@modelcontextprotocol/client";
import { amepEvidenceClient, supportsReceipts } from "@stafordtituss/amep-mcp-evidence";
import { Gateway, fetchKeySet } from "@stafordtituss/amep-mcp-evidence/gateway";

const client = new Client(info, { extensions: [amepEvidenceClient()] });
```

The reference `Gateway` signs an AMEP invocation for each call, verifies the returned evidence against the server's published key set, recovers evidence for a lost response through `resources/read`, and evaluates the result with the AMEP verifier.

## When "nothing was executed" is signed

The SDK turns a thrown tool error into an error result before middleware sees it. So the extension signs `not_executed` only when that's known:
- **A normal result with no effect recorded:** signed `not_executed`.
- **The tool threw `NotExecuted` before acting:** signed `not_executed`.
- **An error result with nothing recorded:** the tool may have acted without recording it. The outcome is unknown, so **no statement is signed**, and an AMEP verifier reports the call as `unresolved`, never as "nothing happened".
- **Effects recorded, then an error:** `failed_after_effects`, with the receipts.

## What changed from the SDK 2.4.0 prototype

The prototype (`prototypes/mcp-amep-evidence-ts`) wrapped each tool handler, so its argument digest covered the arguments *after* schema validation. The middleware sees the raw request, so `args_digest` now covers the arguments exactly as the client sent them, even when the schema fills in defaults (`test/raw-arguments.test.mjs`).

## Tests

```bash
npm test
```

There are 40 tests. They run real MCP sessions on both protocol eras (`initialize`, and `2026-07-28` with `server/discover`), over in-memory, HTTP and stdio transports, and cross-check the verdicts against AMEP's Python verifier. Until 2.5.0 ships, install a build of the SDK's `main` first.
