# amep-evidence on the MCP TypeScript SDK (experimental)

> **Status: Experimental.** This is a reference implementation of the MCP extension `io.github.stafordtituss/amep-evidence` on the official MCP TypeScript SDK (v2.4.0). The extension is not an official MCP extension. Its wire format may change, so pin to a commit.

MCP tool servers sign **receipts of the effects they actually executed**. A gateway signs what the agent declared, under which authority. An AMEP verifier then checks, offline and without trusting the agent, whether each executed effect stayed within what the user delegated. The verdict is `preserved`, `violated` or `unresolved`.

The extension uses only capability advertisement and `_meta`. It needs no change to the MCP protocol and is off unless both sides opt in.

| File | Role |
|---|---|
| `src/extension.mjs` | **Server:** `AmepEvidenceExtension` advertises the extension and wraps tool handlers. Tools call `recordEffect(...)` for what they actually did, and the wrapper returns signed receipts in the result's `_meta`. **Client:** `clientCapabilities()` opts in with `wantsReceipts`; `supportsReceipts(client)` lets a client find and filter for servers that sign receipts before calling any tool. |
| `src/gateway.mjs` | Reference gateway: signs an AMEP invocation per call, sends the invocation id in `_meta`, fetches the server's key set (`fetchKeySet`, HTTPS only, observer keys only), verifies receipts, and evaluates the evidence. |
| `src/tickets-server.mjs` | Example server (a tiny ticket tracker). `node src/tickets-server.mjs` serves it over stdio. |
| `test/` | 24 integration tests with real MCP sessions. |

## Quick start

```bash
cd prototypes/mcp-amep-evidence-ts
npm install
npm test
```

### Server

```js
import { McpServer } from "@modelcontextprotocol/server";
import { Key } from "@stafordtituss/amep";
import { AmepEvidenceExtension, recordEffect } from "./src/extension.mjs";

const ext = new AmepEvidenceExtension({
  observerKey: Key.fromPem(pem, "tickets-observer-1", ["observer"]),
  observedBy: "server:tickets.example",
  keysUrl: "https://tickets.example/.well-known/amep-keys.json",
});

const mcp = new McpServer({ name: "tickets", version: "1.0.0" });
ext.registerTool(mcp, "update_ticket", { inputSchema }, async ({ ticket_id, status }) => {
  await tickets.update(ticket_id, status);
  recordEffect("saas.update", `tickets:issue/${ticket_id}`, "write_shared", { reversible: true });
  return { content: [{ type: "text", text: "done" }] };
});
```

### Client

```js
import { Client } from "@modelcontextprotocol/client";
import { clientCapabilities, supportsReceipts } from "./src/extension.mjs";
import { Gateway } from "./src/gateway.mjs";

const client = new Client({ name: "gateway", version: "1.0.0" }, { capabilities: clientCapabilities() });
await client.connect(transport);
if (supportsReceipts(client)) {
  const gw = new Gateway(client, await Gateway.discoverKeys(client));
  await gw.call("update_ticket", { ticket_id: "4821", status: "closed" },
    { action: "saas.update", resource: "tickets:issue/4821", effect: "write_shared" });
  console.log(gw.evaluate().verdict); // { outcome: "preserved", ... }
}
```

## What the tests show

Every behavior is tested on **both protocol eras** the SDK serves:
- **2025-era:** capabilities exchanged in `initialize`.
- **2026-07-28:** server capabilities in `server/discover`, client capabilities in each request's `_meta` envelope, served through `createMcpHandler`.

| Test | Outcome |
|---|---|
| The server advertises the extension | The client reads `revision`, `effectReceipts` and `keys`, and `supportsReceipts` is true, before any tool call |
| An honest server | Signed receipt; verdict `preserved` |
| A server that changes a different ticket than requested | Its own receipt exposes it: `violated` (I2) |
| A client that did not opt in | No receipt: `unresolved` (I7), because missing evidence is never permission |
| A receipt tampered with in transit | The gateway rejects it: `unresolved` (I7) |
| A tool that executes nothing | No receipt |
| A server without the extension | Tool calls work exactly as in core MCP |
| A client that does not know the extension | Plain results, no receipts |

Plus:
- the real stdio transport (`serveStdio`);
- key discovery:
  - the gateway fetches the advertised key set;
  - it drops revoked keys, expired keys and keys without the observer role;
  - it refuses non-HTTPS URLs;
  - it never trusts a server key for anything but receipts;
- a cross-check: the **Python reference verifier** returns the same verdicts as the JavaScript one on the packets this gateway produces.

## Notes and limits

- **Partial adoption.** Each server opts in. Calls to servers without the extension are unaffected; their effects are simply `unresolved` rather than verified. A deployment can require receipts only for high-impact tools.
- **Stateless legacy HTTP.** A 2025-era client served statelessly over HTTP has no session that holds its `initialize` capabilities, so the server cannot see `wantsReceipts` and sends no receipts (tested in `test/stateless.test.mjs`). Use a stateful session, or the 2026-07-28 era, where the capability travels with each request.
- **Trust.** A receipt proves what the server says it did, signed with its own key. It protects against a lying or compromised agent or host, not against a dishonest server. Trust in the key set rests on HTTPS (see AMEP spec sections 12.4–12.6 and 17).
- **Keys.** The example server generates a key per process. A real server loads a persistent key and publishes the public half at its `keys` URL.

## Related

- [SEP draft](../../proposals/mcp-sep-amep-evidence.md)
- [Python prototype on the official MCP Python SDK](../mcp-amep-evidence/)
- [AMEP specification](../../spec/amep-v0.2.md)

## License

Apache 2.0, as for the rest of the repository.
