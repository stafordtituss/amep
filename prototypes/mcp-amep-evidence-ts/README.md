# amep-evidence on the MCP TypeScript SDK (experimental)

> **Status: Experimental.** This is a reference implementation of revision 0.3 of the MCP extension `io.github.stafordtituss/amep-evidence` on the official MCP TypeScript SDK (v2.4.0), using the AMEP 0.3 verifier in this repository. The extension is not an official MCP extension. Its wire format may change, so pin to a commit.

MCP tool servers sign **receipts of the effects they actually executed**, plus one **call statement** per call: whether anything was executed, how many receipts belong to the call, and a digest of the arguments the server received. A gateway signs what the agent declared, under which authority, with a digest of the arguments it sent. An AMEP verifier then checks, offline and without trusting the agent, whether each executed effect stayed within what the user delegated. The verdict is `preserved`, `violated` or `unresolved`.

The extension uses only capability advertisement and `_meta`. It needs no change to the MCP protocol and is off unless both sides opt in.

| File | Role |
|---|---|
| `src/extension.mjs` | **Server:** `AmepEvidenceExtension` advertises the extension and wraps tool handlers. Tools call `recordEffect(...)` for what they actually did, on the execution path. Before the result leaves the server, the wrapper signs the receipts and the call statement, stores them (write-ahead), and returns them in the result's `_meta`. A client whose response was lost fetches them with `resources/read` on `amep-receipt://{invocation}`. **Client:** `clientCapabilities()` opts in with `wantsReceipts`; `supportsReceipts(client)` lets a client find and filter for servers that sign receipts before calling any tool. |
| `src/gateway.mjs` | Reference gateway: signs an AMEP invocation per call (random 128-bit id, digest of the arguments sent), sends the id and the digest of the signed invocation in `_meta`, fetches the server's key set (`fetchKeySet`, HTTPS only, observer keys only), verifies statements and receipts (bound to that exact invocation), recovers them after a lost response, and evaluates the evidence as an AMEP 0.3 packet. |
| `src/tickets-server.mjs` | Example server (a tiny ticket tracker). `node src/tickets-server.mjs` serves it over stdio. |
| `test/` | 34 integration tests with real MCP sessions. |

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
| A tool that executes nothing | No receipt, and a signed `not_executed` statement: the call is provably `preserved`, not `unresolved` |
| Arguments changed between the gateway and the server | The server's statement shows a different argument digest: `violated` (I2) |
| A genuine receipt from another call presented for this one | Rejected (bound to another invocation); the statement shows a receipt missing: `unresolved` (I7) |
| The response is lost after the tool ran | The gateway recovers the statement and receipt with `resources/read`: `preserved` |
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
- **Arguments as received.** SDK 2.4.0 passes tool handlers the arguments after schema validation, not the raw request, so the server's argument digest covers what the tool received. A schema that strips or defaults fields makes it differ from what the gateway sent. The `ctx.use('tools/call')` middleware of typescript-sdk#2820 sees the raw request and removes this limit; the port to that API will use it.
- **Receipt recovery.** Evidence is kept in a `MemoryReceiptStore` (the most recent 10,000 calls) unless the server supplies a durable store. Invocation ids are unguessable and never listed, and receipts carry identifiers, not payloads.
- **Keys.** The example server generates a key per process. A real server loads a persistent key and publishes the public half at its `keys` URL.

## Related

- [SEP draft](../../proposals/mcp-sep-amep-evidence.md)
- [Python prototype on the official MCP Python SDK](../mcp-amep-evidence/)
- [AMEP specification](../../spec/amep-v0.2.md)

## License

Apache 2.0, as for the rest of the repository.
