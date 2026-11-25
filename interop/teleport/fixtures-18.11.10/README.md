# Teleport 18.11.10: MCP audit events from a real run

**What these are:** audit events from a local Teleport cluster fronting a two-tool MCP server over stdio, captured on 25 November 2026.

**The build:** the official macOS arm64 release `teleport-v18.11.10-darwin-arm64-bin.tar.gz`, SHA-256 `11da831d…228c`, matching Teleport's published checksum.
- The binary reports build commit `3e50964c`.
- The GitHub tag `v18.11.10` points to commit `a2409e7`.

**The setup:** user `alice` holds a role that allows only the `get_ticket` tool. Personal identifiers (the host's username, hostname, paths and ports) are replaced with placeholders.

| Request (`exchange.json`) | What the client got | Audit event (`events.jsonl`) | AMEP reading |
|---|---|---|---|
| `tools/call get_ticket 4821` (allowed) | The ticket | `mcp.session.request`, `TMCP003I`, `success: true` | Dispatched; **outcome unknown** from the event alone |
| `tools/call update_ticket` (not in the role) | Error −32602, "RBAC is enforced by your Teleport roles" | `mcp.session.request`, `TMCP003E`, `success: false`, "access to resource denied" | **Not executed through this proxy** (a pre-forward denial) |
| `tools/call` with no `name` | Error −32600, "Teleport did not forward an invalid Request object" | `mcp.session.request`, `TMCP003E`, `success: false`, "\"name\" parameter missing" | Not forwarded; an invalid request, **not** a statement about an authorized call |
| `tools/call get_ticket 9999` (allowed; the tool fails) | `result` with `isError: true` | `mcp.session.request`, `TMCP003I`, `success: true`. **Identical to the call that worked** | Dispatched; **outcome unknown**. The tool's failure isn't in the audit log |

## What the run shows

1. **The mapping's two readings hold** on a real cluster. A pre-forward denial is distinguishable; a forwarded call says nothing about what the tool did.
2. **A tool error is invisible in the audit log.** The failing call and the working call produce the same event. That's the gap gravitational/teleport#70015 asks to close.
3. **One code, two meanings.** An access denial and an invalid request both carry `TMCP003E`; only the error text tells them apart. An importer has to match that text, which is fragile across releases.

## Reproduce

Teleport 18.11.10 with `proxy_listener_mode: multiplex` (needed by `tsh mcp connect`), an `app_service` app with `mcp.command` pointing at a stdio MCP server, and a role with `mcp.tools: ["get_ticket"]`. Then run `tsh login` with a signed identity, and `tsh mcp connect` to send the requests in `exchange.json`.
- `tsh mcp connect -i <identity>` failed in its reconnect layer with "missing required parameter ProxyAddress". Logging in first, with `tsh login -i`, worked.
- A local cluster with a self-signed certificate needs `teleport start --insecure`, so the app service can reach the proxy.
