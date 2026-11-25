# Teleport MCP audit events as AMEP evidence

**What this is:** a mapping of Teleport's MCP access audit events to AMEP evidence, written with what the events can and can't establish stated plainly. It's pinned to Teleport **18.11.10**, source commit `a2409e75364ef312099347782bd71e86dcaf8d10`.

**Source:** the event behaviour below comes from a Teleport engineer's answers, including a check of this mapping's two readings against 18.11.10, in [gravitational/teleport#70011](https://github.com/gravitational/teleport/discussions/70011), with code references, and from the [MCP session audit reference](https://goteleport.com/docs/reference/audit-events/mcp-sessions/).

**No endorsement:** Teleport has not reviewed or endorsed this mapping, and says its event fields may change between releases. Treat the mapping as tied to the pinned version.

## Why a proxy's record matters to AMEP

For a high-impact call, AMEP needs a record from a party other than the agent's host (invariant I10). Since spec 12.5, that party must also be under another operator. A Teleport proxy run by a different team or organization than the agent's host is that kind of party: it sees each `tools/call` on the way through, and the host can't edit what it logged.

## The events

| Teleport event | When it's emitted | What it establishes | AMEP evidence |
|---|---|---|---|
| `mcp.session.request` with `success: false` and an **access-denied** error (for example `TMCP003E`, "access denied"), for a `tools/call` | The access check failed **before** forwarding. Teleport returns an error to the client and doesn't send the call upstream (`lib/srv/mcp/session.go` L212–254, `http.go` L355–361). | The call never reached the MCP server **through this proxy**. | A `call_statement` with `disposition: not_executed` and `effect_count: 0`, `observed_by` the proxy, for the invocation it matches. This can settle non-execution for that path (spec 5.14, rule 5), within the limits below. |
| `mcp.session.request` with `success: false` **after forwarding**: a transport error, or (HTTP) an upstream status outside [200, 400) | Teleport attempted to dispatch the call, then recorded a failure (`http.go` L396–407, L429–443). | The call may have reached the server. It is **not** evidence of non-execution. | **No `not_executed` statement.** The outcome is unknown, so the call holds its approval, operation and period reserve (spec 5.8.1, 5.10, 7.6) until the server side shows what happened. |
| `mcp.session.request` with `success: false` for a `tools/call` with no tool `name` | Rejected before forwarding as an invalid request, not an access denial. | The malformed call wasn't forwarded. | Not mapped to a statement about any authorized call. |
| `mcp.session.request` with `success: true`, for a `tools/call` | **HTTP:** no send error, and the upstream status was in [200, 400). **stdio:** the request was accepted and handed to the server writer. | Teleport forwarded the call with these exact `params` (`name`, `arguments`). **Not** that the tool ran, or what it did. A JSON-RPC tool error inside a 2xx body isn't visible (`lib/srv/mcp/http.go` L396–407, L429–443; `session.go` L233–276). | **No effect receipt.** `message.params.arguments` can be checked against the invocation's `args_digest` (SHA-256 of the RFC 8785 form), to catch arguments changed between host and proxy. The call was dispatched, so its outcome is **unknown**, which holds approvals, operations and period limits (spec 5.8.1, 5.10, 7.6). |
| (none) | Teleport records no event for the tool's result. | Nothing about the outcome. | The outcome must come from the server side: an MCP server signing effect receipts (AMEP's MCP extension), or another observer of the effect. |
| `mcp.session.start`, `.end`, `.notification`, `.listen_sse_stream`, `.invalid_http_request` | Session lifecycle and transport | Context only | Not mapped. `tools/list` and other discovery calls aren't recorded at all. |

## Limits

1. **Integrity of the record.** Teleport audit events aren't individually signed. An importer reading them from the audit log signs the AMEP statement itself, as the observer, at assurance L1. That's the same treatment AMEP gives other unsigned records, such as AER-1. A verifier then trusts the importer's access to the Teleport audit log, not a Teleport signature.
2. **"Not executed" covers one path, and denials only.** Only a pre-forward access denial supports it: a `success: false` recorded after forwarding means the outcome is unknown. A denial shows the call didn't reach the server through this proxy. It can't show the agent didn't reach the same server another way. That's AMEP's stated completeness limit (LIMITS.md, section A), and one more reason to reconcile at the system of record.
3. **The operator must actually differ.** The proxy counts as independent only if it's run by a different operator than the agent's host. In the key set, give the importer's key the proxy's operator (spec 12.5). If both are run by the same team, AMEP will, correctly, not count it.
4. **Matching events to invocations.** The match is by arguments (`args_digest`) and time. If the host doesn't record `args_digest`, the importer can only match by tool name and time, and must say so.
5. **Schema stability.** Fields and codes may change in later releases. This mapping holds for 18.11.10.

## Status

This is a mapping, not yet an import profile in `packages/conformance`. The next step is a profile with fixtures, a denied call and a forwarded call, generated from a real 18.11.10 deployment, with the per-event results published as for protect-mcp (`interop/protect-mcp/`).
