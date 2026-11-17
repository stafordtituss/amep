# SEP-{NUMBER}: AMEP Evidence Extension for Tool Calls

- **Status**: (unset until a working group sponsors it)
- **Type**: Extensions Track
- **Created**: 2026-11-17
- **Author(s)**: Staford Titus Selvaraj <stafordtituss@gmail.com> (@stafordtituss)
- **Sponsor**: None
- **PR**: https://github.com/modelcontextprotocol/modelcontextprotocol/pull/{NUMBER}

## Abstract

This SEP proposes an optional extension, `io.github.stafordtituss/amep-evidence`, that lets MCP clients, gateways and servers exchange signed evidence about tool calls. A client or gateway attaches stable references to each `tools/call`: an invocation identifier and the mandate the call is made under. A server that supports the extension returns, in the result's `_meta`, a signed receipt describing what it actually did: the action, the resource, its effect class and the data released. The receipt is signed by a key the server publishes, so an auditor can later check, offline and without trusting the client, whether each executed effect stayed within the authority the user delegated.

The evidence format is the Agentic Mandate Evidence Protocol (AMEP), an open specification with an IETF Internet-Draft (draft-stafordtituss-agentic-mandate-evidence-00), 95 conformance vectors, and two independent verifiers published as packages for Python and JavaScript. The extension adds no new methods and changes no core behavior. It uses only capability negotiation and `_meta`. Peers that don't advertise it behave exactly as today.

## Motivation

MCP tells a client which tools a server offers and returns each call's result. It does not let anyone prove, after the fact, what a tool call actually changed:

1. **Tool annotations are self-description.** `readOnlyHint` and `destructiveHint` are hints a server makes about itself. Clients cannot rely on them for security decisions, and nothing records whether a given call behaved as annotated.
2. **Results are not evidence.** A tool result is unsigned and may be summarized, truncated or rewritten before it reaches a log. An organization reviewing an incident cannot distinguish "the server deleted three records" from "the agent claimed it did".
3. **Delegation is invisible at the server.** When an agent calls a tool on a user's behalf, possibly through sub-agents and gateways, the server sees a credential, not the chain of authority behind the call. Audit records on each side cannot be joined reliably.

Enterprises deploying agents over MCP need audit trails that survive these gaps, and regulators increasingly ask for them. Today each gateway vendor invents its own log format, so evidence from one product cannot be checked by another.

The problem cannot be solved by the core protocol as it stands, because there is no defined place for signed, server-attested effect records or for stable correlation references across hops. An optional extension fits the problem well: it is only needed where audit evidence is wanted, and it can be ignored everywhere else.

## Specification

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174.

### Identifier

`io.github.stafordtituss/amep-evidence`

### Negotiation

**Server settings**, advertised under `capabilities.extensions` in the `server/discover` result (or the `initialize` result for protocol versions up to `2025-11-25`):

```json
"extensions": {
  "io.github.stafordtituss/amep-evidence": {
    "revision": "0.2",
    "effectReceipts": true,
    "keys": "https://tools.example/.well-known/amep-keys.json"
  }
}
```

| Field | Type | Meaning |
|---|---|---|
| `revision` | string | AMEP revision the server implements. This SEP defines `"0.2"`. |
| `effectReceipts` | boolean | The server returns effect receipts in tool results. |
| `keys` | string (HTTPS URL) | Where the server publishes its AMEP key set. |

**Client settings**, advertised under `extensions` in `_meta["io.modelcontextprotocol/clientCapabilities"]` on each request (or in the `initialize` request for protocol versions up to `2025-11-25`):

```json
"io.github.stafordtituss/amep-evidence": { "revision": "0.2", "wantsReceipts": true }
```

A server MUST NOT include receipts unless the client advertised `wantsReceipts: true` for the request.

### Request metadata

A client or gateway that has advertised the extension SHOULD include in a `tools/call` request's `params._meta`:

| Key | Value |
|---|---|
| `io.github.stafordtituss/amep-invocation-id` | string: a unique identifier for this call, used as the AMEP Invocation `id` |
| `io.github.stafordtituss/amep-mandate-ref` | string: the identifier of the AMEP mandate or delegation the call is made under |

A server MUST treat these values as correlation identifiers only. They MUST NOT be used as authorization; authorization comes from the transport's own credentials.

### Result metadata: the effect receipt

A server that advertised `effectReceipts` and received a request with `wantsReceipts: true` SHOULD include in the result's `_meta`:

```json
"_meta": {
  "io.github.stafordtituss/amep-effect-receipt": {
    "id": "e-77",
    "kind": "effect",
    "invocation": "<amep-invocation-id from the request>",
    "observed_by": "server:tickets.example",
    "assurance": "L3",
    "executed": {
      "action": "saas.update",
      "resource": "tickets:issue/4821",
      "effect": "write_shared",
      "released": [],
      "reversible": true,
      "t": 1767225611
    },
    "proof": { "alg": "Ed25519", "kid": "tickets-observer-1", "sig": "…" }
  }
}
```

Behavioral requirements:

1. The receipt is an AMEP ExecutedEffectReceipt (AMEP section 5.9). It MUST describe what the server actually executed, not what was requested.
2. `invocation` MUST equal the request's `amep-invocation-id`. If the request had none, the server MUST NOT return a receipt.
3. The receipt MUST be signed as AMEP section 12 specifies: Ed25519 over the RFC 8785 (JCS) canonical form of the receipt without its `proof`, by a key in the set at `keys` whose roles include `observer`.
4. `resource` MUST be a canonical identifier (AMEP section 6.2), and `effect` MUST be one of `read`, `write_local`, `write_shared`, `external_send`, `destructive` or `financial`.
5. A server that executed nothing (for example, after a validation error) SHOULD return no receipt.
6. A server that executed more than one effect for a single call MAY return an array of receipts under the same key.

### Client handling

1. A client MUST NOT trust a receipt it has not verified against the server's published keys.
2. A client or gateway SHOULD store received receipts with its own records of the call, so that an AMEP verifier can later evaluate the call.
3. A client that cannot verify a receipt, for example because the key set is unreachable, MUST NOT treat it as evidence, and SHOULD record that verification failed.

### Error handling and degradation

- If either peer does not advertise the extension, both MUST behave as if it did not exist. Tool calls work exactly as in the core protocol.
- A malformed receipt MUST NOT cause the tool call to fail. The client ignores the receipt and SHOULD log the problem.
- The extension never changes a tool call's result content.

## Rationale

**Why an extension and not core.** Most MCP deployments don't need signed evidence, and requiring every server to manage signing keys would add cost for no benefit. An optional extension lets the deployments that need audit evidence opt in. The intended destination is Stable rather than Core.

**Why `_meta` and not new methods.** Receipts belong to the call they describe. Attaching them to the call's own result keeps correlation trivial, needs no extra round trip, and leaves existing methods untouched.

**Why server-signed receipts.** The value of a receipt comes from who attests it. A record produced by the agent or client is self-reporting, which AMEP treats as insufficient for high-impact effects (its invariant I10). The receiving server is the only party that knows what it actually did.

**Alternatives considered.**

- *OpenTelemetry spans only:* good for correlation, but spans are unsigned and mutable, and a verifier cannot check them offline.
- *SCITT transparency logs only:* complementary, not a substitute. Receipts defined here can be registered as SCITT signed statements, and AMEP's SCITT mapping covers that.
- *A new `tools/receipt` method:* adds a round trip and a race between the call and its receipt, for no gain.
- *Annotations:* already exist and are self-description, so they cannot serve as evidence.

**Prior art.** The IETF AUDIT architecture (draft-kuehlewind-audit-architecture), SCITT, the agent audit-trail draft (draft-sharif-agent-audit-trail), OAuth token exchange (RFC 8693) for delegation chains, and OpenID AuthZEN for decisions. AMEP builds on these and defines the evaluation that tells whether an effect stayed within delegated authority.

**Consensus.** To be gathered in the sponsoring working or interest group before review. Discussion links will be added here.

## Backward Compatibility

No backward-compatibility concerns. The extension is opt-in on both sides, adds no methods, and does not change the content of any message. Peers that don't advertise it behave exactly as in the core protocol.

## Security Implications

- **Correlation identifiers are not credentials.** Servers must not grant or widen access based on `amep-mandate-ref` or `amep-invocation-id` (see Specification).
- **Key compromise.** A stolen `observer` key could forge receipts for that server. Servers should keep observer keys separate from TLS and OAuth keys, rotate them, and publish revocations in their key set.
- **Untrusted content.** Tool results, including receipts, are untrusted input to the model. Clients should not place receipts in the model's context.
- **Privacy.** Receipts can reveal what resources a user touched. They carry canonical identifiers and data-class labels, not payloads. Servers should avoid personal data in resource identifiers where possible, and deployments should treat stored receipts as sensitive audit data.
- **Replay.** A receipt binds to one invocation identifier and time; verifiers reject a receipt whose invocation is absent from the evidence they evaluate.

## Reference Implementation

- **Evidence format and verifiers (available):** the AMEP specification, conformance suite and two independent verifiers: https://github.com/stafordtituss/amep, published as `amep-protocol` on PyPI and `@stafordtituss/amep` on npm. Both include a producer SDK that creates and signs effect receipts.
- **MCP prototype (available):** https://github.com/stafordtituss/amep/tree/main/prototypes/mcp-amep-evidence, built on the official MCP Python SDK (`mcp` 2.3.0) through its extension interface (`Extension.intercept_tool_call` on the server, `ClientExtension` on the client). A reference server advertises the extension and signs receipts for what each tool actually executed. A reference gateway verifies them and evaluates the evidence. Eight integration tests run real MCP sessions, in-process and over stdio, covering: an honest server (`preserved`), a server whose receipt shows it changed a different resource than requested (`violated`), no opt-in (no receipt), a tampered receipt (rejected), a tool with no effect (no receipt), a server without the extension (unchanged behavior), and the stdio transport. Setup instructions are in its README.
- **Next step:** per the extension process, publish the extension as Experimental in an `experimental-ext-` repository associated with the sponsoring group, and port the server half into an SDK branch if the group prefers.

## Open Questions

1. Which working or interest group is the right home: authorization, security, or enterprise readiness?
2. Should the extension also define a field in `server/discover` (or Server Cards) that links each tool to a pinned AMEP interpretation, so clients can detect tool-definition changes?
3. Should multiple receipts per call be allowed in this revision, or deferred?
