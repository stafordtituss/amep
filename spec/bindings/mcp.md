# AMEP Binding: Model Context Protocol (MCP)

| | |
|---|---|
| **Document** | `amep-binding-mcp` |
| **Version** | 0.2.0-draft.3 |
| **Status** | Public Draft. Companion to `spec/amep-v0.2.md` (the "core"). |

This binding lets MCP clients, gateways and servers exchange AMEP references, so that a tool call made through MCP can be linked to its mandate, and so that a server can return an effect receipt at assurance L3 (the receiving system confirms what it did).

The key words MUST, SHOULD and MAY are used as in BCP 14 (RFC 2119, RFC 8174).

## 1. Capability negotiation

A party that supports this binding advertises it during initialization, under the `experimental` capabilities object (or under MCP's extension mechanism once one is standardized), using the identifier `dev.amep/v0.2`:

```json
"capabilities": { "experimental": { "dev.amep/v0.2": { "effect_receipts": true, "keys": "https://tools.example/.well-known/amep-keys.json" } } }
```

| Member | Meaning |
|---|---|
| `effect_receipts` | The server returns `dev.amep/effect_receipt` in tool results (Section 3). |
| `keys` | Where the party's AMEP key set is published (core 12.4). |

A party MUST NOT send the `_meta` members below to a peer that has not advertised the capability, except `dev.amep/invocation_id`, which is harmless to ignore.

## 2. Request metadata

A client or gateway calling `tools/call` SHOULD add to the request's `_meta`:

| Key | Value |
|---|---|
| `dev.amep/invocation_id` | the AMEP Invocation `id` for this call |
| `dev.amep/mandate_ref` | the `authority_ref` the call is made under |
| `traceparent` | W3C Trace Context of the call (core 4.3) |

A server MUST NOT treat these references as authorization. They are for correlation only. Authorization comes from the transport's own credentials.

## 3. Effect receipts (L3)

A server that advertised `effect_receipts` SHOULD return an ExecutedEffectReceipt (core 5.9) in the tool result's `_meta`, under `dev.amep/effect_receipt`:

- `invocation` is the `dev.amep/invocation_id` from the request;
- `assurance` is `L3`, and `observed_by` names the server;
- `executed` describes what the server actually did, not what was requested;
- it is signed by a key with role `observer` that the server publishes.

A server that did nothing (for example, after a validation error) SHOULD return no receipt.

## 4. Adapter interpretation from tool listings

A client or gateway MAY derive an AdapterInterpretation (core 5.7) for an MCP tool from `tools/list`. Tool annotations are claims the server makes about itself. An interpretation derived from them alone MUST therefore use `source: "provider_hint"`, which does not satisfy I3. Suggested starting points:

| Annotation | Suggested effect class |
|---|---|
| `readOnlyHint: true` | `read` |
| `destructiveHint: true` | `destructive` |
| `openWorldHint: true`, for a write | `external_send` |
| otherwise | `write_shared` |

To reach `curated` or `customer`, a deployment reviews the mapping and pins it. The adapter id is `mcp:<server-name>`, and the version is a digest of the tool's name, input schema and annotations as listed. If any of these changes after review, the version changes, the pin no longer matches, and evaluation returns `unresolved` (I3) until someone reviews the new definition.

## 5. Gateways

An MCP gateway between client and server is the natural PEP and L2 observer:

- before forwarding `tools/call`, it builds the Invocation and obtains a ContinuityDecision (for example through the AuthZEN binding);
- after the result, it emits an ExecutedEffectReceipt at L2, and passes on any L3 receipt from the server unchanged;
- it MUST fail closed: if it cannot decide, it returns a tool error rather than passing the call through.

## 6. Security considerations

- Tool descriptions and results are untrusted content. A gateway SHOULD emit a ContentFinding (core 5.11) for any tool result that enters the model's context, and set `influenced_by` on later invocations accordingly.
- `_meta` members from a peer are data, never instructions.
