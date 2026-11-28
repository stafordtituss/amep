# AMEP Verifier: an MCP server

<!-- mcp-name: io.github.stafordtituss/amep-verifier -->

An [MCP](https://modelcontextprotocol.io) server that checks **AMEP** (Agentic Mandate Evidence Protocol) evidence: signed records of what a person authorized an AI agent to do, every delegation along the way, and what a tool or service actually executed.

Give it an evidence packet and a key set, and it returns one of three verdicts:

- `preserved`: the executed effect stayed within the delegated authority;
- `violated`: it did not; the result names the broken invariant (I1 to I11) and the party at fault (`blame`);
- `unresolved`: the evidence cannot show it either way, and the result lists the evidence needed (`gaps`). This is never permission.

Evaluation runs locally with the reference verifier from [`amep-protocol`](https://pypi.org/project/amep-protocol/). Nothing is sent anywhere.

## Tools

| Tool | What it does |
|---|---|
| `verify_packet` | Evaluates a packet against a key set. Give the packet as `packet_text`, its exact JSON text, which is parsed strictly so that duplicate member names are caught, or as `packet`, an object. Returns the verdict, a result per invocation with blame and gaps, `parsed_strictly`, and the verifier state to pass along with the next packet in a stream. |
| `explain_invariant` | Explains I1 to I11, the outcome when each is broken, and which conformance vectors exercise it. |
| `list_vectors` | Lists the bundled conformance vectors: the 311-vector AMEP suite v0.3.7 (`core`), the 20-vector W3C delegation-continuity suite (`delegation`), and the 16-vector approval-path attacks suite (`approval-path`, a draft). |
| `get_vector` | Returns one vector, with its packet (or exact `packet_text`) and test keys, ready for `verify_packet`. |
| `check_suite` | Runs a bundled suite through the verifier and reports agreement, vector by vector. |

## Install

The server runs over stdio. With [uv](https://docs.astral.sh/uv/):

```json
{
  "mcpServers": {
    "amep-verifier": { "command": "uvx", "args": ["amep-mcp"] }
  }
}
```

Or install it with `pip install --pre amep-mcp` and use `"command": "amep-mcp"`.

## Try it

Ask your MCP client:

> Use the AMEP verifier to fetch the vector `revoked-root-with-live-child` and verify it. Then explain the invariant it violates.

The verdict is `violated`, I6: the sub-agent's delegation was valid, but the user had revoked the root mandate before the sub-agent acted.

## Links

- [Specification](https://github.com/stafordtituss/amep/blob/main/spec/amep-v0.2.md) and [IETF Internet-Draft](https://datatracker.ietf.org/doc/draft-stafordtituss-agentic-mandate-evidence/)
- [Optional MCP extension for signed effect receipts](https://github.com/stafordtituss/amep/tree/main/prototypes/mcp-amep-evidence)
- Source: [`packages/mcp`](https://github.com/stafordtituss/amep/tree/main/packages/mcp)

Licensed under Apache 2.0. AMEP is a trademark of Staford Titus Selvaraj.
