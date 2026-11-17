# Prototype: MCP extension `io.github.stafordtituss/amep-evidence`

Reference prototype for the MCP Extensions Track SEP in [`proposals/mcp-sep-amep-evidence.md`](../../proposals/mcp-sep-amep-evidence.md), built on the **official MCP Python SDK** (`mcp` 2.3.0) using its extension interface (`mcp.server.extension.Extension` and `mcp.client.extension.ClientExtension`).

| File | What it is |
|---|---|
| `amep_evidence.py` | The extension. Server half: advertises the extension and, through `intercept_tool_call`, signs AMEP effect receipts for what each tool actually executed. Client half: advertises `wantsReceipts`. |
| `tickets_server.py` | A small reference MCP server (a ticket tracker) whose tools report their real effects with `record_effect(...)`. |
| `gateway.py` | A reference client/gateway: signs an AMEP Invocation for each call, sends the invocation id in `_meta`, verifies returned receipts against the server's key, and evaluates the evidence with the AMEP verifier. |
| `test_prototype.py` | Integration tests over real MCP sessions (in-process and stdio). |

## Run it

Requires Python 3.10 or later. From this directory:

```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest -v test_prototype
```

The tests import the AMEP reference package from `../../packages/python/src`, so run them from a checkout of the repository.

## What the tests show

| Test | Outcome |
|---|---|
| The server advertises the extension and its settings | `capabilities.extensions` carries `revision`, `effectReceipts`, `keys` |
| An honest server | signed receipt; AMEP verdict `preserved` |
| A server that changes a different ticket than requested | the receipt exposes it; `violated` (I2) |
| A client that did not opt in | no receipt; `unresolved` (I7): missing evidence is never permission |
| A receipt tampered with in transit | the gateway rejects it; `unresolved` (I7) |
| A tool that executes nothing | no receipt |
| A server without the extension | tool calls work exactly as in core MCP |
| The real stdio transport | a signed receipt arrives in the result's `_meta` |

## Deviations from the SEP, for the prototype only

- **Key discovery.** The SEP has servers publish their key set at an HTTPS URL (`keys`). The prototype advertises such a URL but, to stay self-contained, the tests hand the server's public key to the gateway directly.
- **Clock.** Receipt times use the server's local clock.

## License

Apache 2.0, as for the rest of the repository.
