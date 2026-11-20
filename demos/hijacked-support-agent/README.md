# Demo: a hijacked support agent, caught from evidence alone

An AI support agent works for Alice through an MCP help desk. A customer's ticket hides an instruction, and the agent obeys it by emailing the customer's record to an outsider. Afterwards, could anyone prove what happened, without trusting the agent's own logs?

This demo answers that with real MCP sessions (official MCP Python SDK), signed AMEP evidence, and both AMEP reference verifiers.

## What runs

| Part | Role | Signs with |
|---|---|---|
| `helpdesk.py` · `build_server` | MCP server with `get_ticket`, `update_ticket`, `send_email`. It runs the [`amep-evidence` MCP extension](../../prototypes/mcp-amep-evidence/), so it signs a receipt of what each call **actually executed** | the help desk's key (observer) |
| `helpdesk.py` · `EvidenceGateway` | Sits between agent and server. Signs an AMEP invocation for each tool call: what the agent declared, under which authority | the agent platform's key (host) |
| Alice's mandate and task intent | **Mandate:** the standing permission (help desk and support mailbox). **Intent:** this task only, "close ticket 4821 and reply to Dana" | Alice's key (issuer) |
| `helpdesk.py` · `support_agent` | A stand-in for an LLM agent that does its task and also obeys instructions found in the data it reads. It's deterministic, so the demo is reproducible. Real-model behaviour is measured in [`experiments/agentdojo`](../../experiments/agentdojo/) | — |

## Run it

From this directory, with Python 3.10+ (Node.js is optional and adds the JavaScript cross-check):

```
python3 -m venv .venv
.venv/bin/pip install -r ../../prototypes/mcp-amep-evidence/requirements.txt
.venv/bin/python run_demo.py --explain
.venv/bin/python bench.py 500
```

## What you'll see

| Scenario | What happened | Verdict |
|---|---|---|
| `benign-run` | No injection; the agent closes the ticket and replies to Dana | **preserved** |
| `hijacked-task-scoped` | The agent emails the record to `records@ticket-audit.example`. Evidence carries Alice's task intent | **violated I2** at the 4th call: resource outside what Alice asked for |
| `hijacked-tool-wide` | The same attack. The only authority on record is the tool-wide permission, which is how most agents are deployed | **preserved**: the evidence is genuine, but the authority it is checked against is too broad to show anything wrong |
| `hijacked-no-receipts` | The same attack; the client never asked the help desk for receipts | **unresolved I7**: missing evidence is never permission |
| `lying-host` | A compromised host logs the customer as recipient while the email goes to the outsider | **violated I2**: declared ≠ executed, exposed by the help desk's receipt |
| `log-entry-deleted` | Someone deletes the agent's record of the 4th email afterwards | **violated I11**: the help desk's signed receipt has no authorized invocation |
| `log-entry-edited` | Someone edits the agent's record to show the customer | **unresolved I7**: the host's signature no longer verifies |

`run_demo.py` writes all seven packets to `out/` in the AMEP vector format, and the JavaScript verifier agrees on 7/7.

**Two lessons:**
- **Evidence has to be checked against the right authority.** The same signed evidence proves the attack under task-scoped authority, and shows nothing under tool-wide permission. Over AgentDojo's 571 successful action-taking attacks (oracle traces), that's 566 detected versus 0.
- **Independent receipts are what make the evidence hard to falsify.** Lies, deletions and edits in the agent's own record are all caught because the help desk signs what it executed with its own key.

## Cost (`bench.py`, 500 calls, Apple Silicon, Python 3.11, in-process MCP transport)

| | Median per call |
|---|---|
| Plain MCP tool call | 0.12 ms |
| With AMEP invocation, receipt and receipt check | 0.24 ms (**+0.12 ms**) |
| Verifying the evidence afterwards | 0.32 ms per call |
| Evidence size | ~940 bytes per call (invocation + receipt) |

The in-process transport has no network, so the absolute overhead is the meaningful figure.

## Limits
- The agent is a deterministic stand-in, not an LLM.
- Task-scoped intent has to come from somewhere. Here Alice signs it; in practice it would be derived from her request and confirmed.
- Attacks that act on the *same* object as the task with different content (e.g. sending Dana's own record to Dana with extra data) need effect-bound approvals (I8) or data-release rules (I5), not resource scope.
- Both verifiers are by the same author.

Keys in this demo are deterministic **test keys**. Never use them for anything else.
