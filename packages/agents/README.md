# amep-agents: AMEP evidence for agent frameworks

Record, for every tool call your agent makes, signed evidence of **what it declared** and **what the tool actually did**. Then check, offline, whether it stayed within the authority a person delegated. Supports:

- **OpenAI Agents SDK**: a tracing processor;
- **LangGraph and LangChain**: a callback handler.

The evidence format is **AMEP** (Agentic Mandate Evidence Protocol), an open specification with an IETF Internet-Draft. Evaluation returns one of three verdicts:

- `preserved`;
- `violated`, naming the broken invariant;
- `unresolved`, meaning evidence is missing. This is never permission.

```
pip install --pre "amep-agents[openai-agents]"     # or  "amep-agents[langgraph]"
```

## How it works

You describe your tools once:

```python
from amep_agents import Effect

def interpret(tool, args):            # what a call declares
    if tool == "update_ticket":
        return Effect("tickets.update", f"tickets:issue/{args['ticket_id']}", "write_shared", reversible=True)
    if tool == "get_ticket":
        return Effect("tickets.read", f"tickets:issue/{args['ticket_id']}", "read")
    return None                       # not governed: no evidence

def executed(tool, args, output):     # optional: what the tool reports it actually did
    if tool == "update_ticket":
        return Effect("tickets.update", f"tickets:issue/{output['updated']}", "write_shared", reversible=True)
    return interpret(tool, args)
```

The recorder then emits:
- a host-signed **invocation** for each governed call;
- an observer-signed **receipt** when the call finishes.

A tool that fails gets no receipt, so its call evaluates to `unresolved`, never `preserved`.

```python
from amep_protocol import sdk
from amep_agents import EvidenceRecorder

recorder = EvidenceRecorder(
    host_key, observer_key,                # sdk.Key with roles "host" and "observer"
    authority_ref="d-1",                   # the mandate or delegation the agent acts under
    interpret=interpret, executed=executed,
    chain=[mandate, delegation],           # the signed authority objects
    actor="agent:support-bot",
)
```

### OpenAI Agents SDK

```python
from agents import add_trace_processor
from amep_agents.openai_agents import AmepTracingProcessor

add_trace_processor(AmepTracingProcessor(recorder))
result = await Runner.run(agent, "close ticket 4821")
verdict, results = recorder.evaluate(sdk.keyset(issuer_key, host_key, observer_key))
```

### LangGraph and LangChain

```python
from amep_agents.langchain import AmepCallbackHandler

handler = AmepCallbackHandler(recorder)
graph.invoke(inputs, config={"callbacks": [handler]})
verdict, results = recorder.evaluate(keys)
```

## What it catches

| Situation | Verdict |
|---|---|
| Tool did what the agent declared, within the delegation | `preserved` |
| Tool changed something other than what was requested | `violated`, I2 |
| Agent acted on a resource outside its delegation | `violated`, I2 |
| A delegation is wider than its parent, or was revoked before the call | `violated`, I1 or I6 |
| Tool failed, or reported nothing | `unresolved`, I7 |
| LangGraph `interrupt()`, resumed with approval | one invocation and one receipt, for the run after the resume: `preserved` |
| LangGraph `RetryPolicy`: an attempt fails, the retry succeeds | one invocation per attempt; the failed attempt is `unresolved` (I7: its effect is unknown), the retry `preserved` |

The interrupt and retry cases are in [`tests/test_langgraph_interrupt_retry.py`](tests/test_langgraph_interrupt_retry.py).

## How-to guides

Runnable guides for each framework, for saving and checking evidence, for keeping the observer key away from the agent, and for publishing a signed verdict: [HOWTO.md](HOWTO.md). CI runs every one.

## Keys and trust

- **Keep the observer key away from the agent.** It should live in the tool runtime or a proxy, so that high-impact effects are observed by someone other than the actor (I10). In-process hooks give assurance level L1.
- **Stronger assurance:** for L2 or L3, have the tool server sign its own receipts, for example with the MCP extension in `prototypes/mcp-amep-evidence`.
- **Checking a packet:** `recorder.packet()` is a plain JSON packet. Anyone can check it with `amep-protocol verify`, the `amep-mcp` server, or the browser verifier.

## Links

- [Specification](https://github.com/stafordtituss/amep/blob/main/spec/amep-v0.2.md) · [IETF Internet-Draft](https://datatracker.ietf.org/doc/draft-stafordtituss-agentic-mandate-evidence/)
- Source and tests: [`packages/agents`](https://github.com/stafordtituss/amep/tree/main/packages/agents)

Licensed under Apache 2.0. AMEP is a trademark of Staford Titus Selvaraj.
