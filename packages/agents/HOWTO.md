# amep-agents how-to guides

Each guide is a short script in [`examples/`](examples/) that runs as it stands. `tests/test_examples.py` runs every one of them in CI and checks the verdict each guide says it gives.

The shared setup is [`examples/_setup.py`](examples/_setup.py):
- Alice lets a support agent read and update tickets.
- The delegation narrows that to tickets 48xx.
- Two small functions describe the tools in AMEP terms: what a call declares, and what it actually did.

| I want to… | Guide | Needs |
|---|---|---|
| Record a LangGraph or LangChain agent | [`langgraph_tickets.py`](examples/langgraph_tickets.py) | `amep-agents[langgraph]` |
| Record an OpenAI Agents SDK agent | [`openai_agents_tickets.py`](examples/openai_agents_tickets.py) | `amep-agents[openai-agents]` |
| Save the evidence and check it later, anywhere | [`save_and_verify.py`](examples/save_and_verify.py) | nothing extra |
| Keep the observer key away from the agent | [`separate_observer.py`](examples/separate_observer.py) | nothing extra |
| Publish a signed verdict (in-toto) | [`signed_verdict.py`](examples/signed_verdict.py) | nothing extra |

## Record a LangGraph agent

```python
from amep_agents.langchain import AmepCallbackHandler

handler = AmepCallbackHandler(recorder)
graph.invoke(inputs, config={"callbacks": [handler]})
verdict, results = handler.recorder.evaluate(keys)
```

The example closes ticket 4821, which is inside the delegation: `preserved`. Then it closes 9999, which is outside: `violated`, I2. The model's tool calls are scripted, so it runs without an API key. With a real model, the handler records the same way.

## Record an OpenAI Agents SDK agent

```python
from agents import set_trace_processors
from amep_agents.openai_agents import AmepTracingProcessor

set_trace_processors([AmepTracingProcessor(recorder)])
await Runner.run(agent, "close ticket 4821")
verdict, results = recorder.evaluate(keys)
```

Same two cases and same results. Drop the scripted `model=` to use a real one.

## Save the evidence and check it later

`recorder.packet()` is plain JSON, and the key set holds only public keys, so both files can be shared:

```bash
python examples/save_and_verify.py
amep-protocol verify packet.json --keys keys.json     # exit 0 preserved, 1 violated, 2 unresolved
```

The same files open in the [browser verifier](https://stafordtituss.github.io/amep/verify/), with nothing uploaded.

## Keep the observer key away from the agent

For a call of class `write_shared` or above, AMEP counts a receipt only if a party other than the agent's host signed it (I10). Where the key set names operators (spec 12.5), that party must also be under another operator. In practice, the receipt is signed where the tool runs.

The example has two sides:
- the agent's host signs the invocation;
- the ticket service signs the receipt with its own key, bound to that exact invocation by digest.

Result: `preserved`. The same receipt signed by the agent's own host key gives `unresolved`, I10: the actor vouching for itself.

## Publish a signed verdict

```python
from amep_protocol.verdicts import sign_envelope, statement
env = sign_envelope(statement(packet_bytes, keys, results, {"name": "amep-protocol", "role": "ci"}), ci_key, "ci-verifier")
```

The statement names the packet by digest and lists every result, so anyone with the packet can re-run the check rather than trust the signer. Attach it next to the release, deployment or payment it covers.
