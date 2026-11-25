"""How-to: record an OpenAI Agents SDK agent.

Add one tracing processor; every function tool call the Runner makes is recorded. A scripted model stands in for the
LLM so the example runs without an API key. With a real model, drop the `model=` argument.

    pip install --pre "amep-agents[openai-agents]"
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agents import Agent, Runner, function_tool, set_trace_processors  # noqa: E402
from agents.items import ModelResponse  # noqa: E402
from agents.models.interface import Model  # noqa: E402
from agents.usage import Usage  # noqa: E402
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText  # noqa: E402

from amep_agents.openai_agents import AmepTracingProcessor  # noqa: E402
import _setup  # noqa: E402


class ScriptedModel(Model):
    """Calls one tool, then answers. Remove it to use a real model."""

    def __init__(self, tool, args):
        self.tool, self.args, self.turn = tool, args, 0

    async def get_response(self, *a, **kw):
        self.turn += 1
        if self.turn == 1:
            out = [ResponseFunctionToolCall(type="function_call", call_id="call_1", name=self.tool,
                                            arguments=json.dumps(self.args), id="fc_1", status="completed")]
        else:
            out = [ResponseOutputMessage(type="message", id="msg_1", role="assistant", status="completed",
                                         content=[ResponseOutputText(type="output_text", text="done", annotations=[])])]
        return ModelResponse(output=out, usage=Usage(), response_id=None)

    def stream_response(self, *a, **kw):
        raise NotImplementedError


@function_tool
def update_ticket(ticket_id: str, status: str) -> str:
    """Change a ticket's status."""
    return json.dumps(_setup.update_ticket(ticket_id, status))


async def run(ticket):
    recorder = _setup.new_recorder("openai-agents")
    set_trace_processors([AmepTracingProcessor(recorder)])
    agent = Agent(name="support", instructions="Close tickets.", tools=[update_ticket],
                  model=ScriptedModel("update_ticket", {"ticket_id": ticket, "status": "closed"}))
    await Runner.run(agent, f"close ticket {ticket}")
    return recorder.evaluate(_setup.KEYS)


def main(ticket="4821"):
    v, _ = asyncio.run(run(ticket))
    print(f"ticket {ticket}: {v.outcome} {v.invariant}")
    return v.outcome, v.invariant


if __name__ == "__main__":
    main()
    main(ticket="9999")
