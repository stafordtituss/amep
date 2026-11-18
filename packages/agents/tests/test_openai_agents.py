"""End-to-end tests with the OpenAI Agents SDK: a real Runner and real function tools, driven by a scripted model
(no API key or network needed), with AMEP evidence recorded by the tracing processor."""
from __future__ import annotations

import json
import unittest

from agents import Agent, Runner, function_tool, set_trace_processors
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

from amep_agents.openai_agents import AmepTracingProcessor
from common import KEYS, Tickets, recorder


class ScriptedModel(Model):
    """Calls one tool, then answers. Stands in for an LLM."""

    def __init__(self, tool: str, args: dict):
        self.tool, self.args, self.turn = tool, args, 0

    async def get_response(self, *a, **kw) -> ModelResponse:
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


async def run(tool: str, args: dict, *, buggy: bool = False):
    store = Tickets(buggy=buggy)

    @function_tool
    def get_ticket(ticket_id: str) -> str:
        """Read a ticket."""
        return json.dumps(store.get(ticket_id))

    @function_tool
    def update_ticket(ticket_id: str, status: str) -> str:
        """Change a ticket's status."""
        return json.dumps(store.update(ticket_id, status))

    rec = recorder("openai-agents")
    set_trace_processors([AmepTracingProcessor(rec)])
    agent = Agent(name="support-bot", instructions="Help with tickets.", tools=[get_ticket, update_ticket],
                  model=ScriptedModel(tool, args))
    await Runner.run(agent, "please close ticket")
    return rec


class OpenAIAgentsTest(unittest.IsolatedAsyncioTestCase):
    async def test_honest_tool_is_preserved(self):
        rec = await run("update_ticket", {"ticket_id": "4821", "status": "closed"})
        p = rec.packet()
        self.assertEqual((len(p["invocations"]), len(p["effects"])), (1, 1))
        self.assertEqual(p["invocations"][0]["declared"]["resource"], "tickets:issue/4821")
        v, _ = rec.evaluate(KEYS)
        self.assertEqual((v.outcome, v.invariant), ("preserved", "-"))

    async def test_tool_that_changed_something_else_is_violated(self):
        rec = await run("update_ticket", {"ticket_id": "4821", "status": "closed"}, buggy=True)
        v, _ = rec.evaluate(KEYS)
        self.assertEqual((v.outcome, v.invariant), ("violated", "I2"))

    async def test_action_outside_delegation_is_violated(self):
        rec = await run("update_ticket", {"ticket_id": "9999", "status": "closed"})
        v, _ = rec.evaluate(KEYS)
        self.assertEqual((v.outcome, v.invariant), ("violated", "I2"))

    async def test_failed_tool_is_unresolved_not_preserved(self):
        rec = await run("update_ticket", {"ticket_id": "0000", "status": "closed"})   # tool raises
        p = rec.packet()
        self.assertEqual((len(p["invocations"]), len(p.get("effects", []))), (1, 0))
        v, _ = rec.evaluate(KEYS)
        self.assertEqual((v.outcome, v.invariant), ("unresolved", "I7"))

    async def test_read_is_preserved(self):
        rec = await run("get_ticket", {"ticket_id": "4821"})
        v, _ = rec.evaluate(KEYS)
        self.assertEqual(v.outcome, "preserved")


if __name__ == "__main__":
    unittest.main()
