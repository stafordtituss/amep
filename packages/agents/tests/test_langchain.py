"""Tests with LangGraph's ToolNode and plain LangChain tools, with AMEP evidence recorded by the callback handler.
The tool calls are given as an AIMessage, as a model would emit them, so no LLM or network is needed."""
from __future__ import annotations

import unittest

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode

from amep_agents.langchain import AmepCallbackHandler
from common import KEYS, Tickets, recorder


def tools(store: Tickets):
    @tool
    def get_ticket(ticket_id: str) -> dict:
        """Read a ticket."""
        return store.get(ticket_id)

    @tool
    def update_ticket(ticket_id: str, status: str) -> dict:
        """Change a ticket's status."""
        return store.update(ticket_id, status)

    return [get_ticket, update_ticket]


def run_graph(calls, *, buggy=False):
    """A one-node LangGraph graph: the prebuilt ToolNode executes the tool calls in an AIMessage."""
    handler = AmepCallbackHandler(recorder("langgraph"))
    g = StateGraph(MessagesState)
    g.add_node("tools", ToolNode(tools(Tickets(buggy=buggy)), handle_tool_errors=True))   # errors go back to the model
    g.add_edge(START, "tools")
    g.add_edge("tools", END)
    msg = AIMessage(content="", tool_calls=[{"name": n, "args": a, "id": f"call_{i}", "type": "tool_call"}
                                            for i, (n, a) in enumerate(calls)])
    g.compile().invoke({"messages": [msg]}, config={"callbacks": [handler]})
    return handler.recorder


class LangGraphTest(unittest.TestCase):
    def test_honest_tools_are_preserved(self):
        rec = run_graph([("get_ticket", {"ticket_id": "4821"}),
                         ("update_ticket", {"ticket_id": "4821", "status": "closed"})])
        p = rec.packet()
        self.assertEqual((len(p["invocations"]), len(p["effects"])), (2, 2))
        v, results = rec.evaluate(KEYS)
        self.assertEqual((v.outcome, v.invariant), ("preserved", "-"))
        self.assertEqual(len(results), 2)

    def test_tool_that_changed_something_else_is_violated(self):
        rec = run_graph([("update_ticket", {"ticket_id": "4821", "status": "closed"})], buggy=True)
        v, _ = rec.evaluate(KEYS)
        self.assertEqual((v.outcome, v.invariant), ("violated", "I2"))

    def test_action_outside_delegation_is_violated(self):
        rec = run_graph([("update_ticket", {"ticket_id": "9999", "status": "closed"})])
        v, _ = rec.evaluate(KEYS)
        self.assertEqual((v.outcome, v.invariant), ("violated", "I2"))

    def test_failed_tool_is_unresolved(self):
        rec = run_graph([("update_ticket", {"ticket_id": "0000", "status": "closed"})])   # raises; ToolNode reports it
        v, _ = rec.evaluate(KEYS)
        self.assertEqual((v.outcome, v.invariant), ("unresolved", "I7"))

    def test_plain_langchain_tool(self):
        handler = AmepCallbackHandler(recorder("langchain"))
        get_ticket, update_ticket = tools(Tickets())
        update_ticket.invoke({"ticket_id": "4822", "status": "closed"}, config={"callbacks": [handler]})
        v, _ = handler.recorder.evaluate(KEYS)
        self.assertEqual(v.outcome, "preserved")


if __name__ == "__main__":
    unittest.main()
