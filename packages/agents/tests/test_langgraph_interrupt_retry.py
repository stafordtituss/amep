"""LangGraph human-in-the-loop and retries, with AMEP evidence recorded by the callback handler.

Two things re-run a LangGraph node: resuming after `interrupt()`, and a node's `RetryPolicy`. Evidence has to stay
correct across both. The handler records one invocation per tool *attempt* (each attempt has its own run id), and a
receipt only when the attempt finished, so:
  - interrupt, then resume with approval: the tool runs once after the resume; one invocation, one receipt: preserved;
  - interrupt, then the human declines: the tool never starts; no invocation, no receipt;
  - a tool that fails once and succeeds on retry: two invocations. The failed attempt has no receipt, so it is
    `unresolved` (I7, its effect is unknown), the successful one is `preserved`, and the packet is `unresolved`
    until someone accounts for the failed attempt. A failed attempt is never read as "did nothing".
No LLM or network is needed: tool calls are given as an AIMessage, as a model would emit them.
"""
from __future__ import annotations

import unittest

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.types import Command, RetryPolicy, interrupt

from amep_agents.langchain import AmepCallbackHandler
from common import KEYS, Tickets, recorder


def update_tool(store: Tickets, fail_first: int = 0):
    attempts = {"n": 0}

    @tool
    def update_ticket(ticket_id: str, status: str) -> dict:
        """Change a ticket's status."""
        attempts["n"] += 1
        if attempts["n"] <= fail_first:
            raise TimeoutError("backend timed out")   # transient: the node is retried
        return store.update(ticket_id, status)

    return update_ticket


def call(ticket_id: str) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": "update_ticket", "args": {"ticket_id": ticket_id, "status": "closed"},
                                              "id": "call_0", "type": "tool_call"}])


def approval_graph(store: Tickets):
    """START -> approve (interrupt) -> tools -> END, or -> END if the human declines."""
    def approve(state: MessagesState) -> Command:
        answer = interrupt({"question": "Close this ticket?", "tool_calls": state["messages"][-1].tool_calls})
        return Command(goto="tools" if answer == "yes" else END)

    g = StateGraph(MessagesState)
    g.add_node("approve", approve)
    g.add_node("tools", ToolNode([update_tool(store)]))
    g.add_edge(START, "approve")
    g.add_edge("tools", END)
    return g.compile(checkpointer=InMemorySaver())


class InterruptTest(unittest.TestCase):
    def run_with_answer(self, answer: str):
        handler = AmepCallbackHandler(recorder("langgraph"))
        graph, cfg = approval_graph(Tickets()), {"configurable": {"thread_id": "t-1"}, "callbacks": [handler]}
        graph.invoke({"messages": [call("4821")]}, config=cfg)
        self.assertEqual(handler.recorder.packet().get("invocations", []), [])      # paused before the tool: no evidence yet
        graph.invoke(Command(resume=answer), config=cfg)
        return handler.recorder

    def test_approved_after_interrupt_runs_once_and_is_preserved(self):
        rec = self.run_with_answer("yes")
        p = rec.packet()
        self.assertEqual((len(p["invocations"]), len(p["effects"])), (1, 1))
        v, _ = rec.evaluate(KEYS)
        self.assertEqual((v.outcome, v.invariant), ("preserved", "-"))

    def test_declined_after_interrupt_leaves_no_invocation(self):
        p = self.run_with_answer("no").packet()
        self.assertEqual((len(p.get("invocations", [])), len(p.get("effects", []))), (0, 0))


class RetryTest(unittest.TestCase):
    def test_failed_attempt_then_successful_retry(self):
        handler = AmepCallbackHandler(recorder("langgraph"))
        g = StateGraph(MessagesState)
        g.add_node("tools", ToolNode([update_tool(Tickets(), fail_first=1)], handle_tool_errors=False),
                   retry_policy=RetryPolicy(max_attempts=2, initial_interval=0, jitter=False,
                                            retry_on=TimeoutError))
        g.add_edge(START, "tools")
        g.add_edge("tools", END)
        g.compile().invoke({"messages": [call("4821")]}, config={"callbacks": [handler]})

        p = handler.recorder.packet()
        self.assertEqual((len(p["invocations"]), len(p["effects"])), (2, 1))   # one invocation per attempt
        v, results = handler.recorder.evaluate(KEYS)
        per_attempt = [(r.outcome, r.invariant) for r in results]
        self.assertEqual(per_attempt, [("unresolved", "I7"), ("preserved", "-")])
        self.assertEqual(v.outcome, "unresolved")   # the failed attempt's effect is unknown, not "nothing happened"


if __name__ == "__main__":
    unittest.main()
