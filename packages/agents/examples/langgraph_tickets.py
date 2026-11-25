"""How-to: record a LangGraph agent.

Add one callback handler; every tool call the graph makes is recorded. Here the model's tool calls are given as an
AIMessage, so the example runs without an API key. With a real model, replace the scripted message with your model
node: the handler records the same way.

    pip install --pre "amep-agents[langgraph]"
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from langchain_core.messages import AIMessage  # noqa: E402
from langchain_core.tools import tool  # noqa: E402
from langgraph.graph import END, START, MessagesState, StateGraph  # noqa: E402
from langgraph.prebuilt import ToolNode  # noqa: E402

from amep_agents.langchain import AmepCallbackHandler  # noqa: E402
import _setup  # noqa: E402


@tool("get_ticket")
def get_ticket_tool(ticket_id: str) -> dict:
    """Read a ticket."""
    return _setup.get_ticket(ticket_id)


@tool("update_ticket")
def update_ticket_tool(ticket_id: str, status: str) -> dict:
    """Change a ticket's status."""
    return _setup.update_ticket(ticket_id, status)


def main(ticket="4821"):
    handler = AmepCallbackHandler(_setup.new_recorder("langgraph"))
    g = StateGraph(MessagesState)
    g.add_node("tools", ToolNode([get_ticket_tool, update_ticket_tool], handle_tool_errors=True))
    g.add_edge(START, "tools")
    g.add_edge("tools", END)
    calls = [{"name": "update_ticket", "args": {"ticket_id": ticket, "status": "closed"}, "id": "call_1", "type": "tool_call"}]
    g.compile().invoke({"messages": [AIMessage(content="", tool_calls=calls)]}, config={"callbacks": [handler]})
    v, _ = handler.recorder.evaluate(_setup.KEYS)
    print(f"ticket {ticket}: {v.outcome} {v.invariant}")
    return v.outcome, v.invariant


if __name__ == "__main__":
    main()                 # 4821 is inside the delegation: preserved
    main(ticket="9999")    # 9999 is outside it: violated, I2
