"""LangGraph / LangChain adapter: a callback handler that records AMEP evidence for every tool call.

    from amep_agents import EvidenceRecorder
    from amep_agents.langchain import AmepCallbackHandler

    handler = AmepCallbackHandler(EvidenceRecorder(host_key, observer_key, "d-1", interpret, chain=[...]))
    graph.invoke(inputs, config={"callbacks": [handler]})     # LangGraph (ToolNode, create_react_agent, ...)
    tool.invoke(args, config={"callbacks": [handler]})        # a single LangChain tool
    handler.recorder.evaluate(keys)

The handler records the invocation when the tool starts (before it runs) and the receipt when it ends; a tool that
raises gets no receipt.
"""
from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler

from .recorder import EvidenceRecorder


def _content(output: Any) -> Any:
    """Tool output as the tool returned it: unwrap a ToolMessage/Command if LangGraph wrapped it."""
    content = getattr(output, "content", output)
    if isinstance(content, str):
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return content
    return content


class AmepCallbackHandler(BaseCallbackHandler):
    """Feeds tool start/end/error callbacks into an EvidenceRecorder."""

    raise_error = False   # never let evidence recording break the agent run

    def __init__(self, recorder: EvidenceRecorder):
        self.recorder = recorder

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, *, run_id: UUID,
                      inputs: dict[str, Any] | None = None, **kwargs: Any) -> None:
        name = (serialized or {}).get("name") or kwargs.get("name") or "tool"
        args = inputs if isinstance(inputs, dict) else _content(input_str)
        self.recorder.declare(str(run_id), name, args if isinstance(args, dict) else {"input": args})

    def on_tool_end(self, output: Any, *, run_id: UUID, **kwargs: Any) -> None:
        self.recorder.observe(str(run_id), _content(output))

    def on_tool_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
        self.recorder.observe(str(run_id), error=error)
