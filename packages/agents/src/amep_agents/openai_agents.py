"""OpenAI Agents SDK adapter: a tracing processor that records AMEP evidence for every function-tool call.

    from agents import add_trace_processor
    from amep_agents import EvidenceRecorder
    from amep_agents.openai_agents import AmepTracingProcessor

    recorder = EvidenceRecorder(host_key, observer_key, "d-1", interpret, chain=[mandate, delegation])
    add_trace_processor(AmepTracingProcessor(recorder))
    ...  # run agents as usual; then recorder.packet() / recorder.evaluate(keys)

The SDK opens a function span around each tool call, with the arguments as JSON input and the tool output; a span
that ends with an error gets no receipt.
"""
from __future__ import annotations

import json
from typing import Any

from agents.tracing import Span, Trace, TracingProcessor
from agents.tracing.span_data import FunctionSpanData

from .recorder import EvidenceRecorder


def _args(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            v = json.loads(raw)
            return v if isinstance(v, dict) else {"input": v}
        except json.JSONDecodeError:
            return {"input": raw}
    return {}


class AmepTracingProcessor(TracingProcessor):
    """Feeds function-tool spans into an EvidenceRecorder. Other spans (LLM calls, handoffs) are ignored."""

    def __init__(self, recorder: EvidenceRecorder):
        self.recorder = recorder

    def on_trace_start(self, trace: Trace) -> None:
        pass

    def on_trace_end(self, trace: Trace) -> None:
        pass

    def on_span_start(self, span: Span[Any]) -> None:
        pass   # arguments are attached to the span after it starts, so both records are made at span end

    def on_span_end(self, span: Span[Any]) -> None:
        data = span.span_data
        if not isinstance(data, FunctionSpanData):
            return
        call_id = span.span_id
        if self.recorder.declare(call_id, data.name, _args(data.input)) is None:
            return
        output = data.output
        if isinstance(output, str):
            try:
                output = json.loads(output)   # function tools usually return JSON text
            except json.JSONDecodeError:
                pass
        self.recorder.observe(call_id, output, error=span.error["message"] if span.error else None)

    def shutdown(self) -> None:
        pass

    def force_flush(self) -> None:
        pass
