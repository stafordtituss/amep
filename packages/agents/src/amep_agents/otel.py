"""Join AMEP evidence to OpenTelemetry traces (interop/otel-genai/MAPPING.md).

When OpenTelemetry is installed and a span is recording, the recorder:
- adds the span's W3C trace context and the framework's tool-call id to each invocation (`correlation`, spec 5.8),
  so an auditor holding the evidence can find the trace;
- sets `amep.invocation.id` and `amep.invocation.digest` on the span when a call is declared, `amep.effect.id` when its
  receipt is signed, and `amep.verdict.outcome` / `amep.verdict.invariant` on the span current at evaluation, so a
  trace backend can filter for calls whose evidence is violated or unresolved.

Only ids, digests and verdicts go on spans, never tool arguments or outputs: AMEP binds those by digest. Spans are
the application's own telemetry and are not evidence; the signed records are. Without OpenTelemetry, nothing here
does anything.
"""
from __future__ import annotations

try:  # optional dependency
    from opentelemetry import trace as _trace
except ImportError:  # pragma: no cover - exercised when OpenTelemetry is absent
    _trace = None

from amep_protocol.core import digest


def _span():
    if _trace is None:
        return None
    span = _trace.get_current_span()
    return span if span is not None and span.is_recording() else None


def correlation(call_id: str | None) -> dict | None:
    """The invocation's `correlation` member for the current span, or None when there is no recording span."""
    span = _span()
    if span is None:
        return None
    ctx = span.get_span_context()
    out = {"traceparent": f"00-{ctx.trace_id:032x}-{ctx.span_id:016x}-{int(ctx.trace_flags):02x}"}
    if call_id:
        out["tool_use_ref"] = str(call_id)
    return out


def mark_invocation(inv: dict) -> None:
    span = _span()
    if span is not None:
        span.set_attribute("amep.invocation.id", inv["id"])
        span.set_attribute("amep.invocation.digest", digest(inv))


def mark_effect(receipt: dict) -> None:
    span = _span()
    if span is not None:
        span.set_attribute("amep.effect.id", receipt["id"])


def mark_verdict(v) -> None:
    span = _span()
    if span is not None:
        span.set_attribute("amep.verdict.outcome", v.outcome)
        span.set_attribute("amep.verdict.invariant", v.invariant)
