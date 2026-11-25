"""The OpenTelemetry join: AMEP ids, digests and verdicts on the span; the span's trace context on the invocation."""
import unittest

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
except ImportError:  # pragma: no cover
    trace = None

from amep_protocol.core import digest
from common import KEYS, recorder

if trace is not None:
    EXPORTER = InMemorySpanExporter()
    PROVIDER = TracerProvider()
    PROVIDER.add_span_processor(SimpleSpanProcessor(EXPORTER))
    TRACER = PROVIDER.get_tracer("amep-agents-test")


@unittest.skipIf(trace is None, "opentelemetry-sdk not installed")
class OtelJoin(unittest.TestCase):
    def setUp(self):
        EXPORTER.clear()

    def test_ids_digests_and_verdict_on_spans(self):
        rec = recorder("otel-test")
        with TRACER.start_as_current_span("execute_tool update_ticket") as span:
            inv = rec.declare("call_7", "update_ticket", {"ticket_id": "4821", "status": "closed"})
            receipt = rec.observe("call_7", {"updated": "4821", "status": "closed"})
            ctx = span.get_span_context()
        with TRACER.start_as_current_span("invoke_agent support"):
            v, _ = rec.evaluate(KEYS)
        tool_span, agent_span = EXPORTER.get_finished_spans()
        self.assertEqual(tool_span.attributes["amep.invocation.id"], inv["id"])
        self.assertEqual(tool_span.attributes["amep.invocation.digest"], digest(inv))
        self.assertEqual(tool_span.attributes["amep.effect.id"], receipt["id"])
        self.assertEqual((agent_span.attributes["amep.verdict.outcome"], agent_span.attributes["amep.verdict.invariant"]), ("preserved", "-"))
        self.assertEqual(inv["correlation"], {"traceparent": f"00-{ctx.trace_id:032x}-{ctx.span_id:016x}-{int(ctx.trace_flags):02x}", "tool_use_ref": "call_7"})
        self.assertEqual(v.outcome, "preserved")    # the signed correlation member doesn't change the verdict

    def test_no_arguments_or_outputs_on_spans(self):
        rec = recorder("otel-test")
        with TRACER.start_as_current_span("execute_tool update_ticket"):
            rec.declare("call_8", "update_ticket", {"ticket_id": "4821", "status": "SECRET-VALUE"})
            rec.observe("call_8", {"updated": "4821", "status": "SECRET-VALUE"})
        (span,) = EXPORTER.get_finished_spans()
        self.assertFalse(any("SECRET-VALUE" in str(v) for v in span.attributes.values()))

    def test_no_recording_span_means_no_correlation(self):
        rec = recorder("otel-test")
        inv = rec.declare("call_9", "update_ticket", {"ticket_id": "4821", "status": "closed"})
        self.assertNotIn("correlation", inv)

    def test_trace_off(self):
        rec = recorder("otel-test")
        rec.trace = False
        with TRACER.start_as_current_span("execute_tool update_ticket"):
            inv = rec.declare("call_10", "update_ticket", {"ticket_id": "4821", "status": "closed"})
        self.assertNotIn("correlation", inv)
        (span,) = EXPORTER.get_finished_spans()
        self.assertNotIn("amep.invocation.id", span.attributes)


if __name__ == "__main__":
    unittest.main()
