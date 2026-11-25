# AMEP evidence alongside OpenTelemetry GenAI traces

**Purpose:** connect AMEP evidence with the OpenTelemetry GenAI semantic conventions (agent and tool spans), so a team that already traces its agents can find the evidence for any tool call from its trace, and the trace from its evidence.

**Status:** a proposed mapping. It is not part of either specification, and the attribute names below are AMEP's own, not OpenTelemetry's.

## Two records of one call

| | OpenTelemetry trace | AMEP evidence |
|---|---|---|
| **Purpose** | Observability: latency, errors, what ran | Accountability: whether what ran stayed within delegated authority |
| **Integrity** | None required; spans are mutable telemetry | Every object signed by the party that made it |
| **Who records the outcome** | The process that runs the code | For high-impact calls, a party other than the agent's host (I10) |

## Joining them

An `execute_tool` span carries `gen_ai.tool.name` and `gen_ai.tool.call.id`. AMEP's recorder signs an invocation per governed call and a receipt when it ends. The proposed join is:
- **On the span:** `amep.invocation.id`, plus, once the receipt exists, `amep.effect.id` and the invocation's SHA-256 as `amep.invocation.digest`.
- **On the invocation:** optionally `correlation.tool_use_ref` = `gen_ai.tool.call.id` and `correlation.traceparent` = the span's W3C trace context (spec 5.8, `correlation`).
- **On the `invoke_agent` span, after evaluation:** `amep.verdict.outcome` and `amep.verdict.invariant`.

A trace backend can then filter for tool calls whose evidence is `violated` or `unresolved`. An auditor holding the AMEP packet can find the trace for a finding.

## What not to do

- **Don't treat spans as evidence.** A span is the application's own account of what it did. AMEP's minting rule (spec 5.14) caps a receipt reconstructed from telemetry at L1. A receipt signed on the execution path is stronger.
- **Don't put tool arguments into spans to make the join work.** AMEP binds arguments by digest (`args_digest`), so the join needs ids and digests only.

## Next steps

- **Done:** `amep-agents` sets these attributes when OpenTelemetry is present (`packages/agents/src/amep_agents/otel.py`, tested in `tests/test_otel.py`).
- If useful to the GenAI SIG, a proposal for an `evidence` reference on tool spans: a pointer to a signed record of the call, whatever its format.
