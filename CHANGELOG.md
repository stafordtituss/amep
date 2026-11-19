# Changelog

Specification drafts, conformance-suite versions and package versions are listed together. Package versions follow PEP 440 (Python) and SemVer (npm).

## Unreleased

- **Fix (both reference verifiers):** an agent acting directly under a mandate (no delegation) whose `exp` or `nbf` is an RFC 3339 time. The effect time was compared with the unconverted string. Python returned `unresolved`/I7 for every such packet; JavaScript never detected an effect after expiry or before `nbf`. **Conformance suite v0.2.2** adds 3 vectors for this path (114 vectors: 33 positive, 81 must-reject). Found by the AgentDojo experiment.
- **AgentDojo experiment** (`experiments/agentdojo`): AMEP evidence over all 949 user-task × injection-task pairs of AgentDojo v1.2.2, with mandates of three granularities.
- **Conformance suite v0.2.1** (no normative change): 16 vectors found by mutation analysis of the reference evaluator, covering the action-widening and effect-ceiling rules, `write_shared` as high impact, intent references to non-intent objects, approval `nbf`, verdict precedence within a packet, and the inclusive edge of every time, budget and approval-window bound. 111 vectors (32 positive, 79 must-reject).
- **Mutation analysis tool** (`paper/eval/mutation.py`) with a `--check` mode for CI, and verification benchmarks (`paper/eval/bench.py`, `bench.mjs`).
- **`amep-mcp`**: the verifier as an MCP server (`packages/mcp`), with both conformance suites bundled.
- **`amep-agents`**: evidence recording for the OpenAI Agents SDK (tracing processor) and LangGraph/LangChain (callback handler), with end-to-end tests (`packages/agents`).
- **Delegation-continuity test materials** for the W3C Agent Identity Registry Protocol Community Group (`interop/w3c-agent-identity/delegation-continuity/`): 20 vectors and an offline browser verifier.
- **AMEP-Proposal-1: EvaluationRecord** (`proposals/`).
- `RESEARCH.md`, `CONTRIBUTING.md` and this changelog.

## v0.2.0-draft.4-r2 (2026-11-17)

- Release metadata update for archiving (Zenodo, Software Heritage); no change to the specification or packages.

## v0.2.0-draft.4, packages 0.2.0a5 / 0.2.0-alpha.5 (2026-11-17)

- Data lineage (`accessed`, `recipient`, `derived_from`), which detects data leaving after a read.
- Verifier state across packets (approvals used, budget spent).
- UCAN profile; a second, independent JSON Schema validator; IETF Internet-Draft rendering (draft-stafordtituss-agentic-mandate-evidence-00).
- Conformance suite v0.2.0: 95 vectors (25 positive, 70 must-reject).

## v0.2.0-draft.3

- `phase` on every decision, so detection is never presented as enforcement; `quarantine` decisions; deny lists that only grow along a chain; conformance Levels 0–5 with an "Attested" qualifier; Biscuit, Macaroon, PASETO and Verifiable Credential profiles; CDDL validation.

## v0.2.0-draft.2

- Signer roles; signed revocations and revocation status; `actor` required for high-impact effects; every effect receipt evaluated; approval digests without `t`, with a validity window and single use; findings trusted only when signed; RFC 3339 times; exact RFC 8785 canonicalization; JSON Schemas; AuthZEN, MCP and host bindings.

## v0.2.0-draft.1

- Attenuation enforces `nbf`, `purpose` and the depth rules; cited intents must exist and be signed; I9 applies to the executed resource.

## v0.1

- Initial model: mandates, delegations, invocations and executed-effect receipts; invariants I1–I7.
