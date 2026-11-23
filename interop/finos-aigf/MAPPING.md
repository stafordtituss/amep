# FINOS AI Governance Framework (agentic risks and mitigations) → AMEP evidence

| | |
|---|---|
| **Author** | Staford Titus Selvaraj (independent) |
| **Status** | Draft for discussion with the FINOS AI Governance Framework (AIGF) project |
| **Date** | 2026-11-22, against AIGF v3 (October 26, 2026) and AMEP v0.3 |
| **Licence** | CC BY 4.0 (to match AIGF content); referenced vectors are Apache 2.0 |

## What this maps

The [FINOS AI Governance Framework](https://air-governance-framework.finos.org/) catalogues agentic risks (RI-24 to RI-30, added in v2.0) and the mitigations that address them. Most of those mitigations are preventive: least privilege, validation, MCP server governance, approval gates. After an incident, or for an audit, a financial institution still has to show that a control actually held for a given action: **did this agent's executed actions stay within what a person authorized, and if not, where did it break?**

AMEP (Agentic Mandate Evidence Protocol) answers that question with signed evidence and a deterministic verdict:
- `preserved`;
- `violated`, naming the broken invariant and the party whose own signed record first departs from authority (`blame`: `agent`, `delegator`, `host`, `transport` or `server`);
- `unresolved`, naming the missing evidence (`gaps`). Missing evidence is never treated as permission.

For each AIGF risk and mitigation, this table shows:
- what AMEP evidence lets a third party establish after the fact;
- the invariant that decides it;
- the conformance vectors that exercise it;
- who is blamed when it is violated, or what evidence is missing when nothing can be decided;
- what AMEP does **not** do.

AMEP is a detection and accountability layer, not a prevention control. For the mitigations, it gives the evidence that a control operated; it does not replace the control.

Vector names refer to three suites in https://github.com/stafordtituss/amep: `vectors/` (core), `interop/approval-path-attacks/` and `interop/w3c-agent-identity/delegation-continuity/`. Each can be run with `amep-protocol check-suite`, opened in the offline browser verifier, or run against any verifier with `amep-conformance verify`. The [results table](#results-of-the-cited-vectors) below is generated from the reference verifier.

## Risks

| AIGF risk | What AMEP evidence establishes | Invariants | Example vectors | Who is blamed, or what is missing | Out of scope |
|---|---|---|---|---|---|
| **RI-24 [Agent Action Authorization Bypass](https://air-governance-framework.finos.org/risks/ri-24_agent-action-authorization-bypass.html)** | Whether each executed effect was within the delegated claims (actions, resources, effect class, limits, validity) and the risk budget; whether each delegation hop only narrowed its parent. Whether an approval covered exactly that effect is under MI-24 | I1, I2 | `effect-outside-delegated-scope`, `payment-over-the-per-call-limit-without-approval`, `payments-through-two-services-against-one-cap`, `risk-budget-exceeded-without-approval`, `delegation-widens-actions`, `delegation-removes-a-deny`; approval-path suite: `payment-split-under-threshold` | `agent` for effects outside its claims or limits; `delegator` for a delegation wider than its parent | Choosing least-privilege scopes in the first place |
| **RI-25 [Tool Chain Manipulation and Injection](https://air-governance-framework.finos.org/risks/ri-25_tool-chain-manipulation-and-injection.html)** | Whether a mutating call was influenced by untrusted or quarantined content without the principal confirming it; whether what executed matches what was declared; whether arguments were changed between host and server | I4, I2 | `injection-driven-mutation`, `quarantined-content-reached-the-agent--a1`, `declared----executed--path-retarget`, `arguments-rewritten-in-transit`; positive: `quarantined-content-promoted-by-the-principal` | `agent` for acting on untrusted influence; `host` for passing quarantined content on; `server` when the executed effect differs from the declared one; `transport` when the arguments received differ from those signed | Detecting the injection itself. AMEP records detectors' findings and evaluates them |
| **RI-26 [MCP Server Supply Chain Compromise](https://air-governance-framework.finos.org/risks/ri-26_mcp-server-supply-chain-compromise.html)** | Whether a tool call was interpreted by an approved, version-pinned adapter; whether a server's or backend's own receipt contradicts the request | I3, I2 | `unapproved-adapter-revision`, `interpretation-from-provider-hint-only`, `lying-adapter-caught-by-backend--l3`; approval-path suite: `decoy-recipient-executed` | `server` when its own receipt, or the backend's, contradicts the request; an unapproved or unpinned adapter is `unresolved` (gap `interpretation_pin` or `interpretation`) | Vetting, allowlisting or isolating MCP servers before use |
| **RI-27 [Agent State Persistence Poisoning](https://air-governance-framework.finos.org/risks/ri-27_agent-state-persistence-poisoning.html)** | Partial: which signed content findings influenced an action, with their integrity labels; whether untrusted content shaped a mutation; data carried out through lineage | I4, I5 | `unsigned-finding-claims-trusted`, `data-leaving-after-a-read--a5` | `agent` | Inspecting or cleaning memory and state stores |
| **RI-28 [Multi-Agent Trust Boundary Violations](https://air-governance-framework.finos.org/risks/ri-28_multi-agent-trust-boundary-violations.html)** | Whether every hop between agents is signed by a key with the right role and narrower than its parent; where in a chain authority was lost; whether revoking a root invalidates every live child | I1, I6, I7 | `revoked-root-with-live-child`, `tampered-effect-receipt`; delegation suite: `redelegation-without-right`, `delegation-outlives-parent`, `self-issued-delegation`, `identity-only` | `delegator` for a widening or outliving delegation; `agent` for acting after revocation. Self-issued or identity-only authority is `unresolved` (gap `signature` or `root_mandate`), and so is a receipt modified in transit (gap `receipt_signature`) | Runtime isolation and segmentation of agents |
| **RI-29 [Agent-Mediated Credential Discovery and Harvesting](https://air-governance-framework.finos.org/risks/ri-29_agent-mediated-credential-discovery-and-harvesting.html)** | Limited: whether an executed command targeted guardrails, keys or the evidence store | I9 | `guardrail-write--i9`, `guardrail-write-via-absolute-path--i9` | `agent` | Keeping credentials out of agent environments; detecting exfiltration |

RI-30 (Skill/Plugin Supply Chain Compromise) is not mapped yet. The adapter-pinning evidence under RI-26 is the nearest AMEP coverage.

## Mitigations: evidence that the control operated

| AIGF mitigation | What AMEP evidence establishes | Invariants | Example vectors | Who is blamed, or what is missing | Out of scope |
|---|---|---|---|---|---|
| **MI-18 [Agent Authority Least Privilege Framework](https://air-governance-framework.finos.org/mitigations/mi-18_agent-authority-least-privilege-framework.html)** | That the least-privilege grant held at execution time: claims, effect-class ceiling, time bounds, cumulative budgets across calls, and revocation (for delegations narrowing their parent, see RI-24 and RI-28) | I2, I6 | `effect-class-above-delegated-ceiling`, `cumulative-spend-exceeds-budget`, `budget-spent-in-earlier-packets`, `revoked-mid-action--after-the-propagation-window`, `revoked-mid-action--inside-the-declared-propagation-window` | `agent`; a revocation still inside its declared propagation window is `unresolved` (gap `revocation_settled`) | Designing the privilege matrix |
| **MI-19 [Tool Chain Validation and Sanitization](https://air-governance-framework.finos.org/mitigations/mi-19_tool-chain-validation-and-sanitization.html)** | That the call which passed validation is the call that ran: declared and executed effects match, and a pre-execution deny was not contradicted by an executed effect | I2, I11 | `destructive-command-drift--a3`, `declared----executed--path-retarget`, `deny-contradicted-by-executed-effect` | `server` for drift between declared and executed; `host` for executing despite its own deny | Sanitizing inputs |
| **MI-20 [MCP Server Security Governance](https://air-governance-framework.finos.org/mitigations/mi-20_mcp-server-security-governance.html)** | For the proxy-based model: the gateway signs each invocation and the MCP server returns a signed effect receipt, which the gateway verifies (see `prototypes/mcp-amep-evidence`). A server that changes a different record is exposed by its own receipt; a tampered receipt is rejected | I2, I3, I7 | `lying-adapter-caught-by-backend--l3`, `unapproved-adapter-revision`, `tampered-effect-receipt`, `invocation-signed-by-unknown-key` | `server`; an unapproved adapter is `unresolved` (gap `interpretation_pin`); tampered or unknown-key objects are `unresolved` (gap `receipt_signature` or `signature`) | TLS, mutual authentication, server allowlisting |
| **MI-21 [Agent Decision Audit and Explainability](https://air-governance-framework.finos.org/mitigations/mi-21_agent-decision-audit-and-explainability.html)** | A tamper-evident audit record that a third party can evaluate offline to a deterministic verdict; high-impact effects reported only by the acting agent are flagged; verdicts can be published as signed in-toto attestations (`interop/in-toto`) | I7, I10, I11 | `tampered-effect-receipt`, `self-reported-high-impact-effect`, `bypass--effect-without-invocation`, `audit-only-discovery-of-an-unknown-agent--a6` | `host` for effects with no authorized invocation; a self-reported high-impact effect is `unresolved` (gap `independent_observer`) | Capturing or explaining the agent's reasoning |
| **MI-22 [Multi-Agent Isolation and Segmentation](https://air-governance-framework.finos.org/mitigations/mi-22_multi-agent-isolation-and-segmentation.html)** | That objects crossing a trust boundary were signed by the right role and unmodified, and that a delegate's authority traces back to a principal | I1, I7 | `forged-mandate--attacker-key`, `mandate-minted-by-host-key`, `unsigned-intent`; delegation suite: `redelegation-without-right` | `delegator`; forged or wrong-role signatures are `unresolved` (gap `signature`): the evidence cannot attribute a forgery to a party | Isolating runtimes, state and credentials |
| **MI-24 [Human-in-the-Loop Action Approval Gate](https://air-governance-framework.finos.org/mitigations/mi-24_human-in-the-loop-action-approval-gate.html)** | That a human approval was bound to the digest of exactly the executed effect (or, for an operation approval, to exactly the listed effects of one call), within its window, and used once, so a retried or replayed call cannot spend it again; and that the approval was not signed by the host itself | I8, I7 | `approval-digest-mismatch--toctou`, `approval-reused-for-a-second-invocation`, `approval-reused-across-packets`, `stale-approval--expired`, `one-approval--the-approved-payment-executed-twice-in-one-call`, `operation-approval-spent-again-by-a-retried-invocation`, `effect-outside-the-operation-approval`, `self-approval-signed-by-host-key`; delegation suite: `approval-replayed` | `agent` for approval misuse; a host-signed approval is `unresolved` (gap `approval`) | The user-interface design of approval prompts; approval fatigue |

MI-23 (Agentic System Credential Protection Framework) is not mapped: AMEP does not protect credentials. The nearest evidence it gives is I9, an executed command that targets keys or guardrails, listed under RI-29.

## Proposed contribution to the AIGF

1. **An "evidence that the control operated" note** for MI-18 to MI-24: for each mitigation, the questions an auditor or counterparty should be able to answer after an incident, and the evidence that answers them. Vendor-neutral, with AMEP as one worked example.
2. **Test material:** the conformance vectors are public, runnable regression cases for implementations of RI-24 to RI-28 controls. Each is a small signed packet with an expected verdict; the two reference verifiers (Python and JavaScript, written separately by the same author) agree on every one.
3. **Portable findings:** a verifier's conclusion about an incident can be published as a signed in-toto attestation, so the finding can be checked by anyone who holds the evidence.

Corrections welcome, especially where a risk is mapped too broadly, a vector does not fit, or the blamed party looks wrong.

## Worked example: the family office of #421

[`case-421-family-office/`](case-421-family-office/) puts the cross-institution example of [finos/ai-governance-framework#421](https://github.com/finos/ai-governance-framework/issues/421) into nine signed packets. A client's 10M mandate is split across two banks, and the phases run from a plan within the mandate to a confirm, reconcile and resolve lifecycle after a lost response, including when evidence arrives in batches. Each phase has the verdict both reference verifiers compute, mapped to RI-24, RI-28, MI-18, MI-22 and MI-24.

## Results of the cited vectors

What the reference verifier returns for every vector cited above, regenerated with `python3 interop/finos-aigf/results.py` (the `--check` flag fails if the table is out of date).

<!-- results: generated by results.py -->
| First cited in | Vector | Suite | Outcome | Invariant | Blame (violated) or gap (unresolved) |
|---|---|---|---|---|---|
| RI-24 | `effect-outside-delegated-scope` | core | violated | I2 | agent |
| RI-24 | `effect-outside-delegated-scope` | delegation | violated | I2 | agent |
| RI-24 | `payment-over-the-per-call-limit-without-approval` | core | violated | I2 | agent |
| RI-24 | `payments-through-two-services-against-one-cap` | core | violated | I2 | agent |
| RI-24 | `risk-budget-exceeded-without-approval` | core | violated | I2 | agent |
| RI-24 | `delegation-widens-actions` | core | violated | I1 | delegator |
| RI-24 | `delegation-removes-a-deny` | core | violated | I1 | delegator |
| RI-24 | `payment-split-under-threshold` | approval-path | violated | I2 | agent |
| RI-25 | `injection-driven-mutation` | core | violated | I4 | agent |
| RI-25 | `quarantined-content-reached-the-agent--a1` | core | violated | I4 | host |
| RI-25 | `declared----executed--path-retarget` | core | violated | I2 | server |
| RI-25 | `arguments-rewritten-in-transit` | core | violated | I2 | transport |
| RI-25 | `quarantined-content-promoted-by-the-principal` | core | preserved | - |  |
| RI-26 | `unapproved-adapter-revision` | core | unresolved | I3 | interpretation_pin |
| RI-26 | `interpretation-from-provider-hint-only` | core | unresolved | I3 | interpretation |
| RI-26 | `lying-adapter-caught-by-backend--l3` | core | violated | I2 | server |
| RI-26 | `decoy-recipient-executed` | approval-path | violated | I2 | server |
| RI-27 | `unsigned-finding-claims-trusted` | core | violated | I4 | agent |
| RI-27 | `data-leaving-after-a-read--a5` | core | violated | I5 | agent |
| RI-28 | `revoked-root-with-live-child` | core | violated | I6 | agent |
| RI-28 | `tampered-effect-receipt` | core | unresolved | I7 | receipt_signature |
| RI-28 | `redelegation-without-right` | delegation | violated | I1 | delegator |
| RI-28 | `delegation-outlives-parent` | delegation | violated | I1 | delegator |
| RI-28 | `self-issued-delegation` | delegation | unresolved | I7 | signature |
| RI-28 | `identity-only` | delegation | unresolved | I7 | root_mandate |
| RI-29 | `guardrail-write--i9` | core | violated | I9 | agent |
| RI-29 | `guardrail-write-via-absolute-path--i9` | core | violated | I9 | agent |
| MI-18 | `effect-class-above-delegated-ceiling` | core | violated | I2 | agent |
| MI-18 | `cumulative-spend-exceeds-budget` | core | violated | I2 | agent |
| MI-18 | `budget-spent-in-earlier-packets` | core | violated | I2 | agent |
| MI-18 | `revoked-mid-action--after-the-propagation-window` | core | violated | I6 | agent |
| MI-18 | `revoked-mid-action--inside-the-declared-propagation-window` | core | unresolved | I6 | revocation_settled |
| MI-19 | `destructive-command-drift--a3` | core | violated | I2 | server |
| MI-19 | `deny-contradicted-by-executed-effect` | core | violated | I11 | host |
| MI-20 | `invocation-signed-by-unknown-key` | core | unresolved | I7 | signature |
| MI-21 | `self-reported-high-impact-effect` | core | unresolved | I10 | independent_observer |
| MI-21 | `bypass--effect-without-invocation` | core | violated | I11 | host |
| MI-21 | `audit-only-discovery-of-an-unknown-agent--a6` | core | violated | I11 | host |
| MI-22 | `forged-mandate--attacker-key` | core | unresolved | I7 | signature |
| MI-22 | `mandate-minted-by-host-key` | core | unresolved | I7 | signature |
| MI-22 | `unsigned-intent` | core | unresolved | I7 | signature |
| MI-24 | `approval-digest-mismatch--toctou` | core | violated | I8 | agent |
| MI-24 | `approval-reused-for-a-second-invocation` | core | violated | I8 | agent |
| MI-24 | `approval-reused-across-packets` | core | violated | I8 | agent |
| MI-24 | `stale-approval--expired` | core | violated | I8 | agent |
| MI-24 | `one-approval--the-approved-payment-executed-twice-in-one-call` | core | violated | I8 | agent |
| MI-24 | `operation-approval-spent-again-by-a-retried-invocation` | core | violated | I8 | agent |
| MI-24 | `effect-outside-the-operation-approval` | core | violated | I8 | agent |
| MI-24 | `self-approval-signed-by-host-key` | core | unresolved | I7 | approval |
| MI-24 | `approval-replayed` | delegation | violated | I8 | agent |
<!-- end of results -->
