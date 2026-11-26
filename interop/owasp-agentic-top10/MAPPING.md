# OWASP Top 10 for Agentic Applications (2026) → AMEP evidence

| | |
|---|---|
| **Author** | Staford Titus Selvaraj (independent) |
| **Status** | Draft for discussion with the OWASP GenAI Security Project, Agentic Security Initiative |
| **Date** | 2026-11-18, revised 2026-11-22 for AMEP v0.3 (blame, evidence gaps, signed verdicts) |
| **Licence** | CC BY-SA 4.0 (to match OWASP GenAI content); referenced vectors are Apache 2.0 |

## What this maps

The OWASP Top 10 for Agentic Applications names the risks. Mitigations reduce them. After an incident, someone still has to answer: **did this agent's executed actions stay within what a person authorized, and if not, where did it break?**

AMEP (Agentic Mandate Evidence Protocol) answers that question with signed evidence and a deterministic verdict: `preserved`, `violated` (naming the broken invariant) or `unresolved` (evidence missing, never treated as permission). Since v0.3, a `violated` result also names **where it broke**: `blame` is the party whose own signed record first departs from authority (`agent`, `delegator`, `host`, `transport` or `server`). An `unresolved` result names the **missing evidence** (`gaps`). This table shows, for each risk:
- what AMEP evidence lets a third party establish after the fact;
- the invariant that decides it;
- the conformance vectors that exercise it;
- who is blamed when it is violated, or what evidence is missing when nothing can be decided;
- what AMEP does **not** do.

AMEP is a detection and accountability layer, not a prevention control. It is complementary to the mitigations in the Top 10.

Vector names refer to three suites in https://github.com/stafordtituss/amep: `vectors/` (core, 233 vectors), `interop/approval-path-attacks/` (16) and `interop/w3c-agent-identity/delegation-continuity/` (20). Each can be run with `amep-protocol check-suite`, opened in the offline browser verifier, or run against any verifier with `amep-conformance verify`. The [results table](#results-of-the-cited-vectors) below is generated from the reference verifier.

## Mapping

| Risk | What AMEP evidence establishes | Invariants | Example vectors | Who is blamed, or what is missing | Out of scope |
|---|---|---|---|---|---|
| **ASI01 Agent Goal Hijack** | Whether a mutating action was influenced by untrusted or quarantined content without the principal confirming it; and, independently of the goal, whether the executed effect stayed within the delegated authority | I4, I2 | `injection-driven-mutation`, `quarantined-content-reached-the-agent--a1`, `unsigned-finding-claims-trusted`; positive: `mutation-influenced-only-by-trusted-content`, `quarantined-content-promoted-by-the-principal` | `agent` when it acted on untrusted influence; `host` when the host passed quarantined content on | Detecting the injection itself. AMEP records detectors' findings and evaluates them |
| **ASI02 Tool Misuse & Exploitation** | Whether the executed effect matches what was declared, is within the effective claims (actions, resources, effect class, data flows, validity) and the risk budget, and whether any approval covered exactly that effect | I2, I3, I8 | `declared----executed--path-retarget`, `destructive-command-drift--a3`, `effect-outside-delegated-scope`, `effect-class-above-delegated-ceiling`, `risk-budget-exceeded-without-approval`, `payment-over-the-per-call-limit-without-approval`, `payments-through-two-services-against-one-cap`; approval-path suite: `decoy-recipient-executed`, `payment-split-under-threshold` | `agent` for effects outside its claims or limits; `server` when what executed differs from what was declared (including a decoy recipient) | Choosing least-privilege scopes in the first place |
| **ASI03 Identity & Privilege Abuse** | Whose authority an agent exercised: every delegation hop signed and narrower than its parent; no upstream revocation at action time; signer roles enforced, so a host key cannot mint a mandate or approve its own action | I1, I6, I7 | `delegation-widens-actions`, `delegation-removes-a-deny`, `identity-only-authorization--no-mandate`, `mandate-minted-by-host-key`, `self-approval-signed-by-host-key`, `revoked-root-with-live-child`; delegation suite: `self-issued-delegation`, `redelegation-without-right` | `delegator` for a widening delegation; `agent` for acting after revocation. Forged or wrong-role signatures are `unresolved` with gap `signature`, `approval` or `root_mandate`: the evidence cannot attribute a forgery to a party | Issuing identities or credentials (AMEP consumes them, e.g. OAuth or DID-based agent identities) |
| **ASI04 Agentic Supply Chain Vulnerabilities** | Whether a tool call was interpreted by an approved, version-pinned adapter, and whether a tool's own receipt (or the receiving system's) contradicts what was requested | I3, I2 | `unapproved-adapter-revision`, `interpretation-from-provider-hint-only`, `lying-adapter-caught-by-backend--l3`; MCP prototype: a server that changes a different record is exposed by its own receipt | `server` when an adapter's or backend's own receipt contradicts the request; an unapproved or unpinned adapter is `unresolved` (gap `interpretation_pin` or `interpretation`) | Vetting packages, MCP servers or agent cards before use |
| **ASI05 Unexpected Code Execution (RCE)** | Whether an executed command stayed within the effect-class ceiling and resources; whether it targeted guardrails, keys or the evidence store; whether it ran despite a pre-execution deny | I2, I9, I11 | `destructive-command-drift--a3`, `guardrail-write--i9`, `guardrail-write-via-absolute-path--i9`, `deny-contradicted-by-executed-effect` | `agent` for targeting guardrails; `server` for a command that drifted; `host` for executing despite its own deny | Sandboxing or containment |
| **ASI06 Memory & Context Poisoning** | Which signed content findings influenced an action, with their integrity labels; whether untrusted content shaped a mutation; data carried in through lineage | I4, I5 | `injection-driven-mutation`, `unsigned-finding-claims-trusted`, `data-leaving-after-a-read--a5` | `agent` | Inspecting or cleaning memory stores |
| **ASI07 Insecure Inter-Agent Communication** | Whether each object exchanged between agents is signed by a key with the right role and unmodified; whether a delegate's authority traces back to a principal | I7, I1 | `tampered-effect-receipt`, `invocation-signed-by-unknown-key`, `unsigned-intent`, `forged-mandate--attacker-key`, `arguments-rewritten-in-transit`; delegation suite: `identity-only`, `self-issued-delegation` | `transport` when the arguments the server received differ from those the host signed; tampered or unsigned objects are `unresolved` (gap `signature` or `receipt_signature`), and an identity with no mandate behind it is `unresolved` (gap `root_mandate`) | Transport security and agent discovery protocols |
| **ASI08 Cascading Failures** | Where in a chain authority was lost: a revoked root invalidates every live child; budgets accumulate across packets; the failing hop is named | I6, I2, I1 | `revoked-root-with-live-child`, `budget-spent-in-earlier-packets`, `cumulative-spend-exceeds-budget`, `revoked-mid-action--after-the-propagation-window`, `revoked-mid-action--inside-the-declared-propagation-window`; delegation suite: `delegation-outlives-parent` | `delegator` for a child that outlives its parent; `agent` for acting after revocation or over a budget; an effect still inside the grant's declared propagation window is `preserved`, with the revocation named in the reason (spec 5.12.1, v0.3.3) | Workflow-level composition across many invocations (planned after v0.3) |
| **ASI09 Human-Agent Trust Exploitation** | Whether a human approval was bound to the digest of exactly the executed effect (or, for an operation approval, to exactly the listed effects of one call), within its window, and used once, so an approval obtained for one thing cannot authorize another, and a retried operation cannot spend it again | I8, I10 | `approval-digest-mismatch--toctou`, `approval-reused-for-a-second-invocation`, `approval-reused-across-packets`, `stale-approval--expired`, `one-approval--the-approved-payment-executed-twice-in-one-call`, `operation-approval-spent-again-by-a-retried-invocation`, `effect-outside-the-operation-approval`; delegation suite: `approval-for-a-different-effect`, `approval-replayed` | `agent` for approval misuse: wrong effect, reuse, expiry, one approval used for two payments, or an operation approval spent by a retry | The user-interface design of approval prompts |
| **ASI10 Rogue Agents** | Effects with no authorized invocation; effects reported only by the acting agent; attempts to edit guardrails or the evidence store | I11, I10, I9 | `audit-only-discovery-of-an-unknown-agent--a6`, `bypass--effect-without-invocation`, `self-reported-high-impact-effect`, `guardrail-write--i9` | `host` for bypasses and unknown agents; `agent` for guardrail writes; a high-impact effect reported only by the actor is `unresolved` (gap `independent_observer`) | Detecting drift in an agent's behaviour before it acts |

## Proposed contribution

1. **A short "Verifiable evidence" note** for the Top 10 or its companion guides: for each risk, the questions an auditor should be able to answer after an incident, and the evidence that answers them. This table is a first draft, written to be vendor-neutral, with AMEP as one worked example.
2. **For the Agent Control Standard:** use signed, independently checkable evidence as the way to demonstrate that a control operated. A control that says "the agent may not exceed scope X" becomes testable: a third party evaluates the evidence and gets `preserved`, `violated` or `unresolved`.
3. **Test material:** the conformance vectors are available as public, runnable examples for each risk.
4. **Portable findings:** a verifier's conclusion can be published as a signed in-toto attestation (an AMEP verdict, or a Simple Verification Result for existing policy engines), so a finding about an incident can be checked by anyone who holds the evidence.

Corrections welcome, especially where a risk is mapped too broadly, a vector does not fit, or the blamed party looks wrong.

## Results of the cited vectors

What the reference verifier returns for every vector cited above, regenerated with `python3 interop/owasp-agentic-top10/results.py` (the `--check` flag fails if the table is out of date).

<!-- results: generated by results.py -->
| First cited in | Vector | Suite | Outcome | Invariant | Blame (violated) or gap (unresolved) |
|---|---|---|---|---|---|
| ASI01 | `injection-driven-mutation` | core | violated | I4 | agent |
| ASI01 | `quarantined-content-reached-the-agent--a1` | core | violated | I4 | host |
| ASI01 | `unsigned-finding-claims-trusted` | core | violated | I4 | agent |
| ASI01 | `mutation-influenced-only-by-trusted-content` | core | preserved | - |  |
| ASI01 | `quarantined-content-promoted-by-the-principal` | core | preserved | - |  |
| ASI02 | `declared----executed--path-retarget` | core | violated | I2 | server |
| ASI02 | `destructive-command-drift--a3` | core | violated | I2 | server |
| ASI02 | `effect-outside-delegated-scope` | core | violated | I2 | agent |
| ASI02 | `effect-outside-delegated-scope` | delegation | violated | I2 | agent |
| ASI02 | `effect-class-above-delegated-ceiling` | core | violated | I2 | agent |
| ASI02 | `risk-budget-exceeded-without-approval` | core | violated | I2 | agent |
| ASI02 | `payment-over-the-per-call-limit-without-approval` | core | violated | I2 | agent |
| ASI02 | `payments-through-two-services-against-one-cap` | core | violated | I2 | agent |
| ASI02 | `decoy-recipient-executed` | approval-path | violated | I2 | server |
| ASI02 | `payment-split-under-threshold` | approval-path | violated | I2 | agent |
| ASI03 | `delegation-widens-actions` | core | violated | I1 | delegator |
| ASI03 | `delegation-removes-a-deny` | core | violated | I1 | delegator |
| ASI03 | `identity-only-authorization--no-mandate` | core | unresolved | I7 | root_mandate |
| ASI03 | `mandate-minted-by-host-key` | core | unresolved | I7 | signature |
| ASI03 | `self-approval-signed-by-host-key` | core | unresolved | I7 | approval |
| ASI03 | `revoked-root-with-live-child` | core | violated | I6 | agent |
| ASI03 | `self-issued-delegation` | delegation | unresolved | I7 | signature |
| ASI03 | `redelegation-without-right` | delegation | violated | I1 | delegator |
| ASI04 | `unapproved-adapter-revision` | core | unresolved | I3 | interpretation_pin |
| ASI04 | `interpretation-from-provider-hint-only` | core | unresolved | I3 | interpretation |
| ASI04 | `lying-adapter-caught-by-backend--l3` | core | violated | I2 | server |
| ASI05 | `guardrail-write--i9` | core | violated | I9 | agent |
| ASI05 | `guardrail-write-via-absolute-path--i9` | core | violated | I9 | agent |
| ASI05 | `deny-contradicted-by-executed-effect` | core | violated | I11 | host |
| ASI06 | `data-leaving-after-a-read--a5` | core | violated | I5 | agent |
| ASI07 | `tampered-effect-receipt` | core | unresolved | I7 | receipt_signature |
| ASI07 | `invocation-signed-by-unknown-key` | core | unresolved | I7 | signature |
| ASI07 | `unsigned-intent` | core | unresolved | I7 | signature |
| ASI07 | `forged-mandate--attacker-key` | core | unresolved | I7 | signature |
| ASI07 | `arguments-rewritten-in-transit` | core | violated | I2 | transport |
| ASI07 | `identity-only` | delegation | unresolved | I7 | root_mandate |
| ASI08 | `budget-spent-in-earlier-packets` | core | violated | I2 | agent |
| ASI08 | `cumulative-spend-exceeds-budget` | core | violated | I2 | agent |
| ASI08 | `revoked-mid-action--after-the-propagation-window` | core | violated | I6 | agent |
| ASI08 | `revoked-mid-action--inside-the-declared-propagation-window` | core | preserved | - |  |
| ASI08 | `delegation-outlives-parent` | delegation | violated | I1 | delegator |
| ASI09 | `approval-digest-mismatch--toctou` | core | violated | I8 | agent |
| ASI09 | `approval-reused-for-a-second-invocation` | core | violated | I8 | agent |
| ASI09 | `approval-reused-across-packets` | core | violated | I8 | agent |
| ASI09 | `stale-approval--expired` | core | violated | I8 | agent |
| ASI09 | `one-approval--the-approved-payment-executed-twice-in-one-call` | core | violated | I8 | agent |
| ASI09 | `operation-approval-spent-again-by-a-retried-invocation` | core | violated | I8 | agent |
| ASI09 | `effect-outside-the-operation-approval` | core | violated | I8 | agent |
| ASI09 | `approval-for-a-different-effect` | delegation | violated | I8 | agent |
| ASI09 | `approval-replayed` | delegation | violated | I8 | agent |
| ASI10 | `audit-only-discovery-of-an-unknown-agent--a6` | core | unresolved | I11 | invocation |
| ASI10 | `bypass--effect-without-invocation` | core | unresolved | I11 | invocation |
| ASI10 | `self-reported-high-impact-effect` | core | unresolved | I10 | independent_observer |
<!-- end of results -->
