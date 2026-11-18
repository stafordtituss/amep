# OWASP Top 10 for Agentic Applications (2026) → AMEP evidence

| | |
|---|---|
| **Author** | Staford Titus Selvaraj (independent) |
| **Status** | Draft for discussion with the OWASP GenAI Security Project, Agentic Security Initiative |
| **Date** | 2026-11-18 |
| **Licence** | CC BY-SA 4.0 (to match OWASP GenAI content); referenced vectors are Apache 2.0 |

## What this maps

The OWASP Top 10 for Agentic Applications names the risks. Mitigations reduce them. After an incident, someone still has to answer: **did this agent's executed actions stay within what a person authorized, and if not, where did it break?**

AMEP (Agentic Mandate Evidence Protocol) answers that question with signed evidence and a deterministic verdict: `preserved`, `violated` (naming the broken invariant) or `unresolved` (evidence missing, never treated as permission). This table shows, for each risk:
- what AMEP evidence lets a third party establish after the fact;
- the invariant that decides it;
- the conformance vectors that exercise it;
- what AMEP does **not** do.

AMEP is a detection and accountability layer, not a prevention control. It is complementary to the mitigations in the Top 10.

Vector names refer to `vectors/` (core suite, 111 vectors) and `interop/w3c-agent-identity/delegation-continuity/` (20 vectors) in https://github.com/stafordtituss/amep. Each can be run with `amep-protocol check-suite`, or opened in the offline browser verifier.

## Mapping

| Risk | What AMEP evidence establishes | Invariants | Example vectors | Out of scope |
|---|---|---|---|---|
| **ASI01 Agent Goal Hijack** | Whether a mutating action was influenced by untrusted or quarantined content without the principal confirming it; and, independently of the goal, whether the executed effect stayed within the delegated authority | I4, I2 | `injection-driven-mutation`, `quarantined-content-reached-the-agent--a1`, `unsigned-finding-claims-trusted`; positive: `mutation-influenced-only-by-trusted-content`, `quarantined-content-promoted-by-the-principal` | Detecting the injection itself. AMEP records detectors' findings and evaluates them |
| **ASI02 Tool Misuse** | Whether the executed effect matches what was declared, is within the effective claims (actions, resources, effect class, data flows, validity) and the risk budget, and whether any approval covered exactly that effect | I2, I3, I8 | `declared----executed--path-retarget`, `destructive-command-drift--a3`, `effect-outside-delegated-scope`, `effect-class-above-delegated-ceiling`, `risk-budget-exceeded-without-approval` | Choosing least-privilege scopes in the first place |
| **ASI03 Identity & Privilege Abuse** | Whose authority an agent exercised: every delegation hop signed and narrower than its parent; no upstream revocation at action time; signer roles enforced, so a host key cannot mint a mandate or approve its own action | I1, I6, I7 | `delegation-widens-actions`, `delegation-removes-a-deny`, `identity-only-authorization--no-mandate`, `mandate-minted-by-host-key`, `self-approval-signed-by-host-key`, `revoked-root-with-live-child`; delegation suite: `self-issued-delegation`, `redelegation-without-right` | Issuing identities or credentials (AMEP consumes them, e.g. OAuth or DID-based agent identities) |
| **ASI04 Agentic Supply Chain** *(title to confirm against the official list)* | Whether a tool call was interpreted by an approved, version-pinned adapter, and whether a tool's own receipt (or the receiving system's) contradicts what was requested | I3, I2 | `unapproved-adapter-revision`, `interpretation-from-provider-hint-only`, `lying-adapter-caught-by-backend--l3`; MCP prototype: a server that changes a different record is exposed by its own receipt | Vetting packages, MCP servers or agent cards before use |
| **ASI05 Unexpected Code Execution** | Whether an executed command stayed within the effect-class ceiling and resources; whether it targeted guardrails, keys or the evidence store; whether it ran despite a pre-execution deny | I2, I9, I11 | `destructive-command-drift--a3`, `guardrail-write--i9`, `guardrail-write-via-absolute-path--i9`, `deny-contradicted-by-executed-effect` | Sandboxing or containment |
| **ASI06 Memory & Context Poisoning** | Which signed content findings influenced an action, with their integrity labels; whether untrusted content shaped a mutation; data carried in through lineage | I4, I5 | `injection-driven-mutation`, `unsigned-finding-claims-trusted`, `data-leaving-after-a-read--a5` | Inspecting or cleaning memory stores |
| **ASI07 Insecure Inter-Agent Communication** | Whether each object exchanged between agents is signed by a key with the right role and unmodified; whether a delegate's authority traces back to a principal | I7, I1 | `tampered-effect-receipt`, `invocation-signed-by-unknown-key`, `unsigned-intent`, `forged-mandate--attacker-key`; delegation suite: `identity-only`, `self-issued-delegation` | Transport security and agent discovery protocols |
| **ASI08 Cascading Failures** | Where in a chain authority was lost: a revoked root invalidates every live child; budgets accumulate across packets; the failing hop is named | I6, I2, I1 | `revoked-root-with-live-child`, `budget-spent-in-earlier-packets`, `cumulative-spend-exceeds-budget`, `delegation-outlives-parent` (delegation suite) | Workflow-level composition across many invocations (planned for v0.3) |
| **ASI09 Human-Agent Trust Exploitation** | Whether a human approval was bound to the digest of exactly the executed effect, within its window, and used once, so an approval obtained for one thing cannot authorize another | I8, I10 | `approval-digest-mismatch--toctou`, `approval-reused-for-a-second-invocation`, `approval-reused-across-packets`, `stale-approval--expired`; delegation suite: `approval-for-a-different-effect`, `approval-replayed` | The user-interface design of approval prompts |
| **ASI10 Rogue Agents** | Effects with no authorized invocation; effects reported only by the acting agent; attempts to edit guardrails or the evidence store | I11, I10, I9 | `audit-only-discovery-of-an-unknown-agent--a6`, `bypass--effect-without-invocation`, `self-reported-high-impact-effect`, `guardrail-write--i9` | Detecting drift in an agent's behaviour before it acts |

## Proposed contribution

1. **A short "Verifiable evidence" note** for the Top 10 or its companion guides: for each risk, the questions an auditor should be able to answer after an incident, and the evidence that answers them. This table is a first draft, written to be vendor-neutral, with AMEP as one worked example.
2. **For the Agent Control Standard:** use signed, independently checkable evidence as the way to demonstrate that a control operated. A control that says "the agent may not exceed scope X" becomes testable: a third party evaluates the evidence and gets `preserved`, `violated` or `unresolved`.
3. **Test material:** the conformance vectors are available as public, runnable examples for each risk.

Corrections welcome, especially where a risk is mapped too broadly or a vector does not fit.
