# AMEP verdicts as SCITT signed statements

**Context:**
- The SCITT architecture is RFC 9943 (June 2026).
- Agent profiles of it are individual drafts. One example is draft-noa-scitt-ai-agent-receipt-01 (August 2026), "A SCITT Profile for AI-Agent Action Receipts".

**The gap a receipt profile leaves:** an action receipt, as that draft states plainly, records what an agent was recorded as doing.
- It doesn't show that a named approver authorized the action beforehand.
- It doesn't show that the agent was right.
- It leaves policy replay out of scope.

That is AMEP's question: given the signed authority and the signed record of what was done, did the action stay within the authority?

## The shape

| SCITT | AMEP |
|---|---|
| **Signed statement** | An AMEP verdict record (spec 10.8), in a DSSE envelope as an in-toto statement (`interop/in-toto/PREDICATE.md`). It names the evidence packet by SHA-256, lists every result, and may name the admitted artifact as its subject. |
| **Issuer** | The verifier that evaluated the packet: a CI system, an auditor, a payment processor. |
| **Transparency service** | Registers the verdict. Its receipt proves the verdict existed by a given time and can't later be rewritten. |
| **Relying party** | Re-runs the verdict from the packet and the key set, or relies on the registered statement. |

The two layers compose. Action receipts, under a SCITT profile, can be the effect evidence an AMEP packet carries. The AMEP verdict over that packet is a second signed statement, registered beside them, that answers the question the receipts leave open.

## What registration adds to AMEP

- **No quiet re-evaluation.** AMEP-Proposal-1 (EvaluationRecord) asks that a later verdict never replace an earlier one silently. A transparency service makes every verdict, and every superseding one, visible in order.
- **Completeness of verdicts, not of evidence.** Registration shows which verdicts were issued. It doesn't show that the evidence packet was complete; that remains `LIMITS.md`, section A.

## Status

This is a mapping. No AMEP SCITT profile is proposed yet. The in-toto statement form is implemented in both reference verifiers, and they produce byte-identical statements across the conformance suite.
