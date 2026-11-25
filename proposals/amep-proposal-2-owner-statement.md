# AMEP-Proposal-2: OwnerStatement

| | |
|---|---|
| **Status** | Draft for discussion. Two rules wait on answers from EAGF (section 6). |
| **Targets** | AMEP core v0.3.x, as an opt-in rule |
| **Author** | Staford Titus Selvaraj (editor) |
| **Source** | REQ-6 (accountable owner) of draft-luna-eagf-agent-delegation-semantics-03, by David Luna, with Tania Aizenman (Alygn). The six cases in section 5 were proposed to them first. |
| **Created** | 2026-11-25 |
| **Discussion** | Issues in https://github.com/stafordtituss/amep |

## 1. Summary

**What it adds:** a signed **OwnerStatement**, in which an organization names the role accountable for an agent, for a period.

**Where it applies:** where a mandate asks for accountability, every invocation's actor needs an owner statement in force at the time of the call.
- **No statement:** the result is `unresolved`, with gap `owner`.
- **Ownership ended, with no successor:** the result is to be decided with EAGF (section 6).

**What it changes:** nothing else. An owner is about who answers for an agent; authority is about what it may do. A packet that satisfies every authority rule but names no owner is not `violated`.

## 2. Motivation

AMEP records the acting agent (`actor`), and for high-impact effects it requires an observer other than that actor (I10). It records no one who is *accountable* for the agent.

Auditors ask exactly that question:
- the EU AI Act's deployer obligations;
- ISO/IEC 42001's assignment of responsibilities;
- EAGF's REQ-6.

EAGF states a rule AMEP should keep: accountability **MUST NOT be inferred solely from causality**. The account that deployed or started an agent is not, by that fact alone, the party that answers for it. A self-description by the agent is no better (EAGF REQ-5).

## 3. The object

`kind: "owner"`, signed by a key with role `issuer` for the organization on whose behalf the agent acts.

| Field | Req. | Meaning |
|---|---|---|
| `id`, `kind` | **yes** | |
| `subject` | **yes** | The agent, as invocations name it in `actor`. |
| `owner` | **yes** | The accountable **role**, for example `role:payments-ops-lead`. A role, so that ownership survives a person leaving. |
| `organization` | **yes** | The organization that assigns the role. Where the key set names operators (12.5), it SHOULD equal the signing key's `operator`. |
| `nbf` | **yes** | Start of the ownership. |
| `ended` | no | End of the ownership, signed by the same organization, either in a later statement or in this one when it is reissued. |
| `supersedes` | no | `id` of the statement this one replaces, for a handover between roles. |
| `proof` | **yes** | Signed by a key with role `issuer`. |

## 4. The rule

A mandate opts in with a claim member `accountable: true` *(v0.3.x)*. Delegations under it inherit the member, and none may drop it (I1).

For each invocation whose effective claims carry `accountable: true`:

1. **One owner in force.** Find the owner statements whose `subject` equals the invocation's `actor`, that verify, and whose signing key has role `issuer`. Keep those whose `nbf` ≤ the invocation's `t` and that have no `ended` at or before `t`. If none is left, the result is `unresolved` (I7), gap `owner`.
2. **No self-report.** A statement signed by the invocation's own key, or by a key with role `host` only, is not an owner statement. It is excluded before rule 1, by the same key test as I10.
3. **Ended without a successor:** see section 6, question 1.
4. **Across organizations:** see section 6, question 2.

The owner rule runs after every check that can decide `violated`, so it never hides a violation.

## 5. Cases (proposed vectors)

| Case | Setup | Proposed AMEP result | EAGF outcome |
|---|---|---|---|
| R6-1 | The organization's issuer key signs an owner statement naming a role for the agent, in force at the call. | `preserved` | allowed |
| R6-2 | No owner statement. | `unresolved` (I7), gap `owner` | not evaluated |
| R6-3 | The only link is causal: the owner's account started the agent. Recorded, for example, as a `deployed_by` member on the interpretation. | `unresolved` (I7), gap `owner`. A causal record is not an owner statement. | not evaluated |
| R6-4 | The agent's own output names its owner. Signed by the host key. | `unresolved` (I7), gap `owner`, by rule 2 | not evaluated |
| R6-5 | Ownership was recorded, then ended by the organization before the call. No successor. | Open: `violated` or `unresolved` (section 6, question 1) | proposed: denied |
| R6-6 | Agent A, of organization X, delegates to sub-agent B, operated by organization Y. Only X recorded B's owner. | Open (section 6, question 2) | not evaluated |

## 6. Open questions, put to EAGF on 24 November 2026

1. **A lapsed owner (R6-5).** Is a call after ownership ended, with no successor, *denied* or *not evaluated until a successor is shown*?
   - *For `violated`:* the organization signed that no one answers for the agent anymore.
   - *For `unresolved`:* a successor statement may simply not be in the packet yet.

   AMEP would follow EAGF's answer.
2. **Across organizations (R6-6).** Must B's owner be recorded by Y, the organization on whose behalf B acts, or may X record it?
   - The proposal leans towards Y, with X's delegation as the authority.
   - Read that way, an owner statement signed only by X shows nothing about B.

## 7. What it does not do

- **It doesn't check that the role is staffed,** or that the person in it was reachable. That is the organization's record, outside the evidence.
- **It doesn't settle blame for a violation.** `blame` still names the party that departed from authority. The owner is who answers for the agent, not who broke the rule.

## 8. Next steps

1. Answers to the two questions.
2. Implementation in both reference verifiers, behind `accountable: true`, with the six vectors, credited to EAGF.
3. An EAGF test-case row for each vector, in the format Tania proposed.
