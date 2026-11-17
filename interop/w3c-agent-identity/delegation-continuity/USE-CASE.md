# Use case: preserving principal authority across agent delegation

*Staford Titus Selvaraj. For discussion in the W3C Agent Identity Registry Protocol CG, 2026-11-17.*

## 1. The problem

An agent's identity and the authority it exercises are different things. In the hiring use case, the hiring agent A acts for the HR lead H. Suppose A hands interview scheduling to a scheduling agent B, which writes to the company calendar T.

B can have a perfectly valid ARIA identity, and T's API can accept the call, and the action can still be one that nobody authorized. Identity answers *who B is*. It doesn't answer:

1. whose authority B is exercising;
2. which of H's constraints survived the hand-off from A to B;
3. whether A was allowed to delegate at all;
4. whether the effective scope grew along the chain;
5. whether anything upstream had been revoked when B acted.

A receiver needs answers to the first four before it acts. An auditor needs all five afterwards, from evidence that neither agent can rewrite.

## 2. What the evidence looks like

Each step is a separately signed object:

| Object | Signed by | In the scenario |
|---|---|---|
| Mandate | the principal's issuer | H to A: read candidates, write interview slots, message candidates; never touch executive calendars; valid until t=100; may be delegated twice |
| Delegation | the delegator's issuer | A to B: write interview slots for requisition 1042 only; same deny; until t=90; no further delegation |
| Invocation | the host running B | B declares it will write `calendar:interview/req-1042/slot-3` |
| Executed effect | T, the tool | T signs what it actually changed |
| Revocation, status, approval | issuer, approver | when present |

A verifier first checks every signature and signer role. It then checks that each delegation is within its parent. Finally, it checks that the executed effect was within the meet (intersection) of the whole chain at the time it happened.

## 3. Mapping to ARIA

| ARIA | These materials |
|---|---|
| Scope `namespace:resource:action` (§6), for example `calendar:interview:write` | Claim: action `calendar.write`, resources `calendar:interview/...`. Resources can be narrowed below ARIA's three segments (here, to one requisition). |
| A scope declares intent and grants nothing by itself (§6) | The outcome is decided by the executed effect T signs, not by B's declared scope (`executed-differs-from-declared`). |
| A matching deny overrides an allow | `deny_resources`. A delegate may add a deny but never drop one (`deny-added-by-delegate`, `delegation-drops-a-deny`). |
| `delegationDepth`, `maxDelegationDepth` (§4, §6) | `depth` must strictly decrease, and a zero-depth holder cannot delegate (`depth-not-decreasing`, `redelegation-without-right`). |
| Every hop signed; principal traceable (§6) | Each delegation is signed by a key holding the issuer role and points at its parent, back to the mandate naming H (`self-issued-delegation`, `identity-only`). |
| Revocation via Bitstring Status List; revocation is terminal (§7) | Signed revocations and status, evaluated at the time of the action (`root-revoked-before-action`, `status-shows-revoked`, `revoked-after-the-action`). |
| `hitlRequired` (§6) | An approval is bound to a digest of the exact effect and is single use (`approval-bound-to-effect`, `approval-for-a-different-effect`, `approval-replayed`). |
| Trust Ledger delegation events (§7) | The evidence a ledger entry would point to. |

## 4. Open questions for the group

1. **Binding a delegation to the delegate's DID.** AMEP delegations name their parent, not their holder; holder binding is left to the carrier, for example a UCAN or an ARIA sub-agent credential. Should an ARIA sub-agent credential carry the delegated claims, so a receiver can check attenuation from the credential alone?
2. **Status freshness: verification time or action time?** ARIA AP accepts a status list up to 3600 s old at verification. An auditor asking "was this authority live when B acted?" needs status as of the action. `stale-status` and `revoked-after-the-action` show the difference. Should the spec distinguish the two?
3. **Credential replacement (§3.5.3, agenda item 4.3.3).** When a credential in the chain is superseded via `previousCredentialId`, which instance should a delegation reference: the one in force when it was issued, or the current one?
4. **Scope granularity.** Exact three-segment comparison can't express "only requisition 1042". Is narrowing below the segment level in scope for ARIA, or left to receiver policy?
5. **Cryptosuites.** ARIA uses `mldsa65-ed25519-2026`. These vectors use Ed25519 over RFC 8785 JCS, and a wrapper profile carries the evidence as a VC 2.0 credential (`eddsa-jcs-2022`). Is the group interested in a vector set re-signed with the ARIA suite?
