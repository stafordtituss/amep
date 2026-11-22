# AMEP and OpenID delegated authorization receipts

This maps two OpenID Foundation drafts onto AMEP, so that a third party can evaluate their action receipts against the delegated authority:
- the eKYC & IDA **Delegated Authorization Execution Layer** (v0.2, §6 Action Receipts);
- the AuthZEN **`receipt` obligation** proposal ([openid/authzen#795](https://github.com/openid/authzen/issues/795)).

It is an informative mapping from the AMEP side, not a statement by either working group.

The import profile is `oidf-action-receipt` in [`packages/conformance`](../../packages/conformance). The tests run the execution layer's own §9.1 scenario: the AI travel agent booking a hotel for Bob.

## The step this fills

The execution layer's verification flow (§6.7) is:
1. verify the PEP's signature;
2. verify the transparency-service inclusion proof;
3. verify the PDP and Credential Manager sub-claim signatures;
4. "verify the delegation chain references against the actual Relationship / Authority / Task JWTs";
5. optionally walk the prior receipts.

Step 4 establishes that the references resolve. It does not say how to decide whether the **action** stayed within what the Authority and Task allowed. #795 leaves the same step to "a third party [that] verifies later".

AMEP is a deterministic evaluation for exactly that decision. It returns:
- `preserved`;
- `violated` (with the deciding invariant);
- or `unresolved`, when the evidence cannot settle it. Missing evidence never counts as permission.

## Mapping

| Execution layer / #795 | AMEP | Notes |
|---|---|---|
| Authority, Task (JWTs, referenced by `jti` and hash) | Mandate and delegation claims (spec §5.3–5.5): actions, resources, ceiling, validity, limits | The receipt carries references only. The verifier supplies the Task as an AMEP mandate. |
| `further_delegation_chain` | AMEP delegations, attenuation (I1) | A sub-delegation that widens scope is `violated` (I1). |
| `audit_id`, `decision_attestation` | Invocation (spec §5.8) | `decision_attestation.request_hash` binds to the invocation's `args_digest` when both hash the same AuthZEN request. |
| `action` (`rs_identity`, `verb`, `resource_type`, `action_time`) | Executed effect (spec §5.9) | Mapped through a published map of verb and resource type. |
| `result.outcome` `success` / `partial` | An effect to evaluate | |
| `result.outcome` `failure` / `network-error`, #795 `unknown` | No effect is imported; the call is `unresolved` | As in #795 items 1 and 6, an unknown outcome is not evidence of non-execution. |
| #795 confirmed non-execution | AMEP call statement `not_executed` (spec §5.14) | |
| A non-`permit` decision with an executed action | Reported, never imported as authorized | This is AMEP's I11 case (an effect despite a deny). |
| Revocation receipts (§6.5) | AMEP revocations, checked at the action's own time (I6) | |

## Results: the §9.1 travel agent

Bob's Task allows hotel bookings at Marriott or Hilton until the end of April.

| Receipt | AMEP verdict |
|---|---|
| Booking at Marriott within the Task | `preserved`, bound to the call by `request_hash` |
| Booking at a chain the Task doesn't allow | `violated` (I2) |
| Booking after the Task expired | `violated` (I2) |
| Booking after the Task was revoked | `violated` (I6) |
| `network-error` outcome | not imported: `unresolved` |
| Action executed under a `deny` decision | reported; not imported: `unresolved` |

## What the receipt does not carry for this decision

These are offered as feedback on the receipt payload (§6.4), not as defects of the drafts:

1. **The action's amount.** The Task's constraint "$400/night" can't be checked from the receipt. The action descriptor has no amount, and `context.constraint_state.accumulated_spend_usd` is a running total asserted by the PEP. AMEP carries amounts as exact decimal strings on the executed effect (`value`, spec §5.9.2), and its per-call and per-period limits (§7.6) would check such a constraint directly. That would need an amount in `action` or `result`.
2. **The Task's content.** By design, the receipt references the Task by `jti` and hash. A verifier must obtain the Task, so the evaluation is only as good as that retrieval. Binding the supplied Task to the referenced hash is the verifier's first check.
3. **The PEP signature format** is deferred to a later profile (§6.10, "Format choice — to be profiled"). Until then, the profile reads the payload only and caps assurance at L1.

## Reproducing

```bash
cd packages/conformance && npm install && npm test
```

The scenario tests are in `test/conformance.test.mjs`, under "OpenID action receipt profile".
