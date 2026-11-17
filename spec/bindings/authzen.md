# AMEP Binding: OpenID AuthZEN

| | |
|---|---|
| **Document** | `amep-binding-authzen` |
| **Version** | 0.2.0-draft.4 |
| **Status** | Public Draft. Companion to `spec/amep-v0.2.md` (the "core"). |

This binding lets a Policy Enforcement Point (PEP) that already speaks the OpenID AuthZEN Authorization API obtain AMEP ContinuityDecisions from a Policy Decision Point (PDP) without a second protocol. It defines how an AMEP Invocation maps onto an AuthZEN evaluation request, how the decision and its evidence come back, and how `step_up` and `mediate` are carried.

The key words MUST, SHOULD and MAY are used as in BCP 14 (RFC 2119, RFC 8174).

*Note:* AuthZEN's Approval and Obligations work was still in draft when this was written. Member names under `context` defined here are AMEP's own and do not depend on those drafts; Section 5 says how to align once they are final.

## 1. Request mapping

A PEP evaluating an invocation sends an AuthZEN Access Evaluation request:

| AuthZEN member | Filled from |
|---|---|
| `subject.type` | `"agent"` |
| `subject.id` | `invocation.actor` |
| `subject.properties.amep_principal` | the root mandate's `principal` |
| `action.name` | `invocation.declared.action` (canonical, core 6.1) |
| `action.properties.amep_effect` | `invocation.declared.effect` |
| `resource.type` | the action namespace (for example `fs`, `saas`) |
| `resource.id` | `invocation.declared.resource` (canonical, core 6.2) |
| `context.amep` | the AMEP object (below) |

`context.amep` carries the evidence the PDP needs to run the core evaluation on the **predicted** effect:

```json
"context": {
  "amep": {
    "version": "0.2",
    "invocation": { "...": "the signed Invocation" },
    "predicted_effect": { "action": "fs.write", "resource": "repo:app/src/auth.ts", "effect": "write_local", "t": 1767225611 },
    "packet_ref": "https://evidence.example/packets/8f1c…",
    "packet": { "...": "OPTIONAL inline packet: chain, interpretation, intent, approval, findings" }
  }
}
```

- The PEP MUST send either `packet` (inline) or `packet_ref` (a URL the PDP can fetch with its own credentials). The PDP MUST NOT treat evidence it cannot obtain as present (core P4).
- `predicted_effect` is an executed-effect body (core 5.9) describing what the PEP expects to execute. The PDP evaluates core 10.2 with it in place of an effect receipt. Steps 10–12 (receipt presence, receipt signature, observer independence) are skipped before execution, and enforced after execution by the detective flow.

## 2. Response mapping

```json
{
  "decision": false,
  "context": {
    "amep": {
      "decision": { "kind": "decision", "invocation": "i-1", "outcome": "violated", "invariant": "I6",
                    "mode": "deny", "reason": "ancestor revoked before invocation",
                    "evidence_refs": ["m-1", "d-1"], "proof": { "...": "PDP signature, role host" } }
    }
  }
}
```

- `decision` MUST be `true` only when the ContinuityDecision's `mode` is `allow`, `observe` or `mediate`.
- `context.amep.decision` MUST be a signed ContinuityDecision (core 5.13). A PEP SHOULD log it with the invocation so that a later verifier can reconcile it (core 10.3).
- A PDP that cannot evaluate (timeout, missing evidence, internal error) MUST return `decision: false` with an `unresolved` decision, never an HTTP error that a PEP might treat as non-blocking (core 11.2).

## 3. Step-up and hold

When the mode is `step_up` or `hold`:

```json
"context": { "amep": { "decision": { "...": "mode step_up" },
  "approval_request": { "effect_digest": "<SHA-256 of JCS(predicted_effect without t)>",
                        "presence_required": "webauthn", "expires_in": 600,
                        "approval_uri": "https://approvals.example/r/7c2e" } } }
```

The approval service issues an ApprovalBinding (core 5.10) signed by an `approver` key. The PEP retries with `approval_ref` set; the PDP verifies I8, including single use within its evaluation window.

## 4. Mediation and obligations

When the mode is `mediate`, `context.amep.obligations` lists what the PEP MUST do before allowing the call:

| Obligation | Meaning |
|---|---|
| `amep.obligation.rewrite_input` | Replace the call with `mediated` (an executed-effect body that satisfies the effective claims). The PEP MUST record it in the invocation's `mediated` member. |
| `amep.obligation.emit_effect_receipt` | Ensure an ExecutedEffectReceipt is produced at assurance `min_assurance` or higher. |
| `amep.obligation.snapshot_before` | Take a restorable snapshot of `resource` before execution (makes the effect reversible for budget purposes, core 9.1). |

A PEP that cannot fulfil an obligation MUST treat the decision as `deny`.

## 5. Alignment with AuthZEN profiles

When AuthZEN's Approval and Obligations profiles are final, implementations SHOULD carry `approval_request` and `obligations` in the profile-defined members as well, and MAY drop the AMEP-specific members in a later version of this binding. Batch evaluation (the AuthZEN Evaluations API) MAY be used to evaluate several invocations of one workflow at once; each result carries its own `context.amep.decision`.

## 6. Security considerations

- The PDP signs decisions with a `host`-role key. A PEP MUST NOT forward a decision it did not receive from its configured PDP.
- Inline packets can be large and can contain personal data; prefer `packet_ref` with access control and data-class minimisation (core 18).
