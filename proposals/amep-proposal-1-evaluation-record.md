# AMEP-Proposal-1: EvaluationRecord

| | |
|---|---|
| **Status** | Draft for discussion |
| **Targets** | AMEP core v0.3 |
| **Authors** | Staford Titus Selvaraj; co-author invited (to be added on acceptance) |
| **Created** | 2026-11-17 |
| **Discussion** | Issues in https://github.com/stafordtituss/amep |

## 1. Summary

Add a signed, append-only **EvaluationRecord**: a verifier's statement of the results it obtained for a packet, bound to that packet by digest. A later record may **supersede** an earlier one when new evidence arrives, under two rules that keep the history auditable:

1. A later record may change a result from `unresolved` to `preserved` or `violated` only if its packet is a **superset** of the earlier record's packet.
2. A later record may **never** change a result from `violated` to `preserved`.

## 2. Motivation

AMEP evaluation (core section 10) is a pure function of the evidence packet, the key set and, for streams, verifier state. It defines no persisted result. That leaves a question open in practice, raised in external review: when an `unresolved` result is later resolved, for example because a missing revocation status arrives, is there a new record that references the first, or a re-evaluation that replaces it?

Without a record:

- an auditor cannot tell what a verifier concluded at a given time, from which evidence;
- nothing stops a party from quietly re-running evaluation on reduced evidence and presenting a better result;
- relying parties cannot reference a result, or learn that it was later superseded.

Related work states the same requirement. draft-luna-eagf-agent-delegation-semantics-02 asks for append-only, content-bound, third-party-verifiable history (its REQ-8), and for supersession to reference the earlier record rather than rewrite it (its REQ-2).

## 3. The object

`kind: "evaluation"`

| Field | Req. | Meaning |
|---|---|---|
| `id` | **yes** | Identifier of this record. |
| `kind` | **yes** | `"evaluation"` |
| `packet_digest` | **yes** | Lowercase hex SHA-256 of the RFC 8785 (JCS) form of the evaluated packet. |
| `object_digests` | **yes** | Sorted array of the digests of every object in the packet (SHA-256 of each object's JCS form, including its `proof`). Used to test the superset rule without the full earlier packet. |
| `state_in_digest` | no | Digest of the verifier state passed in (core 10.7), when state was used. |
| `spec_version` | **yes** | AMEP version applied, e.g. `"0.3"`. |
| `suite_version` | no | Conformance-suite version the verifier passes. |
| `verifier` | **yes** | Identifier of the verifier. |
| `evaluated_at` | **yes** | Time of evaluation. |
| `results` | **yes** | Array of `{ "id", "outcome", "invariant", "reason" }`, one per invocation or orphan effect, exactly as core 10.2–10.4 produce them. |
| `verdict` | **yes** | `{ "outcome", "invariant" }` per core 10.5. |
| `supersedes` | no | `id` of the earlier record this one supersedes. |
| `proof` | **yes** | Signed by a key with the new role `verifier`. |

A new signer role, `verifier`, is added to core section 12.5, permitted to sign `evaluation` objects only. Verifier keys sign nothing else, so a compromised verifier key cannot forge evidence, and an evidence key cannot forge results.

EvaluationRecords are **outputs**, not evidence. They are never placed in a packet that is itself evaluated.

## 4. Supersession rules

A record S that supersedes an earlier record E (S.supersedes = E.id) is **valid** only if all of the following hold:

1. **Same verifier lineage.** S and E are signed by keys of the same verifier (`verifier` field), unless a deployment explicitly allows cross-verifier supersession.
2. **Later.** `S.evaluated_at > E.evaluated_at`.
3. **Superset for resolution.** For every result id present in both: if E's outcome is `unresolved` and S's is `preserved` or `violated`, then `E.object_digests ⊆ S.object_digests`.
4. **Violations are final.** For every result id present in both: if E's outcome is `violated`, S's outcome MUST be `violated`. A violation is never downgraded to `preserved` or `unresolved`.

Transitions not covered above are open questions (section 8): `preserved → violated` (new evidence shows a violation), and `preserved → unresolved` (new, unverifiable evidence appears).

Records are append-only: a record is never edited or deleted. A chain of records for the same subject is read by following `supersedes` back to the first.

## 5. Verifying a record

Given a record R, its packet P, the key set and (if used) the input state, a third party:

1. verifies R's proof and that its key holds the `verifier` role;
2. checks `R.packet_digest` and `R.object_digests` against P;
3. re-evaluates P under core section 10 (deterministic, P8) and checks that the results and verdict equal R's;
4. if R.supersedes is set, obtains the earlier record and checks section 4.

A record that fails step 2 or 3 is **not reproducible**, and a relying party MUST NOT rely on it.

## 6. Conformance vectors (to be added with the change)

Vectors would gain a second form, `evaluation-chain`: an earlier record, a later record, both packets, and an expected `valid`/`invalid`.

| Vector | Expect |
|---|---|
| `unresolved-resolved-by-superset` (missing status arrives; unresolved → preserved) | valid |
| `unresolved-to-violated-by-superset` (signed revocation arrives; unresolved → violated) | valid |
| `resolution-on-non-superset-packet` (an object was dropped) | invalid (rule 3) |
| `violation-downgraded` (violated → preserved) | invalid (rule 4) |
| `record-not-reproducible` (claims preserved; re-evaluation gives unresolved) | invalid (section 5) |
| `packet-digest-mismatch` | invalid (section 5) |
| `record-signed-by-evidence-key` (host key signs an evaluation) | invalid (role) |

## 7. Relationship to EAGF

| EAGF -02 | This proposal |
|---|---|
| REQ-8 append-only, content-bound, third-party-verifiable history | Records are append-only, bound to their packet by digest, signed, and reproducible by anyone (section 5). |
| REQ-2 supersession references the earlier record; silence is not a Decision | `supersedes`, and the rule that a missing record is not a result. |
| "could not evaluate" kept apart from "denied" | AMEP `unresolved` vs `violated`, preserved in records and protected by rule 4. |

## 8. Open questions

1. Should `preserved → violated` be allowed on a superset packet (for example, a signed revocation dated before the invocation arrives late)? Proposed: yes. The new evidence is authoritative, and the earlier record stays in the history.
2. Should `preserved → unresolved` be allowed? An unverifiable object added later would otherwise erase a sound finding. Proposed: no. Report it as a separate *contested* annotation instead.
3. Should records chain across verifiers (one auditor superseding another's record), and if so, under what trust rules?
4. Should records be registrable as SCITT signed statements, so that omission of records becomes detectable?
