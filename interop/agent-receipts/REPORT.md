# Agent Receipts through the AMEP profile: coverage report

**Pinned to:** agent-receipts/obsigna at commit `7c5a02ccabfb4092bb4c2ec7bbcfcd677565c22f`, spec v0.5.0, `cross-sdk-tests/`. AMEP 0.3.0.

**What this is:** the AMEP import profile run offered in agent-receipts/obsigna#1204. The profile (`packages/conformance/src/profiles/agent-receipts.mjs`) carries the four corrections from the maintainers' review in that issue. The Agent Receipts maintainers reviewed the profile's reading of their receipts there. That review covers the reading, and is not an endorsement of AMEP.

**Method:** `node interop/agent-receipts/run.mjs <obsigna checkout>`. It reads the vector files as data and runs no code from the obsigna repository. Canonicalization, hashing and signature checks use AMEP's own code. The full output is in `results.json`.

**Scope:** `cross-sdk-tests/` only. The TypeScript vectors in `sdk/py/tests/fixtures/ts_vectors.json` aren't covered by this run.

## A. Format checks, with AMEP's code

| Check | Result |
|---|---|
| JCS canonicalization vectors | 30 of 33. The other 3 are numbers outside the I-JSON range (`1e21`, 10^20, 2^53). AMEP refuses these by design (spec 12.1), so a receipt carrying such a number wouldn't import. This is a difference between the two canonical forms, not an error in either. |
| Receipt hash vectors | 10 of 10. Two of them are schema-invalid emitter input (`preNormalizationInput`). They match after the SDKs' null-to-absent sweep (ADR-0009, Rule 2). The profile applies that sweep only to reproduce these two vectors, never to a received receipt. |
| Signed receipts outside the malformed set | 15 of 15 verify: Ed25519 over the JCS form without `proof`, under each file's published key |
| Malformed receipts | 7 of 7 rejected |
| Malformed chains | 4 of 4 rejected. Each breaks where its clause says: link 1 (hash), link 2 (hash), link 2 (sequence), link 2 (sequence) |
| The malformed set as a whole | Rejected in full, as the spec requires |
| `v020.terminalChain`, `v040.duplicateIdempotencyChain` | Both valid. The second reports its duplicate `idempotency_key`, as spec 7.3.6 requires |

These counts agree with the two earlier runs on #1204: Brennan Zambo's own verifier, and the maintainers' re-run with their Python SDK.

## B. What imports as AMEP evidence

The profile maps a receipt to an AMEP effect through a deployment tool map (`toolmap.json`), as for every other import profile. `action.type` names a class of action, not a resource or an effect class, so the map is the verifier's reading, not the Agent Receipts spec.

| | Receipts | Why |
|---|---|---|
| Imported | 4 of 15 | Three `system.command.execute` (high risk) and one `data.api.read` success. The map fixes their resource per action type, because none of them carries `action.target`. |
| Not imported: no resource | 9 | `filesystem.file.read` receipts with no `action.target`. A grant scoped to resources can't be checked against them. |
| Not imported: outcome | 1 | `outcome.status: failure` (a timeout). It doesn't establish what was executed, so the call stays `unresolved` and holds its operation (spec 5.8.1, rule 2). |
| Not imported: not an action | 1 | `system.events_dropped`, which is a meta event. |

Each gap below is a gap in what a receipt alone shows. The mechanism Agent Receipts uses to cover it is named beside it.

| What AMEP needs | In the receipt | Covered in Agent Receipts by |
|---|---|---|
| Whether the signer is a party other than the acting agent | Not shown. Daemon and client-side receipts look the same (#1206). | Daemon key custody (ADR-0010), known to the verifier out of band |
| The grant the action is judged against | `authorization.scopes`, opaque and asserted by the issuer, in 1 of 48 receipts | The grounded-principal tier (spec 7.9), which checks that a grant exists for the principal through `grant_ref`. Whether the action stayed within it is #1207. |
| The resource acted on | `action.target`, optional, absent from every signed receipt | — |
| Binding to the authorizing call | `parameters_hash`, if both sides hash the same JCS parameters (unstated) | — |
| The logical operation, for retries | `action.idempotency_key` (spec 7.3.6) | Duplicate-key warning |

## C. Worked AMEP verdicts

The receipts are the effect evidence. Three inputs are the verifier's, stated as such:
- **the mandate:** the principal `did:user:test` may run commands on `host:commands` and read `api:data`;
- **one invocation per receipt,** signed by the agent's host;
- **the deployment mode.**

The importer re-expresses the receipt's issuer as the AMEP observer. It gives that key the operator the deployment declares, so the independence rule (I10, spec 12.5) sees the deployment as declared. Using `issuer.operator` this way is AMEP's interpretation, not the Agent Receipts spec.

| Case | Mode, as the verifier declares it | AMEP verdict |
|---|---|---|
| One high-risk command (`v040.idempotencyKeyReceipt`) | Client-side (ADR-0020): the agent signs its own receipt | `unresolved` I10: the high-impact effect is only self-reported |
| Same | Daemon mode (ADR-0010), daemon run by the agent's own operator | `unresolved` I10: observed only by a key of the host's own operator |
| Same | Daemon run by an operator other than the agent's | `preserved` |
| Timeout, then a retry under the same `idempotency_key` (`v040.duplicateIdempotencyChain`) | Any | `unresolved` I7: the operation is held for the first call, whose outcome is unknown. A signed `not_executed` statement from a party other than the agent would release it, and the retry would be `preserved`. |
| Two successes under one `idempotency_key` (constructed for this run: the chain above plus a second success, signed with the published test key) | Daemon run by another operator | `violated` I2 on the second call: "executed twice" |

The "unresolved until a second party signs" outcome for high-risk actions is AMEP's rule, not an Agent Receipts outcome. The Agent Receipts spec defines no co-signing. Its answer for high-risk actions is the grounded-principal tier (spec 7.9), and under it these three receipts would be rejected because none carries a `grant_ref`.

The last two rows are where the two specs meet. Spec 7.3.6 surfaces a duplicate key as a warning and leaves it to "review whether the duplicates represent expected retries or unexpected double-counting". AMEP's operation identity rules (spec 5.8.1) make that review a verdict:
- a retry after an unknown outcome stays held;
- a retry after the first attempt is shown not executed proceeds;
- a second success under the same key is a double execution.

## D. Small changes that would close most gaps

1. **A deployment-mode claim the verifier can check** (#1206), for example a daemon key certified by the operator. With it, the I10 rows above become checkable rather than declared.
2. **`action.target` on actions that change something**, or at least on high-risk ones.
3. **Name the canonical form of `parameters_hash`.** If it's the JCS SHA-256 of the parameters, it binds to an AMEP invocation by digest.
4. **A signed "not executed" outcome**, distinct from `failure`, for a call the daemon knows did not run. That's what releases a held retry.
