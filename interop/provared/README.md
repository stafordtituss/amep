# Provared books as AMEP evidence

[Provared](https://github.com/provared/provared) (Pavel Izmaylov; [draft-izmaylov-agent-permission-receipts](https://datatracker.ietf.org/doc/draft-izmaylov-agent-permission-receipts/)) records what an AI agent was permitted to do and what it then did. A book holds:
- a **slip**: the person's permission, signed with a passkey;
- the agent's **stubs**: one per action, signed with a hybrid Ed25519 + ML-DSA-87 key set;
- the service's **countersignatures**, the person's **approvals**, the service's **refusals** and **terms**;
- **seals** with outside time-stamps.

The AMEP import profile (`packages/conformance/src/profiles/provared.mjs`) works in two steps:
1. **Check first, by Provared's own rules.** Every record is checked as the format requires: envelope, protected-header labels, canonical form, *both* hybrid signatures, the passkey signatures (WebAuthn steps 2 to 7 of the format's section 4.4), fingerprints, the chain, and approval binding. A record that fails is not used, and everything after a broken link in the chain is dropped.
2. **Then re-express as AMEP evidence and evaluate.** The slip becomes a mandate and each stub an invocation. Each stub's effect is observed by the service if it countersigned (assurance L1, the cap for reconstructed receipts), or by the agent itself if not (L0). Approvals become AMEP approvals, and AMEP gives its verdict. The importer's keys sign the re-expressed objects, and the report says so.

[COMPARISON.md](COMPARISON.md) is generated from the format's own sample book and its expected findings, and puts both results side by side. Regenerate it with `node interop/provared/compare.mjs`.

## What the comparison shows

| | Lines |
|---|---|
| Agree | 2 and 4 are `preserved` and Provared finds no breach. 6 is `violated` (I2, blame `agent`), where Provared finds `over-limit` and `approval-missing` |
| Both flag it, in different terms | 5: an order with no countersignature. Provared reports `countersignature-missing`; AMEP is `unresolved`, gap `independent_observer` (I10) |
| AMEP is stricter | 3: a message the agent sent, recorded only by the agent. Provared requires nothing more. AMEP requires an independent observer for any effect of class `external_send` or above, so it is `unresolved` |
| Both flag it (closed in 0.3.0) | 8: the agent deleted files, an action its slip does not allow, and only the agent recorded it. Provared reports `action-not-allowed`. AMEP was `unresolved` here before 0.3.0; it now treats the agent's own record of the breach as an admission: `violated` (I2), marked "on the actor's own record; not independently observed" |

The tamper checks (in the profile's tests) all fail closed: a changed amount, a removed or flipped signature (Ed25519, ML-DSA-87 or passkey), a moved countersignature or approval, a deleted stub, and non-canonical content.

## Where Provared is ahead

- **Post-quantum and hybrid signatures** on every record, and seals with three algorithms and RFC 3161 time-stamps.
- **The person signs with a passkey**, verified offline.
- **A sealed, time-stamped book with witnesses**, and a guard that writes signed refusals.

AMEP can't yet verify passkey or ML-DSA signatures itself, which is why its objects are re-expressions. That limits what AMEP can claim about the import; it doesn't change what Provared's records prove.

## What AMEP adds

- **The verdict is about what executed, from the executing side's evidence.** A stub is the agent's statement; only a countersignature makes it the service's. AMEP requires an independent observer for high-impact effects (I10), and says so rather than taking the agent's word (line 3).
- **Checks Provared doesn't make:**
  - declared versus executed effects;
  - data released, and data carried in through lineage (I5);
  - untrusted influence (I4);
  - guardrail targets (I9);
  - adapter interpretation (I3).
  Provared stubs carry none of the inputs these need, so these are gaps on the Provared side, not checks that passed.
- **Three outcomes, with blame and gaps.** `unresolved` names the missing evidence, and `violated` names the party at fault.
- **One verdict across formats:** the same evaluation applies to AER-1, OpenID action receipts and Provared books.

## Open questions for AMEP, raised by this run

1. **Answered in 0.3.0 (stafordtituss/amep#32).** The agent's own record of an action outside its permission (line 8). Should a self-reported effect that falls outside the effective claims be `violated`, as the actor's admission, rather than `unresolved` for lack of an independent observer? An admission against interest is strong evidence. The risk to weigh is a host framing an agent with records it signed itself.
2. **Caps an approval cannot lift.** Every AMEP limit can be exceeded with an approval that passed I8. Provared's `each` cap cannot be. A limit member such as `"approvable": false` would express it.
3. **Spending that stays unresolved.** At line 6, AMEP's period total is 205 GBP, not Provared's 230: line 5's 25 GBP isn't counted, because that invocation's evaluation stopped at I10 before the limits. The packet verdict can't come out `preserved` because of this (an unresolved invocation keeps the packet from being preserved), but per-invocation results after an unresolved payment are computed from a smaller total than may have been spent.
4. **Passkey (WebAuthn) and ML-DSA signatures in AMEP itself**, so that a slip could stand as an AMEP mandate without re-expression. That's planned as the optional post-quantum capability.

## Not covered by the profile

- Stubs under a pass (helper agents);
- cancellations;
- vouching records and withdrawals;
- denials and acknowledgements;
- witness statements;
- seal signatures and the tree root.

Lines carrying them are reported as not handled. The full list of what each limit and condition maps to is in the gap list of [COMPARISON.md](COMPARISON.md).
