# VATE case 2 as AMEP evidence: accepted work, interrupted

This is Takao Sato's [VATE case 2](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/093194d/reference/authzen-receipt-vectors/cases/02-accepted-interrupted) for [openid/authzen#795](https://github.com/openid/authzen/issues/795), at VATE commit `093194d`, written as AMEP evidence.

**The case.**
- The owner admits one operation that writes two files.
- runtime-a's attempt is accepted, then interrupted.
- **`zero-effects`:** the provider holds neither file. **`partial-effects`:** it holds `first.txt` only.
- VATE keeps both `unresolved`. Its enforcement point should "hold the same logical effect", including after the work is handed off to runtime-b.

**Takao's question:** after acceptance, what does the evidence establish when we see one of the two writes, or neither?

The admission is an AMEP operation approval (spec 5.10) over the digests of both file effects, as in case 1.

| Packet | What the evidence holds | AMEP |
|---|---|---|
| **zero-effects** | | |
| `z1-interrupted` | runtime-a's signed invocation; nothing from the provider | `unresolved` (I7), gap `receipt` |
| `z2-handoff-rerun` | runtime-b re-runs the operation under the same admission, while runtime-a's outcome is unknown | runtime-a: `unresolved`, gap `receipt`. runtime-b: **`unresolved`, gap `held_outcome` naming runtime-a's call** |
| `z3-not-executed` | the provider signs `not_executed` for runtime-a's call | `preserved`, "nothing executed" |
| `z4-late-write` | as `z3`, then a receipt for that call appears | `violated` (I11), blame `server` |
| **partial-effects** | | |
| `p1-interrupted` | one signed receipt (`first.txt`), no call statement | `preserved` |
| `p2-promised-two` | the provider's statement says `completed`, 2 effects; one receipt is present | `unresolved` (I7), gap `receipt` |
| `p3-handoff-rerun` | runtime-b re-runs both files under the same admission | runtime-a: `preserved`. runtime-b: `violated` (I8): the admission is spent twice |

`z1`, `p1` and the handoffs (`z2`, `p3`) follow VATE's snapshots. `z3`, `z4` and `p2` show what further evidence would establish. VATE doesn't record those.

## What the evidence establishes

- **Neither write seen.** AMEP agrees with VATE: zero observed effects isn't nonexecution, so the call is `unresolved`, and the missing evidence is named.
- **One write seen.** AMEP's `preserved` answers a different question from VATE's `unresolved`: the write that happened was within authority. It says nothing about whether the operation finished. Only the provider's own statement makes the incompleteness visible (`p2`).
- **A signed "not executed".** AMEP takes the provider's statement at its word (`z3`). VATE asks for more after acceptance: confirmed nonexecution and exclusion, so the old worker can't still write (case 3). AMEP's answer to a late write is accountability, not prevention: the receipt contradicts the statement, and the provider is blamed (`z4`).
- **The handoff.** If runtime-b re-runs the work under the same admission:
  - after runtime-a's write, the admission is spent twice: `violated` (`p3`);
  - while runtime-a's outcome is unknown, runtime-b's call can't be `preserved`. It's `unresolved` until runtime-a's outcome is known (`z2`).

## What this case changed in AMEP

`z2` exposed a gap. In AMEP 0.3.0a2, runtime-b's re-run came out `preserved` while runtime-a's outcome was unknown. Only later evidence (runtime-a's receipts) would reveal that the single-use admission had been used twice. AMEP now has **held approvals** (spec 5.10):
- An approval cited by a call with no receipts and no `not_executed` statement is held for that call, within a packet and across packets.
- Another call under it is `unresolved`, with gap `held_outcome`, until the first call's outcome is known.
- Then it's either released (`not_executed`) or a double use (`violated`, I8).

It's AMEP's form of VATE's "hold the same logical effect" when an admission exists, and the approval counterpart of held limits (spec 7.6, rule 6). The commit is `56759a2`, with five new core vectors. The released 0.3.0a2 still gives `preserved` for runtime-b in `z2`.

## Files

- **`*.packet.json`:** the evidence packets.
- **`keys.json`:** the owner, runtime-a, runtime-b and the provider.
- **`*.verdict.dsse.json`:** the caller's signed verdict record for each packet (spec 10.8). Each lists every invocation's result, so `z2` records runtime-b's `held_outcome`. Its public key is in `verifier-key.json`.
- **To regenerate and check:** run `python3 -I interop/authzen-receipts/vate-02-accepted-interrupted/generate.py`. It asserts the packet verdict and each invocation's result. All keys are deterministic test keys.
