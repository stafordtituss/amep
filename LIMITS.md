# What AMEP can't show

AMEP decides, afterwards, whether what an agent did stayed within the authority it was delegated. This page lists where that answer stops, so nobody has to find it out the hard way. Every entry is pinned by a conformance vector or a published test: it's measured behaviour, not a claim. When AMEP can't decide, it says `unresolved` and names the missing record. It never guesses `preserved`.

The entries fall into three groups:
- **A. True of any after-the-fact evidence system.** AMEP narrows them but can't remove them, and neither can any other format.
- **B. Closed by a record AMEP already defines.** The answer is `unresolved` only when a deployment doesn't produce that record.
- **C. Open gaps,** each with the change that would close it.

## A. True of any evidence system

| Limit | What AMEP does | Pinned by |
|---|---|---|
| **A signer is trusted for what it signs.** No format can catch an observer that lies consistently. | Contradictory signed records are caught (I11). L3 receipts come from the system that executed the effect itself, and spec 17 recommends a second independent observer for `destructive` and `financial` effects. | `must-reject/receipt-contradicts-a-not-executed-statement` (`violated`, I11) |
| **A record that was never produced can't be read.** | The answer is `unresolved` (I7), naming the missing receipt, never `preserved`. | `must-reject/missing-effect-receipt` (`unresolved`, I7) |

## B. Closed by a record AMEP already defines

| Without this record | AMEP returns | The record that closes it | Pinned by |
|---|---|---|---|
| An observer's statement that a denied call didn't run | `unresolved`: a host's own claim that it blocked the call isn't proof | `not_executed` call statement (spec 5.14) | `must-reject/deny-on-a-fail-closed-host-with-no-other-record`; with the statement, `positive/deny-honoured-on-fail-closed-host--no-effect` |
| A count of the receipts each call produced | `unresolved` when one is missing | call statement with `effect_count` (spec 5.14) | `must-reject/missing-effect-receipt` |
| Earlier spend, for a period limit | `unresolved` until it's supplied | a counting observer (`counted_by`) or verifier state carried between packets (spec 7.6) | `must-reject/a-period-limit-without-a-counting-observer-needs-earlier-state` |
| A maximum for a call whose outcome is unknown | `unresolved` for later calls under the same period limit | `reserve` on the call (spec 5.9.2) | `must-reject/held-call-without-a-reserve-leaves-the-period-total-unbounded` |
| Current revocation status | `unresolved` | signed status as of the action | `must-reject/revocable-mandate-without-status`, `must-reject/stale-revocation-status` |

## C. Open gaps

| Gap | Today | What would close it |
|---|---|---|
| **Independence is checked by name.** For high-impact effects the observer must not be the actor (I10), and AMEP compares identifiers, so two names run by one party pass. | `must-reject/self-reported-high-impact-effect` is `unresolved` (I10); `positive/independently-observed-high-impact-effect` is `preserved` | Declare each observer key's operator in the key set, and require a different operator for I10. |
| **Some constraints have no field in the evidence:** the purpose of an executed effect, its audience or credential binding, counts across a principal's agents, and conflicting records. | A violation of one of these is invisible to AMEP: delegation-control-bench's [disagreements table](https://github.com/stafordtituss/delegation-control-bench/blob/main/results/RESULTS.md) (DEL-04, DEL-10 and others) | New evidence members, each with its own vectors. |
| **Both reference verifiers have the same author,** so their agreement can't rule out a shared misreading of the specification (spec 15.2). | 279/279 agreement, by one author | An implementation by someone else, run against the suite with `packages/conformance`. |

**Outside AMEP:** AP2 payment receipts carry no amount, so AMEP's AP2 profile takes the executed amount from the closed mandate, on the processor's word (`interop/ap2/README.md`). AP2 adding an amount to its receipts would close this.

To report a limit not listed here, open an issue with a packet that shows it. If it holds, it gets a vector and a row.
