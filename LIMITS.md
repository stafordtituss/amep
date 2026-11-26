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
| **An effect nobody recorded can't be seen.** The presented records may not be all there is. | For file writes, a signed Observed Effect record from an observer below the agent, graded authoritative with absence established, lists every write in a path scope over an interval. `amep-conformance` reconciles it with a packet: writes with no receipt, receipts the observer never saw, and calls whose outcome the record settles. Outside that scope and interval, nothing is concluded. | `packages/conformance/test/observed-effect.test.mjs`; `interop/in-toto/OBSERVED-EFFECT.md` |

## B. Closed by a record AMEP already defines

| Without this record | AMEP returns | The record that closes it | Pinned by |
|---|---|---|---|
| An observer's statement that a denied call didn't run | `unresolved`: a host's own claim that it blocked the call isn't proof | `not_executed` call statement (spec 5.14) | `must-reject/deny-on-a-fail-closed-host-with-no-other-record`; with the statement, `positive/deny-honoured-on-fail-closed-host--no-effect` |
| A count of the receipts each call produced | `unresolved` when one is missing | call statement with `effect_count` (spec 5.14) | `must-reject/missing-effect-receipt` |
| Earlier spend, for a period limit | `unresolved` until it's supplied | a counting observer (`counted_by`) or verifier state carried between packets (spec 7.6) | `must-reject/a-period-limit-without-a-counting-observer-needs-earlier-state` |
| A maximum for a call whose outcome is unknown | `unresolved` for later calls under the same period limit | `reserve` on the call (spec 5.9.2) | `must-reject/held-call-without-a-reserve-leaves-the-period-total-unbounded` |
| Current revocation status | `unresolved` | signed status as of the action | `must-reject/revocable-mandate-without-status`, `must-reject/stale-revocation-status` |
| Who runs each key. Without it, observer independence (I10) is checked by the identifiers in the records, so two names run by one party would pass. | `preserved` for a differently named observer | `operator` on each `host` and `observer` key (spec 12.5). With it, an observer key of the host's own operator is `unresolved` (I10). | `must-reject/high-impact-effect-observed-only-by-a-key-of-the-host-s-own-operator`, `must-reject/high-impact-call-reported-not-executed-only-by-a-key-of-the-host-s-own-operator`; `positive/high-impact-effect-observed-by-a-key-of-another-operator` |

## C. Open gaps

| Gap | Today | What would close it |
|---|---|---|
| **Some constraints have no field in the evidence:** the purpose of an executed effect, its credential binding, counts across a principal's agents, and conflicting records. Audience binding shipped in 0.3.0 (spec 5.3): claims may name `audiences`, and a receipt carries `audience`. Where the claims name audiences and a receipt doesn't, the result is `unresolved`; where they name none, audience isn't checked. | A violation of one of these is invisible to AMEP: delegation-control-bench's [disagreements table](https://github.com/stafordtituss/delegation-control-bench/blob/main/results/RESULTS.md) (DEL-04, DEL-10 and others) | New evidence members, each with its own vectors. |
| **Both reference verifiers have the same author,** so their agreement can't rule out a shared misreading of the specification (spec 15.2). | **Partly closed:** an independent implementation, written from the spec and vectors alone, agrees with all 228 single-packet core vectors (stafordtituss/amep#18). Its reading also led to four clarifications of the spec text. | Its cross-packet row (Section 10.7) and the two interop suites, which are still open there; and further implementations. |

**Outside AMEP:** AP2 payment receipts carry no amount, so AMEP's AP2 profile takes the executed amount from the closed mandate, on the processor's word (`interop/ap2/README.md`). AP2 adding an amount to its receipts would close this.

To report a limit not listed here, open an issue with a packet that shows it. If it holds, it gets a vector and a row.
