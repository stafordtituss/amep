# A model of AMEP's hold and single-use rules

**What's covered:** the rules that stop one operation, or one single-use approval, taking effect twice without being reported:
- operation identity (spec 5.8.1);
- single-use and held approvals (5.10);
- "not executed" call statements, with observer independence (5.14 rules 4 and 5; I10, I11).

**Two forms of the same model:**
- **`AMEPHolds.tla`:** a TLA+ specification, for TLC.
- **`explore.py`:** a standard-library Python explorer that walks the same state space breadth-first and checks the same properties. With `--amep`, it also builds every reachable evidence view as a real packet and evaluates it with AMEP's Python verifier, which must agree with the model on every call.

The explorer is what ties the model to the code. A model that only agrees with itself proves little.

## The model

An agent issues calls, each naming an operation and, optionally, a single-use approval. The server may execute any issued call that hasn't been fenced. Evidence arrives in any order:
- **the observer's receipt** for an executed call;
- **the observer's signed "not executed":** this fences the call, so it can no longer execute (unless the observer may lie);
- **a "not executed" signed by the actor's own key,** whether or not it's true.

**The verifier sees every issued call.** That's AMEP's completeness assumption (`LIMITS.md`, section A). Within it, the verifier sees whatever evidence has arrived.

## Properties

| Property | Statement |
|---|---|
| **Sound** | When two calls took effect under the same operation or the same approval, the later one is `preserved` only if the earlier one is `violated`. A double use is never left unreported. |
| **NoFalseAlarm** | `violated` only when a call really took effect twice, or a signed statement is false. |
| **Settles** | Once every call's outcome is shown (a receipt, or the observer's "not executed"), and nobody lied, nothing is `unresolved`. |
| **Stable** | A `preserved` result stays `preserved` as evidence arrives, unless someone signs a false "not executed". The contradiction is then `violated` (I11). |

## Results (3 calls, 2 operations, an approval or none)

| Configuration | States | Holds | Fails, as expected |
|---|---|---|---|
| High-impact (`write_shared`+), honest observer | 33,825 | all four | — |
| Low-impact (`write_local`), honest observer | 33,825 | NoFalseAlarm, Settles, Stable | **Sound:** the actor's own "not executed" counts for low-impact calls (5.14 rule 5), so a host that lies about its first attempt gets its retry `preserved`. That's the documented limit, and the reason the actor's word doesn't count for high-impact calls. |
| High-impact, observer may lie | 112,945 | NoFalseAlarm, Settles, Stable | **Sound:** an observer that signs "not executed", executes anyway and withholds the receipt defeats it. AMEP's soundness rests on the observer's statement being true, which is what VATE's exclusion of the old worker provides (`interop/authzen-receipts/vate-03-confirmed-nonexecution`). If the receipt surfaces, AMEP reports the contradiction (I11). |

**Cross-check against the verifier:** at 3 calls, AMEP's Python verifier agrees with the model on every call, in every reachable evidence view of all three configurations (14,425, 14,425 and 33,825 views; about five minutes).

## What it found

AMEP's verifier and the model first disagreed on hundreds of evidence views. Each disagreement was either a bug in the verifier, now fixed in both cores, or a rule the model had stated differently, now aligned and written down below.

**Verifier bugs, now fixed (all on stafordtituss/amep#24):**
1. **The actor is its key, not its name** (commit `06a7e0c`).
   - I10 compared names: `observed_by` against `actor`, and operators only where the key set names them.
   - A host key that also had the `observer` role could sign its own "not executed", or its own high-impact receipt, under another `observed_by`. A retry was then released on the actor's own word.
   - Now a record signed by the invocation's own key is the actor's, whatever name it gives.
2. **No hold hides a double use** (commit `e71ed75`). Three orderings let an `unresolved` hold mask a violation that verified receipts already proved, against spec 5.10's rule that checks deciding `violated` come first:
   - an approval's single-use check ran after its hold check;
   - a call held on an approval didn't record its use, so a third use was held too;
   - "executed twice" (5.8.1) ran last, after the approval hold.

**None of these was in the conformance vectors,** so all 256 passed throughout. The first bug appears with two calls, the others only with three.

**Two counting rules the model now states as the verifier applies them:**
- **An operation is done once a receipt for it verifies and no statement contradicts it,** even if the call is `violated` for another reason: the operation ran.
- **A `violated` call is charged once, for its first violation.** Its use of an approval isn't counted against later calls. A double use is still reported, because the earlier call is `violated`, which is what Sound requires.

## Run it

```bash
python3 -I formal/explore.py            # the model, 3 calls (about a second)
python3 -I formal/explore.py --amep     # and AMEP's verifier on every evidence view (needs `cryptography`)
```

With TLC (`tla2tools.jar` from the TLA+ project, and Java 11 or later), from `formal/`:

```bash
java -cp tla2tools.jar tlc2.TLC -config HighImpact.cfg AMEPHolds.tla
java -cp tla2tools.jar tlc2.TLC -config LowImpact.cfg AMEPHolds.tla
java -cp tla2tools.jar tlc2.TLC -config ObserverMayLie.cfg AMEPHolds.tla
```

Each `.cfg` lists only the properties expected to hold in that configuration. To see a counterexample trace, add `Sound` to `LowImpact.cfg`.

**Status:** the results above come from `explore.py`. The TLA+ specification states the same model, but it hasn't been run through TLC yet. If TLC disagrees with the explorer, that's a bug in one of the two: please open an issue.

## Not modelled

- **Period limits and their holds** (7.6 rule 6).
- **Verifier state across packets** (10.7). The model is one packet that grows.
- **Time windows, revocation and keys.**
- **Packets that leave out invocations.** That's the completeness limit, and outside what any verifier of a presented packet can establish.
