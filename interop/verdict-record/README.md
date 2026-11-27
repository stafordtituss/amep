# AMEP verdicts as verdict records (draft-wright-verdict-record)

Seven verdict records of kind `check-run`, each stating AMEP's verdict on one of AMEP's own conformance vectors. They're in the vector format of [verdict-record-test-vectors](https://github.com/diggertydog/verdict-record-test-vectors), with a held module for its reference checker. They were written for the SCITT list thread "Reviewers wanted: draft-wright-verdict-record", 27 November 2026.

## What a record says

**Claim:** "AMEP conformance vector *name* evaluates to *verdict*".

**Evidence:** two files of this repository, each cited by the SHA-256 of its exact published bytes.

| # | File | Format |
|---|---|---|
| 0 | the vector file, under `vectors/` | `urn:amep:format:conformance-vector` |
| 1 | `vectors/keys.json` | `urn:amep:format:keyset` |

**Rule:** `urn:amep:rule:evaluate:core-sha256:<digest>`.
- The rule is software, so its name binds the implementation: the SHA-256 over the Python reference verifier's source files (`packages/python/src/amep_protocol/*.py`, sorted, one line "`<sha256>  <path>`" each). The held module refuses to load against other sources.
- **Inputs:** both are bound without a pointer, so the rule reads the exact held bytes and parses them as AMEP's verifier does. The checker's own JSON number reading never reaches the rule, so the number question Gravit raised can't arise here.

**Result:** AMEP's packet verdict (Section 10.5): `outcome`, `invariant`, `blame`, `gaps`, plus `within_window` when the verdict carries it.

## Vectors and results

| Vector | Record | Reference checker |
|---|---|---|
| av01 | `valid-preserved-flow`: preserved | released; PASS PASS PASS |
| av02 | `effect-outside-delegated-scope`: violated (I2), blame agent | released; PASS PASS PASS |
| av03 | `self-reported-high-impact-effect`: unresolved (I10), gap `independent_observer` | released; PASS PASS PASS |
| av04 | `revoked-between-invocation-and-effect--singletary-case-1`: violated (I6) | released; PASS PASS PASS |
| av05 | `revoked-mid-action--inside-the-declared-propagation-window`: preserved, with `within_window` | released; PASS PASS PASS |
| an01 | states preserved for av02's vector | refused; FAIL at step 3 (the re-run gives violated, I2) |
| an02 | names an AMEP verifier build the checker doesn't hold | held; NOT RUN at step 3 |

These ran on the reference checker `vrcheck.py` at commit `ba9ea21`, 7 of 7 as expected. The full reports are in `results.json`. No record or vector was changed after the first run.

## Two notes for the draft

1. **A rule that runs software can avoid the number question by reading bytes.**
   - Gravit found that a checker parsing an item's numbers as exact decimals, and a kernel reading them as binary floats, can re-run the same rule on the same bytes and disagree.
   - Binding inputs without a pointer, so the rule receives the item's digest and reads the held bytes itself, puts parsing entirely inside the rule's specification.
   - The draft could suggest this for rules that run software, alongside binding the implementation by digest.
2. **Two kinds of verdict record, one layered on the other.** AMEP already has its own signed verdict record: an in-toto statement whose predicate two AMEP implementations produce byte for byte (`interop/in-toto/`). A `check-run` verdict record over it adds what that one doesn't have: a claim, evidence cited by digest, and a rule any checker can re-run. The AMEP predicate's `verdict` object is exactly the `check.result` here.

## Run

    git clone https://github.com/diggertydog/verdict-record-test-vectors vrtv && git -C vrtv checkout ba9ea217610b3960fc5c7d1dfe692e581aeb43e2
    python3 -I interop/verdict-record/gen.py                   # regenerate (pins the verifier digest)
    VRTV=vrtv python3 -I interop/verdict-record/run.py         # 7 of 7; writes results.json

`gen.py` refuses to write a record whose verdict differs from the vector's own expectation. Changing AMEP's Python verifier changes the digest, so `gen.py` must be rerun, and the old records then name a build the checker no longer holds, as an02 shows. As in the reference vectors, no container is included, and each vector supplies the record's upper time bound directly.
