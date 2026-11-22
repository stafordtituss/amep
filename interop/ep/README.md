# AMEP beside EMILIA Protocol

[EMILIA Protocol](https://github.com/emiliaprotocol/emilia-protocol) (EP; draft-schrock-ep-authorization-receipts) signs authorization receipts for high-risk agent actions, and binds an approval to the outcome. The approver signs **predicted** effects with bounds, an executor signs the **observed** effects, and a verifier returns `in_bounds`, `divergent` or `incomparable`. Those are the same three answers AMEP gives: `preserved`, `violated`, `unresolved`.

The AMEP profile (`packages/conformance/src/profiles/ep.mjs`) is tested on two of EP's published suites:
- **`receipts.v1`** (14 vectors): EP-RECEIPT-v1, checked by EP's own rules. The checker was written clean-room, from what the vectors and EP's verifier README and design notes state, without reading or running EP's code.
- **`outcome-binding.v1`, predicate vectors** (24): EP's outcome for each, beside AMEP's verdict. EP's predictions are re-expressed as AMEP claims, signed by the importer, only where AMEP has an exact form.

[COMPARISON.md](COMPARISON.md) has the results, vector by vector. Regenerate it with `node interop/ep/compare.mjs`; add `--check` to test that it's current.

## Results

| | |
|---|---|
| **Receipts** | Agrees with EP's expected result on **14 of 14**, including key-order independence, nested-parameter tampering, wrong keys, a legacy anchor refused by default, and the bound and lifted v2 anchors |
| **Outcome binding: agree** (6 of the 7 that can be compared) | A payment within its bound is `preserved`. Over its bound, it's `violated` I2. An unpredicted account closure is `violated` I2. Amounts written as JSON numbers are `unresolved` I7 on both sides, in the prediction or the observation. A predicted payment with no observed effect is `unresolved` I7 (no receipt) |
| **Outcome binding: differ** (1) | `absent_pass`, a design difference (below) |
| **Not comparable** (17) | 14 use predicates AMEP has no exact form for. 3 are malformed inputs the importer refuses, as EP does |

## What the comparison found

**1. EP's Merkle branch hash is over hex text, not raw bytes.**
- The v2 anchor reconstructs only if each branch is SHA-256 of `0x01` followed by the two children's **lowercase hex strings**.
- EP's transparency design notes write it as `0x01 || left || right`. Readers of RFC 6962, which uses that notation for raw hashes, would hash the 32-byte values, and would reject EP's anchored receipts.
- Every proof in the vectors is a single step with the sibling on the right, and in each v2 proof the sibling also sorts after the leaf. So the vectors can't tell position order from sorted order.
- `reject_tampered_anchor` carries a legacy anchor (no `alg`), so a verifier refuses it for the format before reaching the proof. No vector has a v2 anchor whose leaf is bound but whose root is wrong.

A multi-step v2 proof vector, with a left sibling that sorts after the node, would pin both hashing choices. A v2 vector with a tampered root would test the proof check itself. This is worth raising with EP's author, in the same spirit as the DRP findings.

**2. In the predicate vectors, an effect nobody predicted passes.**
- In `absent_pass`, the approver predicts only that an account is *not* closed. The executor reports a payment, and EP returns `in_bounds`: predictions bound only the effect types they name.
- AMEP's claims are an allowlist, so a payment the approver never granted is `violated` I2.

Neither is wrong; they answer different questions:
- EP's asks whether the predicted outcomes held;
- AMEP's asks whether everything that executed was authorized.

EP's graph vectors, which this profile doesn't run yet, add other conditions; this finding is about the predicate layer only.

**3. EP's outcome predicates are richer than AMEP's claims.**
- EP can bound an effect by:
  - an exact value (`eq`);
  - an exact set (`set_eq`);
  - a minimum (`gte`) or a range;
  - the number of effects (`count_lte`).
- AMEP can bound an amount from above (`per_effect`, `per_call`, `per_period`), and can bind an approval to exact effects by digest (operation approvals).

"At most 3 files deleted" and "this role grant and no other" have no exact AMEP form. A number of actions is also what AMEP couldn't express for Provared's count limits. That makes **count limits** the next candidate for an AMEP extension: two outside formats now need them.

## Where EP is ahead

- **Conformance discipline.** EP pins 21 suites and 340 vectors across three languages in a manifest with SHA-256 digests, and has an external clean-room Rust verifier with hostility cases. A claim ledger also says what each result does *not* establish.
- **Approval over predicted outcomes with tolerances,** and an executor attestation bound to the receipt, the action and a consumption nonce.
- **Witnesses, RFC 3161 time-stamps and post-quantum agility,** each with its own vectors.

## Where AMEP differs

- **Delegated authority across hops.** Each delegation must narrow its parent (I1). AMEP gives one verdict for the whole chain, with blame and the missing evidence named.
- **An allowlist,** so an unpredicted effect is outside authority by default.
- **Influence, data release and interpretation** (I3 to I5), which EP's receipts don't carry.

## Not yet covered

- EP's `outcome-binding.v1` graph vectors (11) and `outcome-binding.exec.v1` (10). They need EP's Trust Receipt and executor-attestation formats, which this profile doesn't check yet.
- EP's other 18 suites.

There is therefore no EP column in `interop/COVERAGE.md` yet: its cells would rest on two suites of 21.

## Corrections

This is the AMEP author's reading of EP through the profile's code. Corrections from EP's author are welcome, by issue or pull request.
