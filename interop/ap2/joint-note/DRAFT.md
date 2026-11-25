# Three verifiers, one AP2 fixture set: a joined comparison

*Working draft for the co-authors. It isn't a publication: nothing here is final until every author has agreed on the whole text, and each author confirms the numbers for their own column or family from their own runs.*

**Proposed authors** (each only with their agreement): Brennan Zambo (AER-1), nmatt1 (APAF-1), Staford Titus Selvaraj (AMEP); and, for the receipt-layer family (section 4.4), the authors of ccs-ap2-pinned-family. The order is for the authors to decide.

**Where:** a short technical note with a DOI (Zenodo), linked from AP2 #402 and from each project. It's citable, and authored by three independent parties.

**How to edit:** open a pull request against this file, or comment on google-agentic-commerce/AP2#402. Numbers marked *(to confirm)* are carried over from the thread, and are replaced only by their owner.

## 1. Question
After an AP2 payment, three different questions can be asked of the same artifacts:
- **AMEP:** was the payment within the authority the user delegated?
- **AER-1:** is the execution record authentic and complete?
- **APAF-1:** would a decision layer have approved it, given state carried across payments?

How far do the answers agree, and where they differ, why?

## 2. Fixtures and pins
- **Family 1:** AP2's Python SDK at `e1ea56d`; 22 payment rows (`sdk-bundles.json` `7e1dd6d9…`, `bundles.json` `bd530228…`).
- **Family 2:** the same SDK with checkouts and `payment.reference`; 33 rows (pin `70626262…`).
- **Each column, pinned:**
  - AMEP: `verdicts.json` `93aa9005…` and `verdicts-checkout.json`;
  - AER-1: aer1-kit join table at `a923247`;
  - APAF-1: `apaf1-column.json` at `e4564ad` and `7b7388e`.

## 3. Join method
- **Key:** bundle name and payment index. `transaction_id` is used where present; s8's `closed_mandate_absent` row has none, so it uses bundle and index only.
- **Vocabularies, mapped and not merged:**
  - AMEP: preserved / violated / unresolved;
  - AER-1: verified / failed / …;
  - APAF-1: approved / declined / escalated / not_evaluated.

## 4. Results *(to confirm)*
- **Family 1, AMEP against AER-1:** 10 rows agree and 12 diverge. 10 of the divergences come from different questions (the record against the decision); 2 are the same facts drawing a different refusal (Brennan's join). *AER-1 column: confirmed by its owner, re-derived row by row from the aer1-kit join table at `a923247` (22 rows: 10 agree, 10 diverge on scope, 2 diverge on kind; AER-1 outcomes 17 verified, 2 verification failed, 3 absent, 0 not checked, 0 rejected).*
- **APAF-1 against AMEP:** every row agrees on the AMEP side, including the `held_outcome` gap on s9 txn-2 and the signature gap on s8.
- **Family 2:** both checkout-binding cases agree across AMEP and APAF-1 (another checkout: violated / declined; checkout chain absent: unresolved / escalated).

### 4.4 Receipt-layer semantics (optional family, ccs-ap2-pinned-family)
Offered by its authors on AP2#402. The family is pinned at DSHCorrectover/ccs-ap2-pinned-family, commit `4271ac0`, and locked by its `manifest.sha256`. Three vectors over its own pinned bundle:
- **A1, budget total recomputed:** the caller's context is untrusted and the mandate amount is authoritative. Result: violated, with the departure named.
- **A2, unknown outcome held:** a pending payment stays a named unresolved, and is never promoted.
- **A3, verdict naming:** violated carries what departed; unresolved carries what is missing.

Each column's result on these vectors is *(to run)*, except the AER-1 column, run by its owner and posted on AP2 #402 (comment 7148415906). The bundle was read as data only; its SHA-256 recomputes to the manifest lock (`a9f49107…`). The bundle carries no digest material (no closed hop bytes, no disclosures, no sd_hash), so no vector earns a verified or a verification failed from the AER-1 column:
- **A1, AER-1 column:** not checked. The amounts were recomputed: caller-claimed 27999 against the mandate's 35999, a departure of 8000 minor units (USD). That mismatch is a decision-layer fact; the receipt's reference is the literal `ref1` and there are no closed mandate bytes to recompute it against, and the AER-1 dictionary carries no "violated".
- **A2, AER-1 column:** not checked, and never promoted. The receipt status `Pending` sits outside the {Success, Error} enum, and the receipt carries no reference and no payment_id, so no binding exists for a record check to run on.
- **A3, AER-1 column:** not applicable as a record evaluation (the vector is verdict objects only, no receipts or digests). As a vocabulary mapping only: `v-bad-name` (violated, no departed named) and `u-bad-name` (unresolved, no missing named) would not meet the naming discipline; `v-good` carries its departed and does.

The family's authors confirm their own numbers.

## 5. Findings that came out of the comparison
1. **The fixtures lacked `payment.reference`.** Found by APAF-1 and fixed on AMEP's side with the second family; AMEP now checks checkout binding.
2. **The receipt `reference` rule:** AP2's specification text and its SDK disagree (AP2 #405).
3. **The s8 join key:** a closed mandate that's absent leaves no `transaction_id`.
4. **State across payments** (budget, use count, replay): judged by APAF-1, and held by AMEP when an outcome is unknown.

## 6. What none of the three can establish from these artifacts
- **The settled amount, independently:** AP2 receipts carry no amount.
- **Completeness of the presented set:** the ACP §7.4a commitment would close this.

## 7. Reproduction
The commands for each column, at the pins above.
