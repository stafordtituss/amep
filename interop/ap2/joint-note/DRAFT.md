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
- **Family 2:** the same SDK with checkouts and `payment.reference`; 11 payment rows (`sdk-bundles-v2.json`: 10 bundles, one with two payments; pin `70626262…`). The APAF-1 column's 33 rows are its total across all three families it covers (correction from nmatt1).
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
- **Family 1, AMEP against AER-1:** 10 rows agree and 12 diverge. 10 of the divergences come from different questions (the record against the decision); 2 are the same facts drawing a different refusal (Brennan's join).
- **APAF-1 against AMEP:** every row agrees on the AMEP side, including the `held_outcome` gap on s9 txn-2 and the signature gap on s8.
- **Family 2:** both checkout-binding cases agree across AMEP and APAF-1 (another checkout: violated / declined; checkout chain absent: unresolved / escalated).

### 4.4 Receipt-layer semantics (optional family, ccs-ap2-pinned-family)
Offered by its authors on AP2#402. The family is pinned at DSHCorrectover/ccs-ap2-pinned-family, commit `4271ac0`, and locked by its `manifest.sha256`. Three vectors over its own pinned bundle:
- **A1, budget total recomputed:** the caller's context is untrusted and the mandate amount is authoritative. Result: violated, with the departure named.
- **A2, unknown outcome held:** a pending payment stays a named unresolved, and is never promoted.
- **A3, verdict naming:** violated carries what departed; unresolved carries what is missing.

Each column's reading below is the one its owner posted on AP2#402, unedited in substance. Each owner read the bundle as data only, at `4271ac0`, and recomputed its SHA-256 to the manifest's lock (`a9f49107…09f8`). The objects carry no signed material, so the binding layer of every column stops first (AMEP: signature gap; AER-1: not checked; APAF-1: escalated). The readings are of each column's decision or record question, taking the objects as authentic.

| Vector | CCS (family's own) | AMEP | AER-1 | APAF-1 |
|---|---|---|---|---|
| **A1**, budget total | violated (claimed 27999 against mandate 35999) | unresolved: the receipt carries no amount (gap `value`); the caller's figure is a claim, not a record of execution | not checked: no closed mandate bytes to recompute a reference against; "violated" is outside its vocabulary | approved: the executed payment equals the mandate; the caller's total is not an input |
| **A2**, unknown outcome held | unresolved, never promoted | unresolved, held against reserves, approvals and operations | not checked, never promoted | escalated, never promoted; a later payment needing the budget escalates on `prior_outcome_unresolved` |
| **A3**, verdict naming | v-good meets it; v-bad-name and u-bad-name don't | met by construction (core suite: every violated names invariant and blame, every unresolved a gap) | not applicable as a record evaluation; the naming discipline matches its own | met by construction (declined names the constraint, escalated what couldn't be verified) |

**A1 is the family's most instructive divergence:** four answers to one artifact, each defensible from its layer's question. Three columns agree that the caller's figure doesn't convict the payment. They differ on what the record shows: an unknown amount (AMEP), nothing checkable (AER-1), or equality with the mandate (APAF-1). CCS answers a different question, whether the caller's context matches the mandate.

*(to confirm: each owner's cell, before the text is agreed.)*

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
