# AP2 payments, evaluated afterwards by AMEP

[AP2](https://ap2-protocol.org/) (Agent Payments Protocol) gives an agent payment two signed mandates:
- the user's **open** mandate, with constraints such as allowed payees, an amount range and a budget;
- the agent's **closed** mandate for one payment.

Processors return signed receipts.

**AP2 checks before the payment.** The credential provider, network and processor evaluate the closed mandate against the open mandate's constraints. AP2's dispute procedure re-verifies the artifacts and their hash links, but leaves dispute resolution itself out of scope. Nothing in AP2 decides, **afterwards**, whether what was processed stayed within the mandate.

**That's the question AMEP answers.** The `ap2` profile (`packages/conformance/src/profiles/ap2.mjs`) first checks the artifacts by AP2's rules: ES256 signatures, SD-JWT disclosures, and the closed mandate's `sd_hash` binding to the open one. It then builds AMEP evidence:

| AP2 | AMEP |
|---|---|
| Open payment mandate: allowed payees, `amount_range` max, `budget` | Mandate: `payments.send` to those payees, ceiling `financial`, `per_call` and per-period limits in `iso4217:<currency>` |
| Closed payment mandate (agent-signed) | Invocation, with the payment amount as its `reserve` |
| Payment receipt `Success`, bound by `reference` | Executed effect, observed by the processor |
| Payment receipt `Error` | A `not_executed` call statement by the processor |
| No receipt, or one bound to another mandate | Nothing: the payment stays `unresolved`, and its reserve is held |

Payments are evaluated as they settle, one packet per payment, with verifier state carried between them. So an earlier payment counts toward the budget, and an unknown one is held.

## Results

**For a crosswalk:** [verdicts.json](verdicts.json) is AMEP's column, regenerated and checked by `node interop/ap2/verdicts.mjs [--check]`.
- **It gives, for every bundle:**
  - each payment's outcome, deciding invariant, blame and named gaps;
  - which AP2 artifact checks failed.
- **It's pinned** to the SHA-256 of the exact fixture files it was computed from.
- **To compare implementations,** join on the bundle name.

The table is in [COMPARISON.md](COMPARISON.md), regenerated and checked by `node interop/ap2/compare.mjs [--check]`. The three scenarios where AMEP adds most:
- **`s6-budget`:** two payments, each within `amount_range`, that together exceed the budget. AMEP finds the second payment `violated` (I2), using past spend it derives from the processors' signed receipts.
  - AP2's SDK evaluates a budget cumulatively only when the verifier supplies past spend itself (`MandateContext.total_amount`). Without that, it reports "Missing mandate context required to evaluate budget".
  - The comparison's AP2 column checks each payment alone, without that context.
- **`s9-unknown-then-second`:** the first payment's receipt never arrives. AMEP holds its amount, so the second payment, which would exceed the budget if the first went through, is `unresolved` with gap `held_outcome`, instead of `preserved`.
- **`s5-lost-receipt`, `s7`:** without a receipt bound to the closed mandate, the payment is `unresolved`, never "fine".

Where AP2's own checks would refuse a payment (`s2` over range, `s3` wrong payee), AMEP independently finds the processed payment `violated`, with blame on the agent. That's the after-the-fact check a dispute needs when a payment slipped through. AP2's credential provider rejects these closed mandates beforehand, so the scenarios assume it didn't.

## Where AMEP goes further than AP2

Each row is a result on the bundles here, most of them produced by AP2's own SDK:

| Question a dispute asks | AP2 (spec and SDK at `e1ea56d`) | AMEP | Evidence |
|---|---|---|---|
| Did the processed payment stay within the mandate? | Checked **before** payment; the dispute procedure re-verifies artifacts and leaves resolution out of scope | Decided **afterwards**, per payment, by a party that signed none of it: `preserved`, `violated` with blame, or `unresolved` naming the missing record | every scenario |
| Was the budget respected across payments? | The verifier must supply past spend itself (`MandateContext.total_amount`); without it, "Missing mandate context" | Recomputed from the processors' signed receipts, so anyone holding the evidence can recompute it | `s6`, `sdk-budget` |
| What about a payment whose outcome is unknown? | Not addressed | Its amount is held: a later payment that would breach the budget if the first went through is `unresolved`, never `preserved` | `s9` |
| One consent redeemed twice (AP2 #346)? | The SDK's verifier accepts the identical chain again; both receipts carry the same reference | Each closed mandate becomes an AMEP intent limited to its own payee and amount per call, so a second execution under it is `violated` (I2) even when the total fits every limit | `s10`, `s11`, `sdk-redeemed-twice` |
| Is the receipt bound to this payment? | Two rules (#405); the SDK's binds by digest, the spec's describes a hash nobody computes | Accepts either and reports which matched; a missing or misbound receipt leaves the payment `unresolved` | `s5`, `s7` |
| Was the mandate altered after signing? | Rejected by verification | `unresolved`, with the signature gap's cause (`missing`) | `s8` |
| Can a second party check the conclusion? | No verdict format | Signed, re-derivable verdict records (spec 10.8), byte-identical across two implementations | `verdicts.json` |

**What AP2 does that AMEP relies on rather than replaces:** checking signatures, disclosures and constraints before payment, and issuing receipts. AMEP adds the decision afterwards; it doesn't stand between the agent and the processor.

**Blame for a double redemption** names the agent's call, the authority it exceeded. AP2's records don't show whether the second presentation came from the agent or from someone replaying it.

## Limits, stated plainly

- **Checked against AP2's own SDK.** `make_sdk_bundles.py` produces seven bundles with AP2's Python SDK (github.com/google-agentic-commerce/AP2, `code/sdk/python`, commit `e1ea56d`), stored in `packages/conformance/test/fixtures/ap2/sdk-bundles.json`.
  - **What they cover:**
    - within the mandate, over the range, the wrong payee, declined, a lost receipt, and over the budget;
    - one bundle using the `issuer_jwt_hash` binding.
  - **Results:** every SDK artifact passes AP2's checks as the profile implements them, and receipts bind by the SDK's reference rule. AMEP's verdict on each is as expected, and a test pins both.
  - **To regenerate:** install the SDK's dependencies in a virtual environment, then run `PYTHONPATH=<AP2>/code/sdk/python python make_sdk_bundles.py out.json`. ECDSA signatures are randomized, so the bytes differ each time; the verdicts don't.
  - **The nine synthetic scenarios** in COMPARISON.md use the same serialization, plus three cases the SDK can't produce: a receipt for another mandate, an altered mandate, and an unknown first payment.
- **AP2's specification and SDK disagree** on the receipt `reference`:
  - the specification says it is "calculated in the same manner as the `sd_hash`", meaning over the closed SD-JWT with its disclosures;
  - the SDK hashes the closed mandate's issuer JWT alone, so a receipt stays bound however the mandate was presented.

  The profile accepts either and reports which rule matched. The fixtures follow the SDK.
- **Units differ between constraints.** `amount_range` is in integer minor units (20000 means 200.00), but `budget.max` is a major-unit number (the SDK's `Budget.max: float`, so 300.0 means 300.00). The profile reads each as AP2 defines it.
- **Payment receipts carry no amount.** The executed value is the closed mandate's amount, on the processor's signed word that it processed that mandate. A processor that charged a different amount would show up only if its receipt said so.
- **Not mapped:** `amount_range` minimum, `agent_recurrence`, `allowed_payment_instruments`, `allowed_pisps`, `execution_date`, and the checkout mandate (`payment.reference`). Each is reported as a gap when present.
- **The budget's starting total** of zero rests on the importer's assertion that the bundle holds every payment under the open mandate. Without that, AMEP returns `unresolved` (spec 7.6, rule 5).

## Findings to report to AP2

Each was observed in AP2's own code at `e1ea56d`:
1. **The receipt `reference` rule.** The specification says the `sd_hash` manner (over the closed SD-JWT with its disclosures). The SDK hashes only the closed issuer JWT (`MandateClient.get_closed_mandate_jwt`).
2. **Budget arithmetic.** `BudgetEvaluator` computes `int(self.constraint.max * 100)`. With floating point, a budget of 1.15 becomes 114 cents and 0.29 becomes 28: one cent less than intended. It also assumes two decimal places for every currency (wrong for JPY's zero, or BHD's three).
3. **A budget depends on caller-supplied past spend** (`MandateContext.total_amount`). Nothing in a bundle lets a third party recompute it afterwards. AMEP's answer is to derive it from signed receipts, and to hold unknown outcomes.
4. **Open mandates may omit `exp`.** The SDK model makes it optional, so an open payment mandate can be valid indefinitely. The profile reports this as a problem rather than assuming a window.
