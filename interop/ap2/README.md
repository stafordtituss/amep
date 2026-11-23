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

The table is in [COMPARISON.md](COMPARISON.md), regenerated and checked by `node interop/ap2/compare.mjs [--check]`. The three scenarios where AMEP adds most:
- **`s6-budget`:** two payments, each within `amount_range`, that together exceed the budget. AP2's per-payment check accepts both. (Whether a credential provider counts earlier payments toward the budget isn't specified.) AMEP finds the second payment `violated` (I2).
- **`s9-unknown-then-second`:** the first payment's receipt never arrives. AMEP holds its amount, so the second payment, which would exceed the budget if the first went through, is `unresolved` with gap `held_outcome`, instead of `preserved`.
- **`s5-lost-receipt`, `s7`:** without a receipt bound to the closed mandate, the payment is `unresolved`, never "fine".

Where AP2's own checks would refuse a payment (`s2` over range, `s3` wrong payee), AMEP independently finds the processed payment `violated`, with blame on the agent. That's the after-the-fact check a dispute needs when a payment slipped through. AP2's credential provider rejects these closed mandates beforehand, so the scenarios assume it didn't.

## Limits, stated plainly

- **Synthetic bundles, aligned with AP2's code.**
  - **The bundles** are written to the field names of the AP2 specification (read on 23 November 2026), and serialized as AP2's Python SDK does it (github.com/google-agentic-commerce/AP2, `code/sdk/python`, commit `e1ea56d`):
    - payment mandate chains are delegate SD-JWTs joined by `~~`;
    - a closed hop binds the open one by `sd_hash` or `issuer_jwt_hash`;
    - disclosure digests and hashes are base64url SHA-256 over ASCII.
  - **Not done yet:** bundles **produced by** the SDK haven't been run through the profile. That's the next step.
- **AP2's specification and SDK disagree** on the receipt `reference`:
  - the specification says it is "calculated in the same manner as the `sd_hash`", meaning over the closed SD-JWT with its disclosures;
  - the SDK hashes the closed mandate's issuer JWT alone, so a receipt stays bound however the mandate was presented.

  The profile accepts either and reports which rule matched. The fixtures follow the SDK.
- **Payment receipts carry no amount.** The executed value is the closed mandate's amount, on the processor's signed word that it processed that mandate. A processor that charged a different amount would show up only if its receipt said so.
- **Not mapped:** `amount_range` minimum, `agent_recurrence`, `allowed_payment_instruments`, `allowed_pisps`, `execution_date`, and the checkout mandate (`payment.reference`). Each is reported as a gap when present.
- **The budget's starting total** of zero rests on the importer's assertion that the bundle holds every payment under the open mandate. Without that, AMEP returns `unresolved` (spec 7.6, rule 5).
