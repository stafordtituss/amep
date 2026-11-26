# AMEP and x402 payments

**What x402 does:** a server answers HTTP 402 with payment requirements, the client pays (typically a stablecoin transfer), and it retries the request with proof of payment. AP2 has an extension in which an AP2 mandate authorizes a payment that settles over x402.

**What x402 doesn't answer:** whether the payment was one the person had authorized. AMEP does, and its AP2 work already covers the mandate side (`interop/ap2/`).

## The mapping

| x402 / AP2 | AMEP |
|---|---|
| AP2 intent or payment mandate, signed by the user | `mandate`, with limits (spec 7.6) on amount, per call and per period |
| The agent's paid request (the retry carrying payment) | `invocation`, with `reserve` set to the most it can move |
| The settlement on chain (transaction hash, amount, asset, payee) | `effect`, observed by the facilitator or a chain indexer: a party the agent's host doesn't control. The amount is a `value` in the asset's smallest unit (`caip19:`, spec 5.9.2) |
| A 402 that was never paid, or a payment that failed | `call_statement` with `not_executed`, from the facilitator |

## Why it's a good fit

- **The settlement is independently observable.** A chain is a public record. An AMEP receipt derived from it, by a facilitator or indexer that isn't the agent's host, meets I10 for a `financial` effect.
- **Lost responses are common.** A client may not know whether its payment settled before it timed out. AMEP holds the reserve against period limits until the outcome is shown (spec 7.6, rule 6), so a retry can't exceed the budget unseen.
- **Amounts are exact.** `caip19:` units are integers in the asset's smallest unit, compared without floating point.

## Next step

A small fixture family, as for AP2:
- an x402 exchange settled within an AP2 mandate (`preserved`);
- a second payment over the period limit (`violated`, I2);
- a payment whose settlement is unknown, followed by a retry (`unresolved`, held).

These are planned, not yet built.
