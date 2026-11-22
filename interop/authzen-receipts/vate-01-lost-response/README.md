# VATE case 1 as AMEP evidence: a lost response, then recovery

This is Takao Sato's [VATE case 1](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/c7533ad70c20e71b7912cdf708f33220e49c1f00/reference/authzen-receipt-vectors/cases/01-lost-response-recovery/with-unknown-observation) (`with-unknown-observation`, commit `c7533ad`) for [openid/authzen#795](https://github.com/openid/authzen/issues/795), written as AMEP evidence.

The case: a runtime submits one operation that creates two files. The provider completes it, but the response is lost, so the caller's outcome is unknown. Later, the provider's record shows that the original attempt completed. The caller's unknown observation stays in the history.

| Phase | The caller holds | AMEP verdict |
|---|---|---|
| `1-pending` | Only its own signed invocation, with the digest of the arguments it sent | `unresolved` (I7), gap `receipt` for `i-1` |
| `2-recovered` | The provider's signed call statement (`completed`, 2 effects) and two receipts, all bound to the original invocation by its digest | `preserved` |
| `3-retried` | What holding prevents: a second invocation with the same arguments, which the provider also ran | `preserved` |

## How the sequence is represented

- **Unknown is derived from the evidence, not asserted.** AMEP has no caller-signed "unknown" object. The caller's own signed invocation, with nothing from the provider bound to it, evaluates as `unresolved` with the missing evidence named. An unknown outcome is never read as "not executed": that requires the provider's signed `not_executed` statement.
- **The unknown observation stays in the history** as a signed verdict record (`1-pending.verdict.dsse.json`: an in-toto statement in a DSSE envelope, spec 10.8). It names the SHA-256 of the exact packet the caller evaluated, and its outcome is `unresolved`. Recovery adds a second record for the second packet; it doesn't replace the first.
- **Recovery adds, never rewrites.** `2-recovered` contains every object of `1-pending` unchanged, and the generator checks this. The recovered receipts bind to the original invocation's digest, so they can't be attributed to a later attempt.

## Where AMEP differs from VATE

- **Holding the same logical effect isn't an AMEP verdict.** In `3-retried`, both executions are within the mandate, so the packet is `preserved`. The evidence makes the double execution visible: two `completed` statements with the same `args_digest`. But deciding that the second run shouldn't have happened is an idempotency property of the enforcement point. VATE's PEP comparison covers it; AMEP doesn't.
  - AMEP flags a repeat only when the authority bounds it: a single-use approval (I8), or a quantity limit.
- **Approvals bind one effect.** An AMEP approval covers the digest of exactly one executed effect, and an invocation cites at most one approval. VATE's single admission covering a two-file operation has no one-approval equivalent in AMEP today.

## Files

- **`N-*.packet.json`:** the evidence packets.
- **`keys.json`:** the owner, the runtime and the provider.
- **`N-*.verdict.dsse.json`:** the caller's signed verdict for each phase. Its public key is in `verifier-key.json`.
- **To regenerate and check:** run `python3 -I interop/authzen-receipts/vate-01-lost-response/generate.py`. All keys are deterministic test keys.

To check a packet with either reference verifier:

```bash
amep-protocol verify interop/authzen-receipts/vate-01-lost-response/2-recovered.packet.json --keys interop/authzen-receipts/vate-01-lost-response/keys.json
```
