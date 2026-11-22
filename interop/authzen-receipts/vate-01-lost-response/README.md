# VATE case 1 as AMEP evidence: a lost response, then recovery

This is Takao Sato's [VATE case 1](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/c7533ad70c20e71b7912cdf708f33220e49c1f00/reference/authzen-receipt-vectors/cases/01-lost-response-recovery/with-unknown-observation) (`with-unknown-observation`, commit `c7533ad`) for [openid/authzen#795](https://github.com/openid/authzen/issues/795), written as AMEP evidence.

The case: a runtime submits one operation that creates two files. The provider completes it, but the response is lost, so the caller's outcome is unknown. Later, the provider's record shows that the original attempt completed. The caller's unknown observation stays in the history.

| Phase | The caller holds | AMEP verdict |
|---|---|---|
| `1-pending` | Only its own signed invocation, with the digest of the arguments it sent | `unresolved` (I7), gap `receipt` for `i-1` |
| `2-recovered` | The provider's signed call statement (`completed`, 2 effects) and two receipts, all bound to the original invocation by its digest | `preserved` |
| `3-retried` | What holding prevents: a second invocation with the same arguments, which the provider also ran | `preserved` |
| `4-approved-recovered` | As `2-recovered`, with the owner's admission carried as an AMEP **operation approval** listing the digests of both file effects | `preserved` |
| `5-approved-retried` | As `3-retried`, under that approval: the retry spends the admission a second time | `violated` (I8) |

## How the sequence is represented

- **Unknown is derived from the evidence, not asserted.** AMEP has no caller-signed "unknown" object. The caller's own signed invocation, with nothing from the provider bound to it, evaluates as `unresolved` with the missing evidence named. An unknown outcome is never read as "not executed": that requires the provider's signed `not_executed` statement.
- **The unknown observation stays in the history** as a signed verdict record (`1-pending.verdict.dsse.json`: an in-toto statement in a DSSE envelope, spec 10.8). It names the SHA-256 of the exact packet the caller evaluated, and its outcome is `unresolved`. Recovery adds a second record for the second packet; it doesn't replace the first.
- **Recovery adds, never rewrites.** `2-recovered` contains every object of `1-pending` unchanged, and the generator checks this. The recovered receipts bind to the original invocation's digest, so they can't be attributed to a later attempt.

## What this case changed in AMEP

Before this case, an AMEP approval bound the digest of exactly one executed effect, and an invocation cites at most one approval. So VATE's single admission over a two-file operation had no AMEP equivalent. AMEP v0.3 now has **operation approvals** (spec 5.10): `effect_digests` lists the digests of the effects of one call.
- **Every executed effect must be listed**, and no body may run more often than it's listed.
- **It is single use.** A retry that cites it is `violated` (I8); the suite has 9 vectors for it.

## Where AMEP still differs from VATE

- **Without an admission, holding isn't an AMEP verdict.** In `3-retried`, both executions are within the mandate, so the packet is `preserved`. The evidence makes the double execution visible: two `completed` statements with the same `args_digest`. But deciding the second run shouldn't have happened is then the enforcement point's idempotency property, which VATE's PEP comparison covers.
- **With an admission (`5-approved-retried`), AMEP decides it:** the retry spends the admission twice.

## Files

- **`N-*.packet.json`:** the evidence packets.
- **`keys.json`:** the owner, the runtime and the provider.
- **`N-*.verdict.dsse.json`:** the caller's signed verdict for each phase. Its public key is in `verifier-key.json`.
- **To regenerate and check:** run `python3 -I interop/authzen-receipts/vate-01-lost-response/generate.py`. All keys are deterministic test keys.

To check a packet with either reference verifier:

```bash
amep-protocol verify interop/authzen-receipts/vate-01-lost-response/2-recovered.packet.json --keys interop/authzen-receipts/vate-01-lost-response/keys.json
```
