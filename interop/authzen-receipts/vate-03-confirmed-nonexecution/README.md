# VATE case 3 as AMEP evidence: confirmed nonexecution, and handoff

This is Takao Sato's [VATE case 3](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/3e9c262/reference/authzen-receipt-vectors/cases/03-confirmed-nonexecution-handoff) for [openid/authzen#795](https://github.com/openid/authzen/issues/795), at VATE commit `3e9c262`, written as AMEP evidence.

**The case.**
- The owner admits one operation that writes two files, and runtime-a gets the first ticket.
- **`fenced-handoff`:** the provider confirms that runtime-a's attempt did not execute, and fences it off (a new generation). The work is handed to runtime-b. runtime-a's late submit is denied (`old_generation`), and runtime-b completes the work.
- **`live-worker`:** runtime-a is still live, so the handoff is refused (`busy`). runtime-a then completes the work itself.

**Takao's question:** what has to be established before a continuation is safe? VATE's answer is confirmed nonexecution *and* exclusion of the old worker.

The admission is an AMEP operation approval (spec 5.10) over the digests of both file effects, as in cases 1 and 2.

| Packet | What the evidence holds | AMEP | VATE |
|---|---|---|---|
| **fenced-handoff** | | | |
| `f1-pending` | runtime-a's signed invocation; nothing from the provider | `unresolved` (I7), gap `receipt` | `unresolved`; hold |
| `f2-fenced` | the provider signs `not_executed` for runtime-a's call | `preserved`, "nothing executed"; the admission is released | `confirmed_unexecuted`; conditional continuation |
| `f3-completed` | as `f2`, then runtime-b runs the operation under the same admission; the provider signs both writes | both calls `preserved`; the admission is used once | `completed` |
| `f4-late-write` | as `f3`, and runtime-a's late write lands as well | `violated` (I11), blame `server`; runtime-b stays `preserved` | — (prevented: `old_generation`) |
| **live-worker** | | | |
| `l1-pending` | as `f1` | `unresolved` (I7), gap `receipt` | `unresolved`; hold |
| `l2-busy-rerun` | runtime-b runs while runtime-a's outcome is unknown | runtime-a: `unresolved`, gap `receipt`. runtime-b: **`unresolved`, gap `held_outcome` naming runtime-a's call** | — (prevented: the handoff is refused, `busy`) |
| `l3-completed` | runtime-a's two writes, signed by the provider | `preserved` | `completed` |
| `l4-rerun-after` | as `l3`, then runtime-b re-runs the operation | runtime-b: `violated` (I8): the admission is spent twice | — (prevented) |

"—" marks evidence VATE doesn't record, because its provider prevents it. These rows show what AMEP concludes if an enforcement point lets it through anyway.

## What the evidence establishes

- **Before the provider speaks,** both systems hold (`f1`, `l1`): no observed effect isn't nonexecution.
- **A signed "not executed"** is enough for AMEP to release the admission (`f2`). VATE asks for one thing more: that the old worker is *excluded*, so it can't still write. AMEP has no counterpart to exclusion. That's prevention, and AMEP checks evidence after the fact.
- **If exclusion fails** (`f4`), the late write contradicts the provider's signed statement, and AMEP names the provider as accountable (I11). runtime-b is not blamed: it continued on a signed statement that it had no reason to doubt. Prevention (VATE) and accountability (AMEP) cover the same failure from two sides.
- **A live worker** (`l2`): when the handoff is let through anyway, runtime-b's call is held until runtime-a's outcome is known. That's AMEP's form of VATE's "hold the same logical effect". Once runtime-a has written, a re-run is a double use (`l4`).

## Files

- **`*.packet.json`:** the evidence packets.
- **`keys.json`:** the owner, runtime-a, runtime-b and the provider.
- **`*.verdict.dsse.json`:** the caller's signed verdict record for each packet (spec 10.8), listing every invocation's result. Its public key is in `verifier-key.json`.
- **To regenerate and check:** run `python3 -I interop/authzen-receipts/vate-03-confirmed-nonexecution/generate.py`. It asserts the packet verdict and each invocation's result. All keys are deterministic test keys.
