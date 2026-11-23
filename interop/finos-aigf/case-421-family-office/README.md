# The family-office example (FINOS AIGF #421) as signed evidence

[finos/ai-governance-framework#421](https://github.com/finos/ai-governance-framework/issues/421) asks a concrete question:

> A client authorizes a family-office agent to arrange an investment within agreed limits. The agent decides to use two financial institutions and delegates parts of the execution to other agents. [...] how do we establish that the final actions, taken together, still fall within what the client originally authorized?

The thread then adds two requirements to the worked example:
- **Partition before dispatch**, so each institution sees only its slice.
- **Confirm, reconcile and resolve**, with confirmed positions "measured from the institutions' records, not the orchestrator's own count". In the thread's words, "a slice with an unknown outcome stays counted until reconciliation shows it was booked or not booked".

This folder is that example as AMEP evidence: seven signed packets, one per phase. Each has a verdict that both reference verifiers compute the same way. It is test material for the worked example the thread plans, not a proposal for a new control.

## Who signs what

| Party | Key role | Signs |
|---|---|---|
| The client | `issuer` | The mandate: `trade.book` at bank A and bank B, effect class up to `financial`, **USD 10,000,000** in the window |
| The family office's orchestrator | `host` | One delegation per leg (a slice, counted by that institution), and each instruction it dispatches |
| Each institution | `observer` | What it booked: a receipt bound to the digest of the instruction it executed, its own running total for the leg, and a call statement (`completed`, or `not_executed` with zero effects) |

The verdict comes from the institutions' signed records:
- Each leg's limit names the institution that counts it (`counted_by`), so the leg total is that institution's figure.
- The mandate's total is kept by the client's verifier, which holds every leg from the start of the window (`state.json`). Without that state, even phase 1 is `unresolved`: the orchestrator alone can't show the total.

## Phases and verdicts

| Phase | What happened | AIGF | AMEP verdict |
|---|---|---|---|
| `1-within-mandate` | Slices of 6M (bank A) and 4M (bank B); both booked in full | MI-18 | `preserved` |
| `2-over-partitioned` | Slices of 6M and 6M, each within the mandate on its own; bank A books 6M and bank B 5M | RI-24, MI-18 | `violated` I2, blame `agent`: 11,000,000 exceeds the mandate's 10,000,000 |
| `3-leg-outside-mandate` | The plan changes: a 4M leg is delegated to a broker the client never authorized | RI-28, MI-22 | `violated` I1, blame `delegator`: the delegation widens the resources |
| `4-lost-response` | Leg A booked; leg B's 4M instruction was sent and nothing came back | MI-24 | `unresolved` I7, gap `receipt` for `i-b1` |
| `5-retried-after-loss` | As 4, and the agent retried leg B, which booked | MI-24 | `unresolved` I7, gap `receipt` for `i-b1`: the retry doesn't resolve the first instruction |
| `6-reconciled-booked` | Reconciliation: bank B's records show the first instruction booked too | RI-24, MI-24 | `violated` I2: 14,000,000 in all |
| `7-reconciled-not-booked` | Reconciliation: bank B signs that the first instruction never booked | MI-24 | `preserved`: 10,000,000 in all |

Phases 4 to 7 are the thread's confirm, reconcile and resolve lifecycle:
- **Confirm:** a leg counts as executed only with the institution's signed record, bound to the exact instruction.
- **Unknown stays open:** phases 4 and 5 can't be `preserved` while an instruction has no outcome, even after a retry that booked.
- **Resolve:** each outcome comes from the institution's record. If the first instruction booked, the retry made it 14M (phase 6). If it didn't, the client is at exactly 10M (phase 7).

The retry in phase 5 is also why the thread sends breaks to operations rather than to an automatic retry: phase 6 is what an automatic retry costs when the first instruction did book.

## What AMEP checks, and what it leaves to the enforcement point

- **Partition is checked per hop; conservation is checked on what executed.**
  - AMEP's narrowing rule (I1) compares each delegation with its parent. In phase 2, two 6M slices under a 10M mandate both pass it.
  - The over-allocation is caught when the bookings, taken together, exceed the mandate.

  Refusing to dispatch an over-allocated plan is the orchestrator's control (partition and reserve, MI-18). AMEP doesn't treat it as a violation by itself, for two reasons:
  - over-allocation without over-spending is common and permitted (slices are allowances, not reservations, unless the mandate says otherwise);
  - a packet's assembler can leave a sibling delegation out, so a sum over the delegations present could pass when the real sum doesn't.
- **A receiving institution's check** of its own slice (scoped, single-leg delegation, MI-22) is per hop, as in phase 3.
- **Known limitation, across packets.**
  - Within one packet, an instruction with no outcome keeps the verdict `unresolved`, as phases 4 and 5 show.
  - Across packets, AMEP's verifier state does not yet carry the unknown instruction forward. If phase 4 is evaluated alone and the retry then arrives in a later packet on its own, the later packet is `preserved`, though the first instruction may have booked.

  That falls short of "a slice with an unknown outcome stays counted until reconciliation", and is to be fixed in AMEP's verifier state.

## Check it

From the repository root:

```bash
python3 -I interop/finos-aigf/case-421-family-office/generate.py
```

It regenerates every packet, `keys.json`, `state.json` and `verdicts.json`, and asserts each verdict. Each phase can also be checked on its own with either reference verifier:

```bash
amep-protocol verify interop/finos-aigf/case-421-family-office/2-over-partitioned.packet.json \
  --keys interop/finos-aigf/case-421-family-office/keys.json \
  --state interop/finos-aigf/case-421-family-office/state.json
```

The JavaScript CLI (`node packages/js/bin/amep-protocol.mjs verify …`) takes the same arguments and gives the same verdicts. All keys are deterministic test keys.
