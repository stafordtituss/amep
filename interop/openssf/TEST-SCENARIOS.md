# Test scenarios for delegated agent authority

**For:** the OpenSSF AI/ML Security WG ([ossf/ai-ml-security#61](https://github.com/ossf/ai-ml-security/issues/61)), as a one-page summary for a 10-minute discussion.

**The question:** whether these cases could become reusable agent-security test scenarios, written in a form that doesn't depend on any one protocol.

## The setting

An agent acts for a person or an organization. Authority passes through one or more delegations to a call. The call has an effect: a push, a payment, a write. Each record is signed by the party that made it.

A checker that sees the records later can conclude one of three things:
- **preserved:** everything stayed within the authority;
- **violated:** a boundary was crossed;
- **unresolved:** a record needed to decide is missing. The missing record is named, and a gap is never read as permission.

## Integrity is not completeness

Every scenario below has records whose signatures verify. The point is what valid signatures *don't* establish.

| # | Scenario | What the records show | Expected | Why it matters |
|---|---|---|---|---|
| 1 | **The only record of the effect is the agent's own** | Within authority, and correctly signed, but signed by the agent's operator | unresolved: no record from a party other than the actor | A self-report is a claim. For high-impact effects, someone other than the actor has to have seen it. |
| 2 | **No record of the effect at all** | Authority and the call are signed; nothing records whether it executed | unresolved: the effect record is missing | The cases a checker most needs to flag are the ones with nothing to verify. |
| 3 | **"Denied", but it happened** | The gateway signs a denial; the system that executes records the effect | violated | The policy decision and the outcome disagree. The decision log alone would say "blocked". |
| 4 | **Authority revoked between the call and the effect** | Valid at the call, revoked before the effect took place | violated | Checking authority at the request isn't enough: what counts is when the effect happened. |
| 5 | **Arguments changed after approval** | A person approved one set of arguments; the effect shows another | violated | An approval binds the exact action. Otherwise "approved" is only a label. |
| 6 | **One approval, executed twice** | Two identical effects in the same second under a single approval | violated | Identical records are two events, not a duplicate delivery. Deduplicating them hides a replay. |
| 7 | **A write nobody accounted for** | An observer below the agent (the host, a hypervisor, the storage layer) lists every write in a scope. One write matches no call. | the evidence is incomplete, or an effect had no authorized call | This is completeness from outside the agent. Without it, a set of evidence can be authentic and still be partial. |

## Where each case lives today

Each scenario is a signed test vector with an expected verdict. Two reference verifiers, Python and JavaScript, agree on all of them; both are by the same author. The vectors are in [stafordtituss/amep](https://github.com/stafordtituss/amep), Apache-2.0.

| # | Vector | Expected |
|---|---|---|
| 1 | `vectors/must-reject/self-reported-high-impact-effect.json` | unresolved |
| 2 | `vectors/must-reject/missing-effect-receipt.json` | unresolved |
| 3 | `vectors/must-reject/deny-contradicted-by-executed-effect.json` | violated |
| 4 | `vectors/must-reject/revoked-between-invocation-and-effect--singletary-case-1.json` | violated |
| 5 | `vectors/must-reject/arguments-rewritten-in-transit.json` | violated |
| 6 | `vectors/must-reject/one-approval--the-approved-payment-executed-twice-in-the-same-second.json` | violated |
| 7 | `packages/conformance/test/fixtures/observed-effect/`, reconciled by `packages/conformance/src/observed-effect.mjs` | an unaccounted write |

Scenario 4 came from Cliff Singletary's review on the IETF audit list. Scenario 6 is one of twelve vectors written by Carlos Vendrell Felici (Zealynx Security). Scenario 7 uses the Observed Effect predicate proposed to in-toto (in-toto/attestation#607, by probityai); its fixtures are copied unchanged under Apache-2.0. `vectors/CREDITS.md` has the full record.

## Others who've run the cases

- **Verifiable Agent Trust Envelope (VATE):** reference cases for confirmed non-execution and late writes are merged upstream. The maintainer reproduced all eight verdicts and verified their signatures.
- **AP2 (agent payments):** two other verifiers judged the same SDK-built fixtures, and the results were joined in public (google-agentic-commerce/AP2#402). One of those verifiers found and fixed a check that had been silently skipped.
- **Provenza (a policy gateway) and Teleport's MCP audit events:** public gap reports map their evidence onto these cases, scenario by scenario.

## Two questions for the WG

1. **Would a protocol-neutral form be useful?** For example: each scenario as a short description, the records it needs (who signs what, and when), and the expected conclusion. That would be independent of AMEP's own encoding, so that other formats can produce their own vectors for it.
2. **Where would scenarios like 1, 2 and 7 fit in the WG's work?** They are the cases where checking signatures passes and the honest answer is still "we can't tell".
