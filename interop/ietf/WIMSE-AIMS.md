# AMEP and WIMSE's AI Identity Management System (draft-ietf-wimse-aims)

**Pinned to:** draft-ietf-wimse-aims-01 (2 November 2026), a WIMSE working-group document: "AI Identity Management System", by Kasselman, Lombardo, Rosomakho, Campbell, Steele and Parecki. The section numbers below are that version's.

**What this is:** a reading of where AMEP's evidence fits in the draft's model. The draft's authors haven't reviewed or endorsed it.

## Where AMEP fits

AIMS defines how agents are identified, credentialed, authenticated and authorized. It lists **Agent Compliance** as a component of the system (section 5): measurement of the state and functioning of the system against the stated policies. Compliance criteria themselves are out of scope (section 13), as are the policy model and document format (section 12).

AMEP is a measurement of exactly that kind, for one question: did what an agent did stay within the authority it was delegated? It works from signed records, offline, with a deterministic answer (`preserved`, `violated` or `unresolved`).

| AIMS section | What it asks for | What AMEP provides |
|---|---|---|
| 4, Agents are workloads | The user or system context an agent acts for is preserved and recorded in audit trails | The principal's mandate and every delegation are signed objects in the evidence. The context is carried, not reconstructed |
| 5, Agent Compliance | Measurement against stated policies | A verdict per call and per packet, naming the invariant and the party that departed first, re-runnable by anyone |
| 10.6, transaction tokens | Scope narrowed at each hop, never exceeding the token presented | The same rule, checked after the fact over the whole chain (I1, spec 7.1), with conformance vectors for each way a hop can widen |
| 11, monitoring | Durable, tamper-evident audit records of authorization decisions | Signed decisions (spec 5.13), and the effects that followed them: what was decided, and what was done |
| 11, revocation without undue delay | Revoked authority not used, even from caches | Revocation evaluated at each effect's own time, not only at the call (I6, spec 5.12), with a propagation window |
| 10.8, human in the loop | Local UI confirmation alone isn't sufficient authorization; more design work may be needed | Approvals bound to the exact executed effect, single use, with presence (`webauthn`, `host_ui`, …) recorded (I8, spec 5.10) |
| 6, unique identifiers | Agents uniquely identified, for auditing and delegation | `actor` on every invocation, and observer independence keyed to the signing key, not the name (I10) |

## Two things AMEP adds that token-based authorization can't show

1. **What actually happened.** A token shows what a call was allowed to do. An effect receipt, signed by the party that executed the call, shows what it did. AMEP compares the two, so a tool that did something other than requested is caught (`violated`, I2).
2. **Unknown outcomes.** When a response is lost and the agent retries under a fresh token, the first attempt's outcome is unknown. AMEP holds the operation, its approval and its budget until that outcome is shown (spec 5.8.1, 5.10, 7.6). So a retry can't quietly run twice.

## Possible contributions to AIMS

- **Section 13:** a pointer to evidence-based compliance measurement, as one way to meet section 5's Agent Compliance component without defining criteria in the draft.
- **Sections 10.6 and 11:** AMEP's vectors for delegation, revocation and retry, as executable checks of the draft's rules on hop narrowing, revocation and retries.
