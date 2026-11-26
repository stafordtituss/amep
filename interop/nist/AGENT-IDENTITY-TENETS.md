# NIST's design tenets for agent identity, tested after the fact

**Source:** "Design Tenets for Agent Identity Management Systems", NIST Cybersecurity Insights, 27 October 2026 (Harold Booth, Bill Fisher, Ryan Galluzzo, Tom Clancy). NIST says the tenets will be "the guideposts for our agentic demonstrations in the NCCoE". It also says not all of them can be met with today's standards and technology.

**What this is:** an independent reading, not reviewed or endorsed by NIST. For each tenet it gives:
- what AMEP checks, if anything;
- the test vectors that show a departure being caught;
- what AMEP leaves to other systems.

**Why it might help a demonstration:** most tenets describe how a system should be *built*. AMEP checks afterwards whether one *behaved* that way, from signed records, with a verdict anyone can recompute offline. So a demonstration can show the tenets being met as test results, not only as an architecture diagram.

| Tenet | What AMEP checks | Vectors that show a departure caught | Left to other systems |
|---|---|---|---|
| **1. Distinct agent identification** | Every record is signed by a key, and the verifier checks key status at the time of use (spec 12.4). | `mandate-signed-by-a-revoked-issuer-key`, `receipt-signed-by-a-revoked-observer-key` | Issuing the identity, and binding it to workload and configuration (WIMSE, SPIFFE, OAuth) |
| **2. Linking, delegation and attenuation** | A signed chain from the person or organization to each effect. Each delegation must be no wider than its parent (I1). | `revoked-root-with-live-child`, `missing-parent-lineage`, and the I1 vectors in spec Appendix B | Minting the delegated tokens |
| **3. Least and zero standing privilege** | Each effect is judged against the narrowest authority on its chain (I2). Actions and resources outside it are `violated`. | `action-outside-delegated-actions` | Removing standing rights in the identity system |
| **4. Short-lived, revocable authorization** | Authority is judged **at the time of the effect, not of the request** (I6). This includes revocation between a call and its effect, and a declared propagation window. | `revoked-between-invocation-and-effect--singletary-case-1`, `revoked-exactly-at-the-effect-time--singletary-case-2`, `revoked-mid-action--inside-the-declared-propagation-window`, `stale-revocation-status` | Issuing short-lived tokens |
| **5. Human-in-the-loop triggers** | An approval binds the **exact action and its arguments**, records how presence was shown, and is used once (I8). | `arguments-rewritten-in-transit`, `one-approval--the-approved-payment-executed-twice-in-the-same-second`, `operation-approval-covers-a-body-once--executed-twice` | Choosing thresholds, and the review interface |
| **6. Mandates and constraints** | A signed **mandate** from the task originator is AMEP's root object: actions, resources, an effect-class ceiling, limits and validity. Selective disclosure for consumer cases is a proposal (`proposals/amep-proposal-3-selective-disclosure.md`). | `cumulative-spend-exceeds-budget`, `budget-spent-in-earlier-packets`, and the payment-limit vectors | Turning a person's intent into a mandate |
| **7. Separating policy from reasoning** | The verdict reads only signed records and the mandate, never the model's reasoning. A prompt-injected action outside the mandate is `violated`, however it was reasoned. On AgentDojo's reference traces, mandates scoped to the objects each task touches flag 566 of 571 successful injections that take an action (`experiments/agentdojo/`). | the AgentDojo experiment | The enforcement point at run time |
| **8. Deterministic access decisions** | The verdict is deterministic: two reference verifiers, in Python and JavaScript, produce byte-identical results on every vector. Both are by the same author. | `tools/compare_verifiers.py` over the whole suite | The access decision itself |
| **9. Continuous monitoring** | Not monitoring. Verifier state carries totals, held operations and used approvals across packets (spec 10.7), so checks can run continuously over a stream. | `budget-spent-in-earlier-packets` | Anomaly detection |
| **10. Immutable evidence** | The tenet asks for logging that "is independent of the agent". AMEP makes that a checkable rule (I10): a high-impact effect counts only if a party other than the actor's operator recorded it. A record from the actor alone is `unresolved`, never accepted. A denial that's contradicted by an observed effect is `violated` (I11). An observer below the agent can show **completeness**: every write in a scope accounted for. | `self-reported-high-impact-effect`, `high-impact-effect-observed-only-by-a-key-of-the-host-s-own-operator`, `missing-effect-receipt`, `deny-contradicted-by-executed-effect`, `bypass--effect-without-invocation`; the Observed Effect reconciler (`interop/in-toto/OBSERVED-EFFECT.md`) | Append-only storage and transparency logs (SCITT, `interop/ietf/SCITT.md`) |

## Where AMEP adds something the tenets leave open

- **Tenet 4 is judged at the effect, not the request.** A call that was valid when made, but whose authority was revoked before the effect happened, is a departure. A check made only at the request misses it.
- **Tenet 10 separates integrity from completeness.** A tamper-evident log of what the agent's side wrote can be intact and still be missing the effect that matters. AMEP reports such a gap as `unresolved`, naming the missing record. It never reads a gap as success.
- **Tenets 5 and 6 bind the arguments.** An approval or mandate that names an action but not its effect-setting arguments, such as a recipient or an amount, can't show that what ran is what was approved.

## How to run it

The suite is Apache-2.0 at github.com/stafordtituss/amep: signed vectors, each with an expected verdict, plus the two verifiers. Each vector named above is in `vectors/must-reject/`. The specification is an IETF individual Internet-Draft, draft-stafordtituss-agentic-mandate-evidence.
