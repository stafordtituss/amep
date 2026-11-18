# Open research problems

AMEP is an open specification for evidence that AI agent actions stayed within delegated authority. These are problems we would like help with: each one is a self-contained project, suitable for a paper, a thesis chapter, or a substantial contribution. If you start on one, open an issue (or a Discussion) so others can find your work and nobody duplicates it.

**Credit.** Contributors are credited in the release notes and `NOTICE`. A contribution that substantially shapes a specification text or a paper is credited as co-authorship of that text, by agreement. Work you publish yourself is yours; please cite AMEP (`CITATION.cff`).

**Ground rules.** Every normative change needs at least one positive and one must-reject vector that distinguish the new behaviour from the old (spec Section 15.3). CI regenerates the suite, runs both verifiers, validates schemas and CDDL, and checks that the spec's vector index is current.

---

## 1. Revocation under failure and federation

*Raised on the W3C Agent Identity CG list.* Today a missing or stale revocation status yields `unresolved` (I7). Two cases are not yet separated: a revocation **query that failed** (authority unreachable, response unparseable) and a revocation **recorded in another federation** that the verifier's reachable source has not yet seen.

- **Done looks like:** a vector set that keeps the delegation chain fixed and varies only the revocation side; agreed expected outcomes; possibly a distinct reason code for "query failed" within `unresolved`.
- **Starting points:** `interop/w3c-agent-identity/delegation-continuity/` (`stale-status`, `root-revoked-before-action`), spec Sections 5.12 and 10.

## 2. A mechanized claim algebra

The order (⊑), meet (⊓) and satisfaction (⊨) in spec Section 7 are defined in prose and implemented twice. Nobody has proved their properties.

- **Prove:** ⊑ is a preorder; ⊓ is a greatest lower bound with respect to ⊑; adding a hop never widens effective claims (monotonicity); deny lists only grow along a chain; `x ⊨ C₁ ⊓ C₂` implies `x ⊨ C₁` and `x ⊨ C₂`.
- **Tools:** Lean 4, Coq/Rocq, Isabelle, or a model in Alloy/TLA+ as a first step.
- **Done looks like:** a mechanized model in `formal/`, with any discrepancy against the prose reported as an issue. Pattern subsumption (`*` suffixes) is the subtle part.

## 3. A third, independent verifier (Rust or Go)

Two verifiers exist (Python and JavaScript), both written by the specification's author. An implementation by someone else is the strongest test of the specification text: every disagreement is either a bug or an ambiguity.

- **Done looks like:** a verifier that passes `vectors/` and the delegation suite on outcome **and** deciding invariant, written from the specification text rather than by translating the existing code. It would make AMEP's Level 5 (cross-vendor interoperability) real.
- **Report:** every place the specification was unclear to you. That list is as valuable as the code.

## 4. Mutation analysis beyond the evaluator

`paper/eval/mutation.py` mutates the Python evaluator's checks, algebra rules, bounds and verdict logic, and the suite now kills every non-equivalent mutant. Not covered yet:

- canonicalization (RFC 8785) and signature handling;
- the JavaScript evaluator (`packages/js/src/core.mjs`);
- higher-order mutants (two faults at once).
- **Done looks like:** new operators, the surviving mutants they reveal, and vectors that kill them.

## 5. How much can real hosts observe?

AMEP's verdict quality depends on how many effects are observed independently (assurance L2 or L3). Nobody has measured it.

- **Question:** for real agent hosts (coding agents, MCP servers, SaaS integrations), what fraction of tool effects can be observed by a party other than the actor, and how often would a real deployment evaluate to `unresolved`?
- **Done looks like:** an empirical study, even on a handful of hosts or MCP servers, with the instrumentation published.

## 6. Benchmarks that emit evidence

Agent-security benchmarks (for example AgentDojo) measure whether attacks succeed. AMEP can report, per run, whether the executed effects stayed within the user's authority, and which invariant broke.

- **Done looks like:** an adapter that turns benchmark runs into AMEP packets, and a labelled dataset of packets from attacked and defended runs, so that defences can be compared on one portable verdict.

## 7. Token-profile vectors (spec Appendix E.4)

The Biscuit, Macaroon and UCAN profiles map token facts onto claims but have no vectors, because they need a profile-aware verifier built on the reference token libraries.

## 8. Revocation quiescence (Appendix E.2)

In distributed deployments a revocation may still be propagating when an action happens. What window Δ should I6 tolerate, how is it signalled, and how do vectors express it?

## 9. Signed verifier state (Appendix E.3)

Verifier state across packets (approvals used, budget spent) is local bookkeeping. A signed, exchangeable format would let verifiers hand over state. `proposals/amep-proposal-1-evaluation-record.md` is related.

## 10. Workflow-level outcomes (Appendix E.1)

Evaluation is per invocation. Some violations only appear across many invocations (composition, disclosure). Reserved for v0.3; design proposals welcome.

## 11. Lineage completeness (Appendix E.5)

A verifier can check the data lineage it is given but cannot detect lineage a host failed to record. Can a host prove completeness, for example with a transparency log or attested runtime?
