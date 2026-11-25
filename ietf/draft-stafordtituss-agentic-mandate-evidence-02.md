---
title: "Continuity Evaluation of Agent Delegation Records"
abbrev: "Agent Continuity Evaluation"
category: info
docname: draft-stafordtituss-agentic-mandate-evidence-02
submissiontype: IETF
number:
date:
consensus: false
v: 3
area: "Security"
workgroup: "AUDIT BOF"
keyword:
 - agents
 - delegation
 - audit
 - authorization
 - continuity
author:
 -
    fullname: "Staford Titus Selvaraj"
    organization: "Independent"
    email: "stafordtituss@gmail.com"

normative:
  RFC8785:
  RFC8032:
  RFC3339:
  RFC7493:

informative:
  RFC7942:
  RFC8610:
  RFC8693:
  RFC9052:
  RFC9635:
  I-D.kuehlewind-audit-architecture:
  I-D.birkholz-verifiable-agent-conversations:
  I-D.ietf-scitt-architecture:
  I-D.nelson-agent-delegation-receipts:
  IN-TOTO:
    title: "in-toto Attestation Framework: Statement v1"
    author:
      - org: "in-toto project"
    target: "https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md"
    date: 2026
  DSSE:
    title: "Dead Simple Signing Envelope"
    author:
      - org: "Secure Systems Lab"
    target: "https://github.com/secure-systems-lab/dsse"
    date: 2026
  SOUTH2025:
    title: "Authenticated Delegation and Authorized AI Agents"
    author:
      - name: "Tobin South"
      - name: "Samuele Marro"
      - name: "Thomas Hardjono"
      - name: "Robert Mahari"
      - name: "Cedric Deslandes Whitney"
      - name: "Dazza Greenwood"
      - name: "Alan Chan"
      - name: "Alex Pentland"
    target: "https://arxiv.org/abs/2501.09674"
    date: 2025
  CHAN2025:
    title: "Infrastructure for AI Agents"
    author:
      - name: "Alan Chan"
      - name: "Kevin Wei"
      - name: "Sihao Huang"
      - name: "Nitarshan Rajkumar"
      - name: "Elija Perrier"
      - name: "Seth Lazar"
      - name: "Gillian K. Hadfield"
      - name: "Markus Anderljung"
    seriesinfo:
      "Transactions on Machine Learning Research": "2025"
    target: "https://arxiv.org/abs/2501.10114"
    date: 2025
  DIF-DATM:
    title: "Threat Model for Delegated Authority in AI-Mediated Systems"
    author:
      - org: "Decentralized Identity Foundation, Trusted AI Agents Working Group"
    target: "https://identity.foundation/delegated-authority-threat-model/"
    date: 2026
  DIF-DAE:
    title: "Delegated Authority Evaluations"
    author:
      - org: "Decentralized Identity Foundation, Trusted AI Agents Working Group"
    target: "https://identity.foundation/delegated-authority-evaluations/"
    date: 2026
  NCCOE-AGENTS:
    title: "Accelerating the Adoption of Software and Artificial Intelligence Agent Identity and Authorization (Concept Paper)"
    author:
      - org: "NIST National Cybersecurity Center of Excellence"
    target: "https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization"
    date: 2026
  AGENTDOJO:
    title: "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents"
    author:
      - name: "Edoardo Debenedetti"
      - name: "Jie Zhang"
      - name: "Mislav Balunović"
      - name: "Luca Beurer-Kellner"
      - name: "Marc Fischer"
      - name: "Florian Tramèr"
    seriesinfo:
      "NeurIPS Datasets and Benchmarks Track": "2024"
    target: "https://arxiv.org/abs/2406.13352"
    date: 2024
  CAMEL:
    title: "Defeating Prompt Injections by Design"
    author:
      - name: "Edoardo Debenedetti"
      - name: "Ilia Shumailov"
      - name: "Tianqi Fan"
      - name: "Jamie Hayes"
      - name: "Nicholas Carlini"
      - name: "Daniel Fabian"
      - name: "Christoph Kern"
      - name: "Chongyang Shi"
      - name: "Andreas Terzis"
      - name: "Florian Tramèr"
    target: "https://arxiv.org/abs/2503.18813"
    date: 2025
  FINOS-421:
    title: "How should agent authorization carry across institutions? (AI Governance Framework, issue 421)"
    author:
      - org: "FINOS AI Governance Framework contributors"
    target: "https://github.com/finos/ai-governance-framework/issues/421"
    date: 2026
  AMEP:
    title: "Agentic Mandate Evidence Protocol (AMEP) v0.3.0-draft.1"
    author:
      - name: "Staford Titus Selvaraj"
    target: "https://github.com/stafordtituss/amep"
    date: 2026

--- abstract

The AUDIT architecture defines records that capture the user's intent, delegation, authorization state, and the actions that agents take across trust boundaries. Records alone don't answer the question an auditor, an operator, or a relying party asks next: did what was executed stay within the authority the user delegated?

This document defines a deterministic, three-valued evaluation over such records. The outcomes are preserved, violated, and unresolved. A violated outcome names the invariant that was broken and the party whose own signed record departed from authority first. An unresolved outcome names the evidence that is missing; missing evidence is never treated as success. The document also defines the claim model the evaluation needs, the roles permitted to sign each record, a signed statement of what a call did or did not execute, a portable verdict record, a mapping onto the AUDIT record types, and interoperable test vectors. It is derived from the Agentic Mandate Evidence Protocol (AMEP).

--- middle

# Introduction

AI agents act through chains of delegation: a user to an agent, an agent to sub-agents, and agents to tools, adapters, and services. Each hop can widen what is done relative to what was asked. Common examples:

- an approval for one command is reused for another;
- a sub-agent receives broader scope than its parent held;
- untrusted content steers a mutation;
- an adapter maps a tool call to an effect that differs from the one declared;
- a gateway refusal is later read as an executed action, or a lost response is read as a failure;
- a decision made after the fact, from an audit log, is presented as if it had prevented the action.

{{I-D.kuehlewind-audit-architecture}} defines Interaction, Action, Delegation, and Authorization Transition records, and the propagation of audit context, so that these chains can be reconstructed. Its Auditor role determines whether recorded behaviour matched the authorization in force at the time.

This document specifies that determination. Given a set of records, it specifies:

1. a **claim model** that makes delegated authority machine-checkable ({{claims}});
2. **signer roles**, so that a record counts as evidence only when it is signed by a party entitled to make it ({{roles}});
3. **call statements**, so that "nothing was executed" and "the outcome is unknown" are distinguishable from each other and from an executed action ({{statements}});
4. **invariants** that a chain of records must satisfy (I1 to I11);
5. a deterministic **evaluation procedure** that returns preserved, violated, or unresolved, with the deciding invariant, the party at fault, and the missing evidence ({{evaluation}});
6. a portable, signed **verdict record**, so that a second auditor can check a first auditor's conclusion ({{verdicts}});
7. **test vectors**, so that independent verifiers can demonstrate that they agree.

The evaluation can run before an effect, when an enforcement point decides on the predicted effect, or after the fact, when an auditor evaluates recorded effects. It never treats missing evidence as success, and it never treats a post-execution decision as a block.

## Requirements Language

{::boilerplate bcp14-tagged}

## Terminology

This document uses the roles of {{I-D.kuehlewind-audit-architecture}}: User, Agent, Tool/Service, Auditing Service, Audit Store, Transparency Log, and Auditor. It adds:

Mandate:
: a signed claim set issued for a principal, stating what an agent may do on the principal's behalf.

Intent:
: an optional claim set derived from a single request (for example, a prompt), narrower than the mandate.

Invocation:
: a declared call to a tool or service, made under a mandate (possibly delegated).

Effect:
: what was actually executed at the boundary where the action took effect.

Observer:
: the party that produced the effect record or call statement.

Call statement:
: the observer's signed account of one call: what it executed, or that it executed nothing, and how many effect records belong to the call.

Packet:
: the set of records a verifier evaluates together.

Verifier:
: an entity that runs the evaluation in {{evaluation}}.

# Relationship to the AUDIT Architecture {#mapping}

| This document | AUDIT record type | What is evaluated |
|---|---|---|
| Mandate, Intent | Interaction Record (prompt, signed grant) | claim set C ({{claims}}) |
| Delegation | Delegation Record | attenuation, I1 |
| Approval | Interaction Record (approval, HITL escalation) | binding to the exact effect or effects, I8 |
| Invocation and interpretation | Action Record (declared) | interpretation provenance (I3), influence (I4) |
| Effect | Action Record (at the effect boundary) | I2, I5, I9, I10, I11 |
| Call statement | Action Record (call outcome, including "not executed") | I7, I11, binding to the exact invocation |
| Grant, revocation, status | Authorization Transition Record | liveness at the invocation and at each effect, I6 |
| Verdict record | (none) | the output of this document ({{verdicts}}) |

Mandates and delegations commonly originate in OAuth 2.0 Token Exchange chains {{RFC8693}}. Records MAY be carried as COSE_Sign1 objects {{RFC9052}}, and MAY be registered with a transparency service {{I-D.ietf-scitt-architecture}}, which makes selective omission of records detectable. Conversation records such as {{I-D.birkholz-verifiable-agent-conversations}} can supply the Interaction Records from which mandates, intents and approvals are taken.

This document doesn't define new transport or storage. It requires only that records carry the fields listed in {{fields}}, and that records can be linked using the AUDIT audit context: trace, parent, actor, and on-behalf-of.

# Related Work {#related}

Most related work grants or checks authority before an agent acts. This document evaluates whether what was executed stayed within that authority, and the two are complementary.

- The Delegation Receipt Protocol {{I-D.nelson-agent-delegation-receipts}} has the user sign an authorization object that is checked before execution. Such an object can serve as the mandate whose claims this document evaluates.
- Authenticated delegation for AI agents {{SOUTH2025}} proposes scoped, verifiable delegation credentials that extend OpenID Connect and OAuth 2.0. Those credentials are another source of mandates and delegations. GNAP {{RFC9635}} negotiates delegated authorization across multiple parties; its grants can likewise be recorded as mandates.
- Work on infrastructure for AI agents {{CHAN2025}} identifies attribution and incident response as functions that require shared infrastructure outside the agent. The evaluation in {{evaluation}} supplies one verifiable input to both.
- The DIF threat model for delegated authority {{DIF-DATM}} argues that delegated authority commonly fails at the moment of action rather than at issuance, and asks for execution-time evaluation. {{DIF-DAE}} compares existing authorization specifications against a set of criteria. This document addresses the execution-time and after-the-fact evaluation those documents call for, and does not define a new credential format.
- The NCCoE concept paper on agent identity and authorization {{NCCOE-AGENTS}} covers identification, authorization, auditing, and non-repudiation for agents using existing standards. The records and outcomes defined here are one way to make the auditing and non-repudiation goals checkable.
- Prompt-injection benchmarks and defenses, such as AgentDojo {{AGENTDOJO}} and CaMeL {{CAMEL}}, detect or prevent untrusted content from steering an agent. When such steering produces an effect outside the user's mandate, this document reports it as violated (I2 or I4), independent of how the injection was detected.

# Claim Model {#claims}

A claim set is C = (G, A⁻, R⁻, D, E, V, P, K, B, L, U), where:

- G is the set of grants. Each grant is a pair (A, R) of canonical action and resource patterns, and permits its actions on its resources. A claim set with plain action and resource lists has one grant. A list of grants expresses permissions such as "read the documents, write the reports" that a single product of actions and resources cannot express without also permitting "write the documents";
- A⁻ and R⁻ are sets of action and resource patterns that are denied even when a grant would permit them;
- D is a set of (data class, recipient class) pairs;
- E is the effect ceiling, an element of the totally ordered set `read < write_local < write_shared < external_send < destructive < financial`;
- V is the validity interval;
- P is the purpose;
- K is the delegation budget (remaining depth);
- B is an OPTIONAL risk budget in points;
- L is an OPTIONAL list of limits on quantities ({{limits}});
- U is an OPTIONAL set of audience patterns: the services at which the authority may be exercised.

C1 ⊑ C2 (C1 is equal to or narrower than C2) holds if and only if: every grant of C1 lies within a single grant of C2 (its actions subsumed by that grant's actions and its resources by that grant's resources); every pattern in A2⁻ and R2⁻ is subsumed by some pattern in A1⁻ or R1⁻ respectively (denies only grow); D1 ⊆ D2; E1 ≤ E2; V1 ⊆ V2; P1 = P2 or P2 is unrestricted; the depth rule holds (if K2 is present, K2 > 0 and K1 < K2); B1 ≤ B2 when B2 is present; no limit of C1 is higher than a limit of C2 in the same unit, actions and period; and, when U2 is present, U1 is present and every pattern of U1 is subsumed by a pattern of U2. A child MAY add limits.

The meet C1 ⊓ C2 takes the pairwise intersection of grants and is otherwise taken component-wise, with denies unioned so that no hop and no intent can lift a deny.

Resource identifiers MUST be canonical. File-system paths MUST be absolute and normalized, with the home directory expanded and ".." collapsed. URLs MUST carry their resolved host class. SaaS objects MUST be identified as `provider:type/id`. A verifier MUST NOT rely on user-relative forms.

An effect is x = (a, r, d, e, t, v, u), where v is an OPTIONAL quantity and u the OPTIONAL audience the effect was sent to. x ⊨ C if and only if some grant of C permits both a and r, a matches no pattern of A⁻, r matches no pattern of R⁻, e ≤ E, every released (data class, recipient class) pair is in D, t ∈ V, and, when U is present, u matches a pattern of U. When U is present and the effect record names no audience, the result is unresolved (I7). Without U, a presentation bound to one service and replayed to another, with an action and resource in scope, would satisfy the claims.

A claim set that carries a member this document does not define, and that is not an extension member, makes the result unresolved (I7): ignoring a member that narrows authority could widen it.

## Limits {#limits}

A limit caps a quantity of one unit, such as `iso4217:EUR`, an asset, or `count:records`, with an OPTIONAL maximum per effect, per call (the total of one invocation's effects), and per period (a total within fixed windows of a stated length, starting at the node's validity start). An effect's quantity is an exact decimal string and a unit. Amounts are compared exactly, never as floating point.

1. For every node on the chain that carries limits, every limit that applies to an effect is checked before the result is decided. A violation takes precedence over an unresolved check, so the result does not depend on the order in which limits are listed.
2. A period total is the verifier's running total for the window, including state carried from earlier packets ({{state}}). A period total reported by an observer counts only if the limit names that observer as the one that counts all of the node's spending in the unit, and only if the observer's figure states the start of the window it covers and that start equals the limit's window start. An observer's figure for a different window would otherwise understate the limit's total, or blame an honest observer.
3. Without such a figure and without earlier state for the window, the period total is unknown, and the result is unresolved (I7). A packet's assembler can leave out earlier effects, so a period total is never assumed to start at zero.
4. An approval that passed I8 authorizes its effect to exceed a limit. The approved amount still counts toward the period total.

# Signer Roles {#roles}

A valid signature shows only that a key signed a record. Each key in the verifier's key set carries roles, and a record counts as signed only when its key holds a role permitted for the record's kind:

| Record | Permitted signer roles |
|---|---|
| Mandate, revocation, revocation status | issuer |
| Delegation, intent | issuer, host |
| Interpretation, invocation, decision | host |
| Effect, call statement | observer |
| Approval | approver |
| Content finding | host, observer |

Without roles, a compromised host key could mint its own mandate or approve its own action.

A key that is revoked, or used outside its validity interval, signs nothing: a record signed with it is treated as unsigned, and the cause is reported (missing, unknown key, role, key status, or invalid signature, in that order). A record is placed in the interval by its own time.

For observer independence (I10), the actor is identified by the key that signed the invocation, not by the names in the records. A record signed by the invocation's own key is the actor's, whatever observer it names, and where the key set names operators, a record signed by a key of the host's operator is the host's.

Ed25519 {{RFC8032}} signatures are accepted under one exact rule in every verifier. A verifier MUST reject a signature whose scalar S is not less than the group order, and a public key or commitment R whose encoding is non-canonical or is a point of small order. Libraries otherwise differ on these edge cases (one accepts a signature by the identity key over every message), and two verifiers would then disagree on the same record.

# Call Statements {#statements}

An effect record says what was executed. It cannot say that nothing was. A **call statement** is the observer's signed account of one call: its disposition (completed, not executed, or failed after the effects it counts), the number of effect records it issued for the call, and OPTIONALLY the digest of the exact signed invocation and of the arguments it received.

1. A statement that does not verify, has an unknown disposition, or says "not executed" while counting effects, makes the result unresolved (I7).
2. A statement or effect record bound to a different invocation (by invocation digest) is not evidence for this one: unresolved (I7). A genuine record for one call therefore cannot be presented for another call that reuses its identifier.
3. If the arguments the observer received differ from those the host signed, the call was changed in transit: violated (I2), or unresolved (I7) when nothing was executed.
4. An effect record for a call the observer says was not executed is equivocation: violated (I11).
5. With no effect records and a verified "not executed" statement, the call provably had no effect, and the result is preserved. For a call at or above `write_shared`, the statement must come from a party other than the actor; otherwise unresolved (I10).

Without a call statement, an invocation with no effect record is unresolved (I7): the effect may have happened. A refusal by a gateway is therefore recorded as a "not executed" statement signed by the gateway, never as an absence of records.

# Operation Identity {#operations}

An agent whose call has an unknown outcome may retry it, often under a fresh authorization. Without a record that the retry is the same logical operation, both attempts are evaluated independently, and an operation that took effect twice breaks no rule. An invocation MAY therefore carry an operation identifier, the same on every attempt.

1. An operation takes effect at most once. A second attempt that takes effect is violated (I2), blamed on the agent.
2. An attempt with no effect record and no "not executed" statement holds its operation. A later attempt of a held operation is unresolved (I7), naming the holding attempt, whatever authorization it carries.
3. A hold is released only by a showing that another party can check: for a call at or above `write_shared`, a "not executed" statement that meets I10. A statement signed only on the actor's side releases nothing.

Checks that decide violated come before any check that can only hold, so that no hold hides a double use. A call that is violated is charged once, for its first violation; if a later packet resolves that violation, its use of an approval is counted again. The identifier is chosen by the party that retries, so it binds only what that party records.

# Invariants

| ID | Invariant | When broken |
|---|---|---|
| I1 | Attenuation: child ⊑ parent at every delegation edge | violated |
| I2 | Every effect matches the declared (or mediated) effect, satisfies the meet of the chain (and of the intent), and stays within limits and risk budgets unless a bound approval covers it | violated |
| I3 | The invocation was interpreted by an approved, version-pinned mapping | unresolved |
| I4 | Content withheld by a quarantine did not reach a later step; a mutation influenced by content that is not signed and trusted was confirmed by the principal | violated (executed) or unresolved |
| I5 | Data classes released to a recipient are permitted | violated |
| I6 | No ancestor was revoked, per signed revocation or status evidence, at or before the invocation or the time of any of its effects | violated (unresolved inside a declared propagation window) |
| I7 | All required records are present, well-formed, signed by a permitted role, bound to the call they describe, and fresh where required | unresolved |
| I8 | An approval matches the executed effect, or each effect of one call, without its time; is within its validity window, unconsumed, and used once | violated |
| I9 | No agent effect targets guardrail configuration, keys, instruction files, or the audit store | violated |
| I10 | An effect at or above `write_shared` names its actor and was observed by a party other than that actor | unresolved |
| I11 | Every recorded effect links to an authorized invocation, none exists for an invocation a pre-execution decision denied, and none contradicts a "not executed" statement | violated |

# Evaluation Procedure {#evaluation}

For each invocation, in recorded order, a verifier MUST apply the following checks in order and return the first outcome that applies, except where a group is marked as checked in full. "Verified" means signed by a key holding a permitted role ({{roles}}).

~~~
ID   Outcome     Condition
I4   violated    quarantined content in the influence set,
                 not confirmed by the principal
I7   unresolved  no root mandate
I7   unresolved  cited intent missing, or a needed record
                 not verified
I7   unresolved  lineage names an invocation that is not earlier
I7   unresolved  malformed limits or reserve, or a claim member
                 the verifier does not implement
I3   unresolved  no approved interpretation, or a pin mismatch
I1   violated    a delegation edge where not (child ⊑ parent)
I6   unresolved  revocation inside the revoked node's declared
                 propagation window
I6   violated    verified revocation or status shows an ancestor
                 revoked at or before the invocation
I7   unresolved  unverified revocation on the chain, or a
                 revocable record without a fresh verified status
I9   violated    guardrail target
I4   violated    untrusted influence on a mutation, unconfirmed
                 (unresolved instead if no effect exists)
     Call statements (see Call Statements), rules 1 to 5
I7   unresolved  no effect record (the call is held; see
                 State Across Packets)
     For every effect record of the invocation:
I7   unresolved    record not verified, names no observer, or is
                   bound to a different invocation
I10  unresolved    e >= write_shared and the actor is absent,
                   the effect is self-observed, or assurance L0
I6   violated      revoked at or before the effect's own time
                   (unresolved inside a propagation window, or
                   when status is not fresh as of that time)
I2   violated      executed != declared (and != the mediated
                   effect)
I9   violated      executed resource is a guardrail
I2   violated      x does not satisfy the meet of the chain and
                   intent (I5 when the failure is a release)
I5   violated      data classes carried in through lineage reach
                   a recipient class the claims do not permit
I7   violated    more effect records than the call statement counts
I7   unresolved  fewer effect records than it counts
I7   unresolved  approval missing or not verified
I8   violated    approval unbound, outside its window, consumed,
                 reused, or covering an effect fewer times than
                 it was executed
     Limits (see Limits), every applicable limit checked in full:
I2   violated      over a per-effect, per-call or per-period
                   limit without a bound approval
I7   violated      the counting observer's total for the window
                   is below the effects recorded
I7   unresolved    period total unknown, or held calls could
                   take it over the limit
I7   violated    recorded budget spend != recomputed cost
I2   violated    risk budget exceeded without a bound approval
-    preserved   otherwise
~~~

After all invocations:

~~~
ID   Outcome     Condition
I11  violated    pre-execution deny/hold decision, and an effect
                 exists (enforcement contradicted)
-    preserved   pre-execution deny/hold decision, no effect,
                 enforcement fail-closed or applied = confirmed
I11  violated    effect with no invocation
~~~

The packet verdict is the first violated result if there is one, else the first unresolved result, else preserved.

Lineage: an effect may record the data classes it read (accessed) and the recipient class of what it sent; an invocation may name the earlier invocations its input came from (derived_from). The data classes an invocation carries are those its own effects read plus those carried by the invocations it derives from, transitively. This detects sensitive data leaving in a later step even when that step declares no release.

Decisions carry a phase: pre_execution, post_execution, or simulation. Only pre-execution decisions can confirm or contradict a block. A post-execution decision is detection and MUST NOT be presented as having prevented the action.

When B is present, the cost of x is base(e) × m(d) × rev(x). The base table is read 0, write_local 1, write_shared 3, external_send 5, destructive 10, financial 20. m(d) is the largest data-class multiplier among the released classes (1, 2, or 5). rev(x) is 1 if the effect is a read, or reversible and not an external send, and 3 otherwise. The cost is charged to every node in the chain. The tables are registries ({{iana}}).

## Approvals {#approvals}

An approval binds the digest of the exact effect it approves: SHA-256 over the JCS {{RFC8785}} form of the effect without its time and without any observer's running totals, so that it can be issued before execution. An operation approval instead lists the digests of the effects of one call, for example an operation that writes two files. Every executed effect of that call must be listed, and no effect may run more often than it is listed. Either form is single use: a retry that cites it again is violated (I8).

## Results: Blame and Missing Evidence {#blame}

Each result carries two further members, derived only from the signed evidence. A verifier MUST NOT infer blame the evidence does not show.

- **blame** (violated results only) names the party whose own signed record is the first to depart from authority: `agent` (it asked for or acted on something not allowed), `delegator` (a delegation widened its parent), `host` (the host or enforcement point failed at its own role), `transport` (the arguments received differ from those signed), or `server` (the executing party's records contradict the authorized call or each other).
- **gaps** (unresolved results only) lists the evidence that would let the evaluation continue, each as a need and the identifier of the record concerned, for example a missing effect record, a fresh revocation status, an independent observer, or the outcome of a held call.

## State Across Packets {#state}

A verifier evaluating a stream of packets MAY carry state from one packet to the next: approval use, risk-budget spending, and per-window period totals. Within one stream, state MUST be passed in time order.

A verified invocation that ends a packet with no effect record and no "not executed" statement may still have executed. Its outcome is unknown, and the verifier records a **hold** in its state against every period limit on its chain that applies to it: the amount the invocation declared as the most it can move, or an unknown amount if it declared none. In later packets, every hold whose invocation is not in that packet counts toward the same window's total. A total that could exceed the limit with the holds added, or an unknown held amount, makes the result unresolved (I7), never violated, because the held call may not have executed. A later packet that contains the held invocation replaces its hold: its effect records then count as any other, a "not executed" statement releases it, and a hold is never counted twice. Only a verified invocation can be held, so evidence that does not verify cannot place holds.

This follows the requirement, raised in a cross-institution example of delegated payment authority {{FINOS-421}}, that a slice with an unknown outcome stays counted until reconciliation shows whether it was booked.

State is the verifier's own bookkeeping, not evidence. A verifier that relies on it SHOULD publish the state it used alongside its verdict records.

# Verdict Records {#verdicts}

A verifier MAY publish what it concluded as a verdict record: the predicate of an in-toto Statement v1 {{IN-TOTO}} whose subject is the SHA-256 of the exact packet bytes evaluated, or, when the evaluated actions produced an artifact that a policy admits, that artifact, with the packet's digest kept in the predicate. The predicate gives the SHA-256 of the JCS form of the key set, the packet verdict, and every result in evaluation order, each with its outcome, invariant, blame and gaps. Free-text reasons are excluded, because they differ between implementations.

Two conforming verifiers given the same packet and key set MUST produce byte-identical JCS forms of the record once the member naming the implementation is removed. A verdict record is therefore re-derivable: a party that trusts neither the agent nor its operator, nor the first auditor, can evaluate the same packet and compare. A signed verdict record is the statement carried in a DSSE envelope {{DSSE}}, signed with Ed25519.

A verdict record is one verifier's reading of the evidence, not evidence of what the agent did. In a dispute, the packet is the evidence.

# Required Fields {#fields}

The evaluation needs the following fields from each AUDIT record. Field names are placeholders until the AUDIT data model is defined.

- Mandate, Intent, and Delegation: id, parent, issuer, claims (C), signature.
- Invocation: id, authority reference, interpretation reference (adapter and version), declared effect, actor, influence references, approval reference, time; OPTIONALLY the digest of the arguments sent, and the most the call can move (its reserve).
- Effect: id, invocation reference, OPTIONAL invocation digest, executed effect x, observer, assurance level (L0 self-reported to L3 provider-confirmed), signature. A quantity carries an amount, a unit, and OPTIONALLY the observer's own totals, each with the start of the window it covers.
- Call statement: id, invocation reference, observer, disposition, effect count, time, OPTIONAL invocation digest and arguments digest, signature.
- Approval: id, effect digest or list of effect digests, presence (webauthn, chat_user, host_ui, or none), validity window, consumed flag, signature.
- Revocation and revocation status: target, time (or as-of time and revocation time), OPTIONAL propagation window on the revocable node, signature.
- Continuity decision: invocation reference, mode, phase, outcome, enforcement context (enforcement point, fail mode, what was returned to the host, whether an effect record confirms it), signature.

Records are canonicalized with JCS {{RFC8785}} and signed with Ed25519 {{RFC8032}} over a domain-separated signing input. Times are numbers of seconds since the epoch or RFC 3339 {{RFC3339}} strings. A CDDL {{RFC8610}} definition and JSON Schemas are published in {{AMEP}}.

A packet that is not well-formed I-JSON {{RFC7493}} within the bounds the specification sets (duplicate member names, numbers outside the safe-integer range, lone surrogates, excessive nesting) makes every invocation in it unresolved (I7): such a packet cannot be canonicalized to the same bytes by every verifier. Values whose exact identity matters, such as amounts and identifiers, SHOULD be strings.

A packet MAY declare the version of the rules it was produced for. A verifier MUST treat a packet declaring a version it does not implement as malformed.

# Test Vectors

{{AMEP}} publishes three suites of signed packets, each with an expected outcome and invariant: 261 core vectors (69 positive and 192 must-reject), 16 approval-path vectors, and 20 delegation-continuity vectors, 297 in all. The must-reject vectors cover all eleven invariants, signer roles, the Ed25519 acceptance rule, malformed I-JSON, revocation at the time of each effect, call statements and binding, key status, operation identity, audience binding, operation approvals, grants, limits checked independently of their order, observer totals for the wrong window, held calls across packets, decision phase, deny lists, data lineage, and state across packets.

Two implementations written separately by the author (Python, and JavaScript run under Node.js and in a browser) agree on all 297, on the outcome, invariant, blame and gaps of every result, and produce byte-identical verdict records. An implementation by another party, zambo-amep-verify (Brennan Zambo), written from this document's source specification and the vectors alone, agrees on all 228 single-packet core vectors of an earlier suite. The hold and single-use rules have also been checked exhaustively against a model of them, over every reachable state with three calls. A conformance tool runs any verifier that can be invoked from a command line against all three suites.

A conforming verifier MUST return the expected outcome and invariant for every vector.

# Implementation Status

**Note to the RFC Editor:** please remove this section before publication, per {{RFC7942}}.

- **AMEP reference verifiers.** Two implementations, both by the author: Python (package amep-protocol 0.3.0a2) and JavaScript (package @stafordtituss/amep 0.3.0-alpha.2, published with build provenance), the latter also run as an offline browser page using WebCrypto. Both evaluate the procedure in {{evaluation}}, agree on all 297 published vectors, and produce byte-identical verdict records. License: Apache 2.0. Location: https://github.com/stafordtituss/amep. Maturity: prototype.
- **AMEP conformance tool and import profiles.** It runs a verifier against the suites, and re-expresses records of other formats as evidence after checking them by their own rules: AER-1 receipts, OpenID action receipts, and Provared permission books. It also compares AMEP's results with the published test vectors of the Delegation Receipt Protocol and of EMILIA Protocol authorization receipts. Location: as above.
- **AMEP MCP server.** Exposes the verifier and the suites to MCP clients; listed in the MCP Registry. Location: as above.
- **Natsar control plane** (agent-authority enforcement for coding-agent hosts and MCP). It emits decision records before tool execution from host hooks. Maturity: pre-release.

Use and review by other parties, each in a public record:

- **zambo-amep-verify (Brennan Zambo).** An independent verifier, written from the specification and the vectors alone, without reading either reference verifier. It agrees on all 228 single-packet core vectors of an earlier version of the core suite. His review of operation identity tightened what releases a hold.
- **OpenID AIIM list review (Andrii, Radiolaria).** Found that revoked keys were accepted, that a producer reported "not executed" after an exception with nothing recorded, and that a retry under fresh authorization started clean. These led to key status and operation identity.
- **Agent Payments Protocol.** Two other verifiers, AER-1 and APAF-1, were run over the same pinned AP2 payment fixtures as this one, and the results were joined row by row. The comparison found that the fixtures lacked the payment-to-checkout reference, which led to checkout binding.

- **AER-1 (Brennan Zambo).** An import run over twelve live receipts from a production MCP server, with the implementer's own tool map. It found that a gateway refusal was imported as an executed effect; the importer was corrected. A later run over two re-issued records was blind, with the expected results committed before either side ran it, and both sides' results matched.
- **Verifiable Agent Trust Envelope (Takao Sato).** The maintainer verified the signatures of five published verdict records for a lost-response and recovery case, matched each to its packet by digest, and reviewed a reference example of the case. Evaluations of two further cases (interrupted work, and confirmed non-execution with a handoff) are published beside the project's own expected results; the second led to holding approvals while an outcome is unknown.
- **Payments review (Carlos Vendrell Felici, Zealynx Security).** Two rounds of review of the quantity limits, with signed test packets run through both verifiers. They led to the per-call and per-effect limits, per-observer counting of effects, the counting observer, integer amounts for on-chain assets, independent totals per limit, order-independent evaluation of limits, and observer totals that name their window.
- **AUDIT mailing list review (Cliff Singletary).** Led to evaluating revocation and status freshness at the time of each effect, not only at the invocation.

Implementation experience motivated several parts of this document: canonical resource identifiers (absolute-path forms bypassed relative-prefix rules); recording the enforcement context and phase (hosts differ in whether they support "ask" and whether hook failures block); treating an effect that contradicts a deny as evidence of bypass; and the call statement, without which a refusal and a lost response are indistinguishable from each other.

# Security Considerations

- **Adversarial models:** the guarantees MUST hold even if every model in the chain is adversarial. Semantic analysis MAY raise a decision level, but MUST NOT mint authority or lower a decision.
- **Self-reporting:** records produced by the actor alone are insufficient for high-impact effects, including a statement that nothing was executed (I10).
- **Key compromise:** signer roles ({{roles}}) limit what one stolen key can forge.
- **Evidence omission:** a missing record, status or signature yields unresolved. A call with no outcome is held across packets ({{state}}), so leaving its outcome out of later packets cannot make a later total look clean. Omission of whole invocations is detected only against an independent effect log (I11).
- **Record substitution:** binding effect records and call statements to the digest of the exact invocation prevents a genuine record for one call from being presented for another.
- **Canonicalization:** non-canonical resource forms and non-canonical JSON enable bypasses and disagreement between verifiers. Canonicalization is therefore normative.
- **Approval replay and time-of-check/time-of-use:** approvals bind the exact effect or effects and are single use (I8). Liveness is checked at the time of each effect, not only at the invocation (I6).
- **Fail-open enforcement:** an enforcement point that errors MUST return a deny decision, not a transport error. A verifier SHOULD treat an effect that contradicts a pre-execution deny as evidence of bypass.
- **Guardrail tampering:** agent writes to hook configuration, keys, instruction files, or the audit store are violations (I9).
- **Verdict records:** a verdict record is a claim by its signer. Relying parties SHOULD re-derive it from the packet, which the determinism in {{verdicts}} allows.

# Privacy Considerations

Effect records can contain personal data. Verifiers need only canonical actions, resource identifiers, data-class labels, quantities, and digests. Payloads SHOULD be detached and hashed, following the AUDIT selective-disclosure work. A verdict record names packets by digest and carries no payload.

# IANA Considerations {#iana}

This document proposes registries for effect classes, data classes, recipient classes, signer roles, call statement dispositions, blame values, gap names, and the risk-cost tables, with the registration policy Specification Required. The registries are to be defined in a later revision.

--- back

# Changes from -01
{:numbered="false"}

- Operation identity: a retry cannot take effect unnoticed under fresh authorization ({{operations}}).
- Audience binding in the claim model ({{claims}}).
- Key status: revoked or out-of-interval keys sign nothing; signature causes reported in a fixed order ({{roles}}).
- Observer independence keyed to the signing key, not to names ({{roles}}).
- Holds never hide a violation; a violated call is charged once.
- Verdict records MAY name the admitted artifact as subject ({{verdicts}}).
- Test vectors: 297 in three suites; Implementation Status updated with an independent implementation and further reviews.

# Changes from -00
{:numbered="false"}

- Claim model: grants (a union of action and resource products) and limits on quantities ({{claims}}).
- Call statements: a signed "not executed", effect counts, and binding of records to the exact invocation and arguments ({{statements}}).
- I6 at the time of each effect, with an optional propagation window.
- Operation approvals over the effects of one call ({{approvals}}).
- Blame and missing evidence on every result ({{blame}}).
- Holds for calls whose outcome is unknown, across packets ({{state}}).
- Verdict records ({{verdicts}}).
- Ed25519 acceptance rule; malformed I-JSON handling; versioning.
- Test vectors: 269 in three suites; Implementation Status updated with use and review by other parties.

# Acknowledgments
{:numbered="false"}

This document is derived from the Agentic Mandate Evidence Protocol (AMEP), designed and written by the author.

The author thanks Cliff Singletary for the review on the AUDIT mailing list that led to evaluating liveness at the time of each effect; Carlos Vendrell Felici for two rounds of review of the quantity limits; Brennan Zambo for the AER-1 runs, including the blind run; Takao Sato for verifying the verdict records of the lost-response case and the review behind operation approvals; the participants in the FINOS AI Governance Framework discussion of cross-institution authorization, whose requirement for unknown outcomes led to holds; Brennan Zambo, also, for the first independent implementation and for the review of operation identity; Andrii (Radiolaria) for the reports that led to key status and operation identity; Takao Sato, also, for the interrupted-work and handoff cases; nmatt1 for the APAF-1 column and the payment-reference finding; Tom Farley for the protect-mcp wire format; Sankalp Gilda for the subject of verdict records; yuzhou for what Teleport's audit events establish; and Tania Aizenman and David Luna for the EvaluationRecord proposal and the accountable-owner cases.
