---
title: "Continuity Evaluation of Agent Delegation Records"
abbrev: "Agent Continuity Evaluation"
category: info
docname: draft-stafordtituss-agentic-mandate-evidence-00
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

informative:
  RFC7942:
  RFC8610:
  RFC8693:
  RFC9052:
  I-D.kuehlewind-audit-architecture:
  I-D.ietf-scitt-architecture:
  AMEP:
    title: "Agentic Mandate Evidence Protocol (AMEP) v0.2"
    author:
      - name: "Staford Titus Selvaraj"
    target: "https://github.com/stafordtituss/amep"
    date: 2026

--- abstract

The AUDIT architecture defines records that capture the user's intent, delegation, authorization state, and the actions that agents take across trust boundaries. Records alone don't answer the question an auditor, an operator, or a relying party asks next: did the executed effect stay within the authority the user delegated?

This document defines a deterministic, three-valued evaluation over such records. The outcomes are preserved, violated, and unresolved, and every non-preserved outcome names the invariant that was broken. The document also defines the claim model that the evaluation needs, the roles permitted to sign each record, a mapping onto the AUDIT record types, and a set of interoperable test vectors. It is derived from the Agentic Mandate Evidence Protocol (AMEP).

--- middle

# Introduction

AI agents act through chains of delegation: a user to an agent, an agent to sub-agents, and agents to tools, adapters, and services. Each hop can widen what is done relative to what was asked. Common examples:

- an approval for one command is reused for another;
- a sub-agent receives broader scope than its parent held;
- untrusted content steers a mutation;
- an adapter maps a tool call to an effect that differs from the one declared;
- a decision made after the fact, from an audit log, is presented as if it had prevented the action.

{{I-D.kuehlewind-audit-architecture}} defines Interaction, Action, Delegation, and Authorization Transition records, and the propagation of audit context, so that these chains can be reconstructed.

This document is complementary. Given a set of such records, it specifies:

1. a **claim model** that makes delegated authority machine-checkable (actions, resources, deny lists, data classes, an effect ceiling, validity, a delegation budget, and an optional risk budget);
2. **signer roles**, so that a record counts as evidence only when it is signed by a party entitled to make it;
3. **invariants** that a chain of records must satisfy (I1 to I11);
4. a deterministic **evaluation procedure** that returns preserved, violated, or unresolved, together with the deciding invariant;
5. **test vectors**, so that independent verifiers can demonstrate that they agree.

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
: the party that produced the effect record.

Verifier:
: an entity that runs the evaluation in {{evaluation}}.

# Relationship to the AUDIT Architecture {#mapping}

| This document | AUDIT record type | What is evaluated |
|---|---|---|
| Mandate, Intent | Interaction Record (prompt, signed grant) | claim set C ({{claims}}) |
| Delegation | Delegation Record | attenuation, I1 |
| Approval | Interaction Record (approval, HITL escalation) | binding to the exact effect, I8 |
| Invocation and interpretation | Action Record (declared) | interpretation provenance (I3), influence (I4) |
| Effect | Action Record (at the effect boundary) | I2, I5, I9, I10, I11 |
| Grant, revocation, status | Authorization Transition Record | liveness, I6 |
| Continuity decision | (none) | the output of this document, with its phase |

Mandates and delegations commonly originate in OAuth 2.0 Token Exchange chains {{RFC8693}}. Records MAY be carried as COSE_Sign1 objects {{RFC9052}}, and MAY be registered with a transparency service {{I-D.ietf-scitt-architecture}}, which makes selective omission of records detectable.

This document doesn't define new transport or storage. It requires only that records carry the fields listed in {{fields}}, and that records can be linked using the AUDIT audit context: trace, parent, actor, and on-behalf-of.

# Claim Model {#claims}

A claim set is C = (A, R, A⁻, R⁻, D, E, V, P, K, B), where:

- A and R are sets of canonical action and resource patterns that are permitted;
- A⁻ and R⁻ are sets of action and resource patterns that are denied even when A or R would permit them;
- D is a set of (data class, recipient class) pairs;
- E is the effect ceiling, an element of the totally ordered set `read < write_local < write_shared < external_send < destructive < financial`;
- V is the validity interval;
- P is the purpose;
- K is the delegation budget (remaining depth);
- B is an OPTIONAL risk budget in points.

C1 ⊑ C2 (C1 is equal to or narrower than C2) holds if and only if: every pattern in A1 and R1 is subsumed by some pattern in A2 or R2 respectively; every pattern in A2⁻ and R2⁻ is subsumed by some pattern in A1⁻ or R1⁻ respectively (denies only grow); D1 ⊆ D2; E1 ≤ E2; V1 ⊆ V2; P1 = P2 or P2 is unrestricted; the depth rule holds (if K2 is present, K2 > 0 and K1 < K2); and B1 ≤ B2 when B2 is present.

The meet C1 ⊓ C2 is taken component-wise, with denies unioned so that no hop and no intent can lift a deny.

Resource identifiers MUST be canonical. File-system paths MUST be absolute and normalized, with the home directory expanded and ".." collapsed. URLs MUST carry their resolved host class. SaaS objects MUST be identified as `provider:type/id`. A verifier MUST NOT rely on user-relative forms.

An effect is x = (a, r, d, e, t). x ⊨ C if and only if a matches A and not A⁻, r matches R and not R⁻, e ≤ E, every released (data class, recipient class) pair is in D, and t ∈ V.

# Signer Roles {#roles}

A valid signature shows only that a key signed a record. Each key in the verifier's key set carries roles, and a record counts as signed only when its key holds a role permitted for the record's kind:

| Record | Permitted signer roles |
|---|---|
| Mandate, revocation, revocation status | issuer |
| Delegation, intent | issuer, host |
| Interpretation, invocation, decision | host |
| Effect | observer |
| Approval | approver |
| Content finding | host, observer |

Without roles, a compromised host key could mint its own mandate or approve its own action.

# Invariants

| ID | Invariant | When broken |
|---|---|---|
| I1 | Attenuation: child ⊑ parent at every delegation edge | violated |
| I2 | Every effect matches the declared (or mediated) effect, satisfies the meet of the chain (and of the intent), and stays within risk budgets unless a bound approval covers it | violated |
| I3 | The invocation was interpreted by an approved, version-pinned mapping | unresolved |
| I4 | Content withheld by a quarantine did not reach a later step; a mutation influenced by content that is not signed and trusted was confirmed by the principal | violated (executed) or unresolved |
| I5 | Data classes released to a recipient are permitted | violated |
| I6 | No ancestor was revoked, per signed revocation or status evidence, at or before the invocation | violated |
| I7 | All required records are present, well-formed, signed by a permitted role, and fresh where required | unresolved |
| I8 | An approval matches the executed effect (without its time), is within its validity window, unconsumed, and used once | violated |
| I9 | No agent effect targets guardrail configuration, keys, instruction files, or the audit store | violated |
| I10 | An effect at or above `write_shared` names its actor and was observed by a party other than that actor | unresolved |
| I11 | Every recorded effect links to an authorized invocation, and none exists for an invocation a pre-execution decision denied | violated |

# Evaluation Procedure {#evaluation}

For each invocation, in recorded order, a verifier MUST apply the following checks in order and return the first outcome that applies. "Verified" means signed by a key holding a permitted role ({{roles}}).

~~~
ID   Outcome     Condition
I4   violated    quarantined content in the influence set,
                 not confirmed by the principal
I7   unresolved  no root mandate
I7   unresolved  cited intent missing, or a needed record
                 not verified
I7   unresolved  lineage names an invocation that is not earlier
I3   unresolved  no approved interpretation, or a pin mismatch
I1   violated    a delegation edge where not (child ⊑ parent)
I6   violated    verified revocation or status shows an
                 ancestor revoked
I7   unresolved  unverified revocation on the chain, or a
                 revocable record without a fresh verified status
I9   violated    guardrail target
I4   violated    untrusted influence on a mutation, unconfirmed
                 (unresolved instead if no effect exists)
I7   unresolved  no effect record
     For every effect record of the invocation:
I7   unresolved    record not verified
I10  unresolved    e >= write_shared and the actor is absent,
                   the effect is self-observed, or assurance L0
I2   violated      executed != declared (and != the mediated
                   effect)
I9   violated      executed resource is a guardrail
I2   violated      x does not satisfy the meet of the chain and
                   intent (I5 when the failure is a release)
I5   violated      data classes carried in through lineage reach
                   a recipient class the claims do not permit
I7   unresolved  approval missing or not verified
I8   violated    approval unbound, outside its window,
                 consumed, or reused
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

Lineage: an effect may record the data classes it read (accessed) and the recipient class of what it sent; an invocation may name the earlier invocations its input came from (derived_from). The data classes an invocation carries are those its own effects read plus those carried by the invocations it derives from, transitively. This detects sensitive data leaving in a later step even when that step declares no release.

A verifier evaluating a stream of packets MAY carry approval use and risk-budget spending from one packet to the next, so that single use and budgets hold across the stream.

Decisions carry a phase: pre_execution, post_execution, or simulation. Only pre-execution decisions can confirm or contradict a block. A post-execution decision is detection and MUST NOT be presented as having prevented the action.

When B is present, the cost of x is base(e) × m(d) × rev(x). The base table is read 0, write_local 1, write_shared 3, external_send 5, destructive 10, financial 20. m(d) is the largest data-class multiplier among the released classes (1, 2, or 5). rev(x) is 1 if the effect is a read, or reversible and not an external send, and 3 otherwise. The cost is charged to every node in the chain. The tables are registries ({{iana}}).

# Required Fields {#fields}

The evaluation needs the following fields from each AUDIT record. Field names are placeholders until the AUDIT data model is defined.

- Mandate, Intent, and Delegation: id, parent, issuer, claims (C), signature.
- Invocation: id, authority reference, interpretation reference (adapter and version), declared effect, actor, influence references, approval reference, time.
- Effect: id, invocation reference, executed effect x, observer, assurance level (L0 self-reported to L3 provider-confirmed), signature.
- Approval: id, effect digest (SHA-256 over the JCS {{RFC8785}} form of x without its time), presence (webauthn, chat_user, host_ui, or none), validity window, consumed flag, signature.
- Revocation and revocation status: target, time (or as-of time and revocation time), signature.
- Continuity decision: invocation reference, mode, phase, outcome, enforcement context (enforcement point, fail mode, what was returned to the host, whether an effect record confirms it), signature.

Records are canonicalized with JCS {{RFC8785}} and signed with Ed25519 {{RFC8032}}. Times are numbers of seconds since the epoch or RFC 3339 {{RFC3339}} strings. A CDDL {{RFC8610}} definition and JSON Schemas are published in {{AMEP}}.

# Test Vectors

{{AMEP}} publishes 95 vectors: 25 positive and 70 must-reject. The must-reject vectors cover all eleven invariants, signer roles, revocation status, decision phase, deny lists, data lineage, state across packets, risk-budget accounting, and a deny that an executed effect contradicts. Each vector is a packet of signed records, with the expected outcome and invariant. Two independently written implementations (Python, and JavaScript run under Node.js and in a browser) agree on all 95.

A conforming verifier MUST return the expected outcome and invariant for every vector.

# Implementation Status

**Note to the RFC Editor:** please remove this section before publication, per {{RFC7942}}.

- **AMEP reference verifiers.** Two independent implementations: Python, and JavaScript (run as a Node.js command-line tool and as an offline browser page using WebCrypto). Both evaluate the procedure in {{evaluation}} and agree on all 95 published vectors. License: Apache 2.0. Location: https://github.com/stafordtituss/amep. Maturity: prototype.
- **Natsar control plane** (agent-authority enforcement for coding-agent hosts and MCP). It emits decision records before tool execution from host hooks. Maturity: pre-release.

Implementation experience motivated several parts of this document: canonical resource identifiers (absolute-path forms bypassed relative-prefix rules); recording the enforcement context and phase (hosts differ in whether they support "ask" and whether hook failures block); and treating an effect that contradicts a deny as evidence of bypass.

# Security Considerations

- **Adversarial models:** the guarantees MUST hold even if every model in the chain is adversarial. Semantic analysis MAY raise a decision level, but MUST NOT mint authority or lower a decision.
- **Self-reporting:** records produced by the actor alone are insufficient for high-impact effects (I10).
- **Key compromise:** signer roles ({{roles}}) limit what one stolen key can forge.
- **Evidence omission:** a missing record, status or signature yields unresolved. Omission of whole invocations is detected only against an independent effect log (I11).
- **Canonicalization:** non-canonical resource forms enable bypasses. Canonicalization is therefore normative.
- **Approval replay and time-of-check/time-of-use:** approvals bind the exact effect and are single use (I8).
- **Fail-open enforcement:** an enforcement point that errors MUST return a deny decision, not a transport error. Hosts commonly treat transport errors as non-blocking, and some treat an unsupported "ask" as a hook failure and run the action. A verifier SHOULD treat an effect that contradicts a pre-execution deny as evidence of bypass.
- **Guardrail tampering:** agent writes to hook configuration, keys, instruction files, or the audit store are violations (I9).

# Privacy Considerations

Effect records can contain personal data. Verifiers need only canonical actions, resource identifiers, data-class labels, and digests. Payloads SHOULD be detached and hashed, following the AUDIT selective-disclosure work.

# IANA Considerations {#iana}

This document proposes registries for effect classes, data classes, recipient classes, signer roles, and the risk-cost tables, with the registration policy Specification Required. The registries are to be defined in a later revision.

--- back

# Acknowledgments
{:numbered="false"}

This document is derived from the Agentic Mandate Evidence Protocol (AMEP), designed and written by the author.
