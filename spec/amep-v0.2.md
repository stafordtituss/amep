# Agentic Mandate Evidence Protocol (AMEP™) — Core Specification

| | |
|---|---|
| **Document** | `amep-core` |
| **Version** | 0.2.0-draft.4 |
| **Date** | 2026-11-17 |
| **Status** | Public Draft. Not endorsed by any standards body. |
| **Author and editor** | Staford Titus Selvaraj (Independent) |
| **Repository** | https://github.com/stafordtituss/amep |
| **Feedback** | Issues and `AMEP-Proposal-N` documents in the repository (see `CONTRIBUTING.md`) |
| **Replaces** | AMEP v0.1 (unpublished working draft) |

> **Copyright and license.** Copyright © 2026 Staford Titus Selvaraj and the AMEP Contributors. AMEP was originally designed and written by Staford Titus Selvaraj. This specification is made available under the **Community Specification License 1.0** (`LICENSE-SPEC.md`). Code, schemas and test vectors referenced by this specification are licensed under the **Apache License 2.0** (`LICENSE-CODE`).
>
> **Trademarks.** "AMEP", "Agentic Mandate Evidence Protocol" and the "AMEP Conformant" mark are trademarks of Staford Titus Selvaraj. The licenses above grant rights to the text and code, not to the names. Use of the names is governed by `TRADEMARKS.md`. In particular, a modified version of this specification MUST NOT be called "AMEP", and an implementation MUST NOT claim to be "AMEP Conformant" unless it passes the conformance suite in Section 15.

---

## Abstract

AI agents act on behalf of people through chains of delegation, tools and adapters. Identity tells a relying party *who* acted, and authorization tells it what a token *allowed*. Neither proves that **what actually happened stayed within what a person authorized**.

AMEP defines portable, signed evidence objects for each link in that chain (mandate, delegation, intent, interpretation, invocation, approval and an **independently observed executed effect**) and a deterministic, three-valued evaluation over them. Its outcome is `preserved`, `violated` or `unresolved`, and every non-preserved outcome names the invariant that was broken. Missing evidence is never treated as permission.

AMEP does not replace identity, authorization or logging standards. It binds to them: OAuth token exchange and OpenID AuthZEN supply mandates and decisions, MCP and A2A carry references, SCITT provides transparency, and OpenTelemetry carries correlation.

---

## Table of contents

1. Introduction
2. Conventions and terminology
3. Design principles
4. Architecture
5. Data model
6. Canonical identifiers and patterns
7. Claim algebra
8. Invariants
9. Risk-budget accounting
10. Evaluation procedure
11. Decision modes and enforcement
12. Cryptography and encoding
13. Bindings (informative summary)
14. Profiles
15. Conformance
16. Versioning and extensibility
17. Security considerations
18. Privacy considerations
19. Registries
20. References
- Appendix A. Worked example
- Appendix B. Conformance vector index
- Appendix C. Relationship to other work
- Appendix D. Changes from v0.1
- Appendix E. Open issues

---

## 1. Introduction

### 1.1 Problem

An agent acting for a principal rarely acts directly. A user asks a host agent; the host spawns sub-agents; sub-agents call tools through adapters; adapters translate calls into effects on files, SaaS records, payment systems or other people's inboxes. At every hop, what is *done* can drift from what was *asked*:

- an approval for one command is replayed for a different one;
- a sub-agent receives broader scope than its parent held;
- untrusted content (a README, an email, a web page) steers a mutation;
- an adapter maps a declared call to a different effect;
- a revoked grant upstream leaves a live child downstream;
- an enforcement point says "deny" on a host that runs the action anyway.

Existing standards answer adjacent questions. OAuth proves a token was valid. AuthZEN transports a decision. Audit logs record that something happened. None of them states, in a way a third party can check offline, **whether an executed effect stayed within the authority that the principal delegated**, nor how to treat the case where the evidence to decide is missing.

### 1.2 Goals

AMEP:

1. defines **evidence objects** that any party in the chain can emit and any verifier can check with public keys alone;
2. defines a **claim model** that makes delegated authority machine-checkable;
3. defines eleven **invariants** (I1–I11) and a deterministic **evaluation procedure** returning `preserved`, `violated` or `unresolved` with the deciding invariant;
4. publishes **conformance vectors**, including MUST-reject vectors, so that independent verifiers can demonstrate agreement;
5. defines **bindings** to existing identity, decision, transport and transparency standards instead of new primitives.

### 1.3 Non-goals

AMEP does not:

- issue agent identities or credentials;
- define a policy language or replace OAuth, OpenID AuthZEN or a PDP;
- define prompt-injection detection algorithms (it records their findings, Section 5.11);
- define log storage or transport.

### 1.4 Scope of this document

This document is the **core**: data model, claim algebra, invariants, evaluation, cryptography and conformance. Bindings (Section 13) and profiles (Section 14) are summarized here and specified in companion documents. Objects marked *reserved* in Section 5.14 are named so that implementations do not collide with them, but are not normative in v0.2.

---

## 2. Conventions and terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY** and **OPTIONAL** in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals.

Sections and paragraphs marked *(informative)* contain no requirements.

| Term | Definition |
|---|---|
| **Principal** | The person or organization on whose behalf authority is exercised. |
| **Mandate Issuer** | The party that signs a PrincipalMandate for a principal (for example, an authorization server or an enterprise control plane). |
| **Agent** | Software that acts under a mandate, autonomously or semi-autonomously. |
| **Delegate** | An agent that receives authority from another agent through a Delegation. |
| **Host** | The runtime in which an agent runs and through which its tool calls pass (for example, a coding-agent CLI or an agent platform). |
| **Adapter** | Code that translates a tool call into a canonical action on a canonical resource. Its translation is recorded as an Interpretation. |
| **Observer** | The party that records an executed effect. It may be the host, a proxy, or the receiving system. |
| **Enforcement Point (PEP)** | A component that can allow, rewrite or block an invocation before it takes effect. |
| **Decision Point (PDP)** | A component that decides whether an invocation is permitted. |
| **Verifier** | An entity that runs the evaluation in Section 10. |
| **Effect** | What was actually executed at the boundary where an action took effect. |
| **Effect Class** | The impact category of an effect (Section 5.1.3). |
| **Data Class** | A sensitivity label on data (for example, `confidential`, `secret`, `phi`). |
| **Recipient Class** | A label for where data goes (for example, `internal`, `external`). |
| **Packet** | A set of AMEP objects submitted together for evaluation (Section 5.2). |
| **Chain** | The ordered list of mandate and delegations from the root mandate to the authority an invocation cites. |

---

## 3. Design principles

These principles are normative. Where a later section appears to conflict with them, the principle prevails and the conflict is a defect in this document.

- **P0. Untrusted-model assumption.** AMEP's guarantees MUST hold if every model in the chain is adversarial. Nothing a model says about itself is evidence.
- **P1. Separation.** Identity ≠ authority ≠ execution ≠ responsibility. Each is evidenced by a different object.
- **P2. Declared ≠ executed.** What an agent declares it will do and what was executed are recorded separately and compared.
- **P3. Attenuation.** Authority can only narrow as it is delegated.
- **P4. Fail-safe evidence.** Missing, unsigned or unverifiable evidence yields `unresolved`, never `preserved`.
- **P5. Advice never mints authority.** Semantic engines (classifiers, LLM judges, injection detectors) MAY raise a decision's strictness. They MUST NOT grant authority or lower strictness.
- **P6. Independent observation.** High-impact effects need an observer other than the actor.
- **P7. Exportable evidence.** Every object can be verified offline by a third party with public keys and this specification.
- **P8. Determinism.** The same packet, keys and pinned adapters always yield the same outcome.
- **P9. Mediation over refusal.** Where a narrower effect satisfies the mandate, implementations SHOULD offer it instead of refusing outright.

---

## 4. Architecture

### 4.1 Roles and trust boundaries

```
 Principal ──signs/approves──► Mandate Issuer ──PrincipalMandate──┐
                                                                  ▼
 Host ── IntentCertificate ── Agent ──Delegation──► Delegate ──► Invocation
                                                                  │
                                    Adapter ──Interpretation──────┤
                                                                  ▼
                               PEP/PDP ──ContinuityDecision──► (allow | mediate | step_up | hold | deny)
                                                                  │
                              Observer ──ExecutedEffectReceipt◄───┘ effect at the boundary
                                                                  │
                                                       Verifier ◄─┘ packet + public keys
```

Each object is signed by the party that produced it. A verifier trusts a signature only to the extent that it trusts the key's holder for that role. Key-to-role assignment is out of scope for the core and is defined by deployments or profiles.

### 4.2 Flows

- **Preventive.** A PEP evaluates an invocation against its *predicted* effect before execution and emits a ContinuityDecision.
- **Detective.** A verifier evaluates recorded invocations and effects after the fact.
- **Mediated.** A PEP rewrites an invocation into a narrower effect and records the substitution (`mediated`). The executed effect is then compared with the mediated effect, not the declared one.

A deployment MAY use all three. The evaluation procedure (Section 10) is the same in each; only the availability of the effect receipt differs.

### 4.3 Correlation

Every Invocation SHOULD carry a `correlation` object with `session_ref`, `prompt_ref`, `tool_use_ref` and `traceparent` (W3C Trace Context [TRACE-CONTEXT]). Observers SHOULD copy `tool_use_ref` into their records so that an effect can be linked to its invocation even when produced by a different system.

---

## 5. Data model

### 5.1 Common types

#### 5.1.1 Identifiers and time

- `ref`: a string identifier, unique within a packet. Producers SHOULD use globally unique identifiers (for example, UUIDv7 or a URN).
- `time`: either a number of seconds since the Unix epoch, or an RFC 3339 date-time string with an explicit offset (`Z` or `±hh:mm`) and at most millisecond precision. Within one packet, a producer SHOULD use one form consistently. Verifiers compare times numerically after conversion. A time in any other form makes the evidence that contains it malformed, and the affected invocation `unresolved` (I7).

#### 5.1.2 Data flows

A data flow is a string `"<data_class>-><recipient_class>"`, matching `^[a-z_]+->[a-z_]+$`. For example, `"confidential->internal"` permits data of class `confidential` to reach recipients of class `internal`. Data classes and recipient classes are registries (Section 19).

#### 5.1.3 Effect classes

Effect classes are totally ordered:

```
read < write_local < write_shared < external_send < destructive < financial
```

| Class | Meaning |
|---|---|
| `read` | Observes state without changing it. |
| `write_local` | Changes state visible only to the principal or the agent's workspace. |
| `write_shared` | Changes state that other people or systems rely on. |
| `external_send` | Sends data or messages outside the principal's organization. |
| `destructive` | Deletes or irreversibly overwrites state. |
| `financial` | Moves money or creates a financial obligation. |

#### 5.1.4 Assurance levels

| Level | Observer |
|---|---|
| `L0` | Self-reported by the actor. |
| `L1` | Recorded by the host, outside the model's control. |
| `L2` | Recorded by a proxy or gateway on the path to the receiver. |
| `L3` | Confirmed by the receiving system (for example, a backend receipt). |

#### 5.1.5 Proof

```json
"proof": { "alg": "Ed25519", "kid": "issuer-1", "sig": "<hex or base64url>" }
```

`proof` signs the object with the `proof` member removed (Section 12). An object without `proof` is *unsigned*.

### 5.2 Packet

A packet groups the objects to be evaluated. All members are OPTIONAL arrays except `pinned_adapters`, which is a map.

| Member | Contents |
|---|---|
| `mandates` | PrincipalMandate objects |
| `delegations` | Delegation objects |
| `intents` | IntentCertificate objects |
| `interpretations` | AdapterInterpretation objects |
| `invocations` | Invocation objects, **in the order they occurred** |
| `effects` | ExecutedEffectReceipt objects |
| `approvals` | ApprovalBinding objects |
| `revocations` | Revocation objects |
| `statuses` | Revocation status assertions |
| `findings` | ContentFinding objects |
| `decisions` | ContinuityDecision objects |
| `pinned_adapters` | map of adapter id → approved version |

Unknown members whose names begin with `x-` MUST be ignored by verifiers. Unknown members without the prefix SHOULD cause a verifier to report a warning and MUST NOT change the outcome.

### 5.3 Claims

A claim set states what may be done. It appears in mandates, delegations and intents.

| Field | Type | Req. | Meaning |
|---|---|---|---|
| `actions` | array of action patterns | **yes** | Canonical actions permitted (Section 6). |
| `resources` | array of resource patterns | **yes** | Canonical resources permitted (Section 6). |
| `data` | array of data flows | no | Data flows permitted. Absent means none. |
| `ceiling` | effect class | **yes** | Highest effect class permitted. |
| `exp` | time | **yes** | End of validity. |
| `nbf` | time | no | Start of validity. Absent means unbounded below. |
| `purpose` | string | no | Purpose token. Absent means unrestricted. |
| `deny_actions` | array of action patterns | no | Actions forbidden even if `actions` would allow them. Absent means none. |
| `deny_resources` | array of resource patterns | no | Resources forbidden even if `resources` would allow them. Absent means none. |

Denies let a claim set say "everything under this prefix except…", which allow-lists alone cannot express. Denies only ever grow along a chain (Section 7.1), and an intent cannot lift one (Section 7.3).
| `depth` | unsigned integer | no | Remaining delegation depth (Section 7.2). |
| `budget` | unsigned integer | no | Risk budget in points (Section 9). |

### 5.4 PrincipalMandate (`kind: "mandate"`)

The root of authority. Signed by the Mandate Issuer.

| Field | Req. | Meaning |
|---|---|---|
| `id`, `kind` | **yes** | |
| `principal` | **yes** | Identifier of the principal (for example, `user:alice`, a DID, or an OAuth `sub`). |
| `issuer` | no | Identifier of the Mandate Issuer. |
| `subject_agent` | no | The agent the mandate is issued to. |
| `claims` | **yes** | Section 5.3. |
| `revocation` | no | `{ "status_ref": <URL> }` where current revocation status can be fetched. When present, every evaluation that relies on this mandate needs a fresh signed status assertion (Section 5.12). |
| `token` | no | The token this mandate was derived from: `{ format, block?, digest, value? }` (Section 14.1). `value` only for expired or holder-bound tokens. |
| `proof` | **yes**¹ | |

¹ Fields marked **yes**¹ are REQUIRED for the object to count as evidence. A verifier MUST accept a packet in which they are missing and MUST then return `unresolved` (I7) where the evaluation needs them.

### 5.5 Delegation (`kind: "delegation"`)

Passes authority from a parent (mandate or delegation) to a delegate.

| Field | Req. | Meaning |
|---|---|---|
| `id`, `kind` | **yes** | |
| `parent` | **yes** | `id` of the parent mandate or delegation. |
| `delegate` | no | Identifier of the receiving agent. |
| `claims` | **yes** | MUST satisfy `claims ⊑ parent.claims` (I1). |
| `token` | no | The token block this delegation was derived from (Section 14.1). |
| `proof` | **yes**¹ | Signed by the delegating party. |

### 5.6 IntentCertificate (`kind: "intent"`)

Narrows a mandate to what was asked in one request.

| Field | Req. | Meaning |
|---|---|---|
| `id`, `kind` | **yes** | |
| `prompt_ref` | no | Reference to the request, for example a hash of the prompt and session. |
| `claims` | **yes** | Expected effects of the request. |
| `derivation` | no | `template`, `judge` or `confirmed` (by the principal). |
| `proof` | **yes**¹ | |

An intent derived by a `judge` is advice (P5). It narrows authority when present but MUST NOT be used to widen it.

### 5.7 AdapterInterpretation (`kind: "interpretation"`)

Records which mapping turned a tool call into a canonical action.

| Field | Req. | Meaning |
|---|---|---|
| `id`, `kind` | **yes** | |
| `source` | **yes** | `curated`, `customer`, `provider_hint`, `judge` or `none` (Section 19.6). |
| `adapter` | **yes** | Adapter identifier. |
| `version` | **yes** | Adapter mapping version. |
| `integrity_hash` | no | Digest of the mapping definition. |
| `proof` | **yes**¹ | |

Only `curated` and `customer` sources are *approved*. `provider_hint` (for example, MCP tool annotations) and `judge` are advice and do not satisfy I3.

### 5.8 Invocation (`kind: "invocation"`)

A declared call.

| Field | Req. | Meaning |
|---|---|---|
| `id`, `kind` | **yes** | |
| `authority_ref` | **yes** | `id` of the mandate or delegation the call is made under. |
| `interpretation_ref` | **yes** | `id` of the AdapterInterpretation. |
| `intent_ref` | no | `id` of the IntentCertificate. |
| `approval_ref` | no | `id` of the ApprovalBinding. |
| `t` | **yes** | Time of the invocation. |
| `actor` | no | Identifier of the acting agent. REQUIRED when the declared effect is `write_shared` or above. Without it, observer independence cannot be shown and the result is `unresolved` (I10). |
| `declared` | **yes** | `{ action, resource, effect }`: canonical action, canonical resource, effect class. |
| `mediated` | no | An executed-effect body (Section 5.9) that a PEP substituted. |
| `influenced_by` | no | Array of ContentFinding `id`s whose content was in the agent's context. |
| `principal_confirmed` | no | `true` if the principal confirmed this invocation after seeing the influence. |
| `derived_from` | no | `id`s of **earlier** invocations whose outputs fed this one (Section 5.9.1). |
| `budget_spent` | no | Points charged for this invocation (Section 9). |
| `correlation` | no | Section 4.3. |
| `proof` | **yes**¹ | Signed by the host or PEP, not by the model. |

### 5.9 ExecutedEffectReceipt (`kind: "effect"`)

What was executed, recorded by an observer.

| Field | Req. | Meaning |
|---|---|---|
| `id`, `kind` | **yes** | |
| `invocation` | **yes** | `id` of the invocation this effect results from. |
| `observed_by` | **yes** | Identifier of the observer. |
| `assurance` | **yes** | `L0`–`L3` (Section 5.1.4). |
| `executed` | **yes** | Executed-effect body (below). |
| `backend_receipt` | no | Opaque receipt from the receiving system (L3). |
| `proof` | **yes**¹ | Signed by the observer. |

**Executed-effect body:**

| Field | Req. | Meaning |
|---|---|---|
| `action` | **yes** | Canonical action executed. |
| `resource` | **yes** | Canonical resource affected. |
| `effect` | **yes** | Effect class. |
| `released` | no | Data flows released. Absent means none. |
| `reversible` | no | `true` if the effect can be undone. Absent means `false`. |
| `accessed` | no | Data classes this effect read or obtained, for example `["confidential"]` (Section 5.9.1). |
| `recipient` | no | Recipient class of what this effect sent or wrote, for example `external` (Section 5.9.1). |
| `t` | **yes** | Time of execution. |

#### 5.9.1 Data lineage

`released` records the data flows an effect *declares*. An agent that reads a confidential document and then posts "a summary" to an external service may declare no release at all. Lineage closes that gap:

- An effect that reads data records the data classes it obtained in `accessed`.
- An invocation whose input came from earlier steps lists them in `derived_from`.
- An effect that sends or writes somewhere records the `recipient` class.

The **carried classes** of an invocation are the `accessed` classes of its own effects, plus the carried classes of every earlier invocation it is `derived_from`, transitively. For each effect with a `recipient` r, every class d among its own `accessed` classes and the carried classes of the invocations it is derived from produces the flow `d->r`, which MUST be permitted by the effective claims' `data`. Otherwise the result is `violated` (I5).

Hosts that cannot track precisely which outputs fed which inputs MUST be conservative: list in `derived_from` every earlier invocation of the same session whose output entered the agent's context. Lineage that is missing cannot be detected by a verifier. This is one reason profiles that handle sensitive data (AMEP-SaaS, AMEP-Health) require L2/L3 observers at the egress point.

### 5.10 ApprovalBinding (`kind: "approval"`)

A human approval bound to one exact effect.

| Field | Req. | Meaning |
|---|---|---|
| `id`, `kind` | **yes** | |
| `effect_digest` | **yes** | Lowercase hex SHA-256 of the canonical form (Section 12.1) of the approved executed-effect body **with its `t` member removed**. |
| `presence` | **yes** | `webauthn`, `chat_user`, `host_ui` or `none`. |
| `approver` | no | Identifier of the approver. |
| `resource_version` | no | Version of the resource at approval time (for example, an ETag or commit hash). |
| `nbf` | no | Time before which the approval may not be used. |
| `expiry` | no | Time after which the approval is void. Producers SHOULD set it. |
| `consumed` | no | `true` once the approval has been used. |
| `proof` | **yes**¹ | Signed by a key with role `approver` (Section 12.5). |

The digest excludes `t` so that an approval can be issued before execution, when the time is not yet known. Time is bound instead by the approval's `nbf`–`expiry` window, which MUST contain both the invocation time and the execution time. An approval is **single use**: within a packet, one approval MAY cover only one invocation and one effect body (the same effect recorded by several observers counts once). Verifiers that see approvals across packets SHOULD track use across packets too.

### 5.11 ContentFinding (`kind: "finding"`)

Evidence that content in the agent's context came from an untrusted source.

| Field | Req. | Meaning |
|---|---|---|
| `id`, `kind` | **yes** | |
| `source_locator` | **yes** | Where the content came from (URL, path, message id). |
| `content_hash` | **yes** | Digest of the content. |
| `span` | no | `{ start, end, excerpt? }`. |
| `hidden_mechanism` | no | `none`, `html_comment`, `zero_width`, `unicode_tags`, `white_text`, `alt_text`, `metadata` or `other`. |
| `integrity_label` | **yes** | `trusted` or `untrusted`. |
| `requested` | no | `{ action, object, recipient }` that the content asked for. |
| `proof` | no | Signed by a key with role `host` or `observer`. |

A finding counts as `trusted` only if it exists in the packet, carries a valid proof from a permitted signer, and is labelled `trusted`. An invocation's `influenced_by` reference to anything else, including a missing or unsigned finding, is treated as untrusted influence (I4). This prevents a packet assembler from neutralising I4 by inserting an unsigned "trusted" finding.

### 5.12 Revocation and revocation status

Whoever assembles a packet could simply leave a revocation out. AMEP therefore treats revocation evidence like any other evidence: it must be signed, and where a mandate says its status can be checked, the packet must show that it was.

**Revocation (`kind: "revocation"`).**

| Field | Req. | Meaning |
|---|---|---|
| `id` | no | |
| `kind` | **yes** | `"revocation"` |
| `target` | **yes** | `id` of a mandate or delegation. |
| `t` | **yes** | Time of revocation. |
| `reason` | no | |
| `proof` | **yes**¹ | Signed by a key with role `issuer`. |

**Revocation status (`kind: "status"`).** A signed assertion, typically fetched from the mandate's `revocation.status_ref`, that states the target's revocation state as of a time.

| Field | Req. | Meaning |
|---|---|---|
| `id` | no | |
| `kind` | **yes** | `"status"` |
| `target` | **yes** | `id` of a mandate or delegation. |
| `as_of` | **yes** | The time at which the state was checked. |
| `revoked_at` | no | Time of revocation, if revoked. Absent means not revoked as of `as_of`. |
| `proof` | **yes**¹ | Signed by a key with role `issuer`. |

Rules (applied in Section 10.2 step 6):

1. A **signed** revocation, or a signed status with `revoked_at`, at or before the invocation time makes the result `violated` (I6).
2. An **unsigned or unverifiable** revocation targeting the chain makes the result `unresolved` (I7). It can neither be trusted nor safely ignored.
3. For every chain element that carries `revocation.status_ref`, the packet MUST contain a signed status with `as_of` at or after the invocation time. Otherwise the result is `unresolved` (I7).

Profiles that need high assurance SHOULD require `revocation.status_ref` on every mandate.

### 5.13 ContinuityDecision (`kind: "decision"`)

A PEP's decision on an invocation.

| Field | Req. | Meaning |
|---|---|---|
| `id`, `kind` | no | |
| `invocation` | **yes** | `id` of the invocation decided. |
| `outcome` | **yes** | `preserved`, `violated` or `unresolved`. |
| `invariant` | no | Deciding invariant, or `-` when `preserved`. |
| `mode` | no | `observe`, `allow`, `mediate`, `step_up`, `hold`, `deny` or `quarantine` (Section 11). |
| `phase` | **yes** | `pre_execution`, `post_execution` or `simulation` (below). |
| `quarantined` | no | For `mode: quarantine`: the `id`s of ContentFindings withheld from the agent. |
| `reason` | no | Human-readable reason. |
| `safe_alternatives` | no | Array of executed-effect bodies the PEP would allow. |
| `evidence_refs` | no | `id`s of the objects the decision relied on. |
| `enforcement` | no | Section 5.13.1. RECOMMENDED for `deny`, `hold` and `step_up`. |
| `proof` | **yes**¹ | Signed by the PEP. |

**Phase.** Every decision states when it was made, so that detection is never mistaken for mediation:

| Phase | Meaning | Effect on evaluation |
|---|---|---|
| `pre_execution` | Made before the effect, by a PEP able to act on it. | May confirm a block or be contradicted (Section 10.3). A `quarantine` takes effect. |
| `post_execution` | Made after the effect, for example from an audit log. | Never counts as a block. A post-execution `deny` MUST NOT be presented as having prevented anything. |
| `simulation` | Evaluated hypothetically (testing, dry runs, policy previews). | Ignored by evaluation. |

A decision without a valid `phase` is not evidence and verifiers MUST ignore it.

**Quarantine.** `mode: quarantine` means the PEP withheld untrusted content from the agent (typically by replacing a tool's output before the model saw it). The tool call itself may have run. A verified `pre_execution` quarantine names the withheld findings in `quarantined`. Any **later** invocation, in packet order, that lists a quarantined finding in `influenced_by` shows that the content reached the agent anyway; unless the principal explicitly promoted it (`principal_confirmed: true`), the result is `violated` (I4), whatever the invocation's effect class.

**Mapping from common decision vocabularies (informative).** Products often use richer labels. They map onto AMEP as follows:

| Product label | AMEP decision |
|---|---|
| `allow` | `mode: allow` |
| `hold` | `mode: hold` |
| `deny` | `mode: deny` |
| `ask_human` | `mode: step_up`, approval `presence` `host_ui` or `chat_user` |
| `step_up_auth` | `mode: step_up`, approval `presence` `webauthn` |
| `safer_path` | `mode: mediate`, with the substituted body in the invocation's `mediated` |
| `quarantine_content` | `mode: quarantine`, with `quarantined` finding ids |
| `detect_after_execution` | `phase: post_execution`, usually with `mode: observe` |

Human-facing views MAY also show separate "authority" and "safety" verdicts. The normative result is always the signed decision with its phase, and the verifier's outcome and deciding invariant.

#### 5.13.1 Enforcement context

The same "deny" means different things on a host that blocks the action when the PEP fails and on one that runs it anyway. The enforcement context records which.

| Field | Req. | Meaning |
|---|---|---|
| `pep` | **yes** | PEP identifier and version, for example `claude-code-hook/2.1.300`. |
| `fail_mode` | **yes** | `closed`, `open` or `unknown`: what the host does with the action if the PEP errors. |
| `host_supports` | no | Subset of `ask`, `deny`, `rewrite_input`, `replace_output`. |
| `encoded_as` | no | What the host actually received, for example `deny+approval_link`. |
| `applied` | no | `confirmed`, `not_observed` or `contradicted`, from the effect record with the same `tool_use_ref`. |

### 5.14 Reserved objects (informative)

The following object kinds are reserved for v0.3 and MUST NOT be used with other meanings: `memory` (MemoryRecord), `lineage` (DataLineageRecord), `responsibility` (ResponsibilityAssignment), `workflow_decision` (WorkflowContinuityDecision), `threat_case` (ThreatCase).

---

## 6. Canonical identifiers and patterns

### 6.1 Actions

A canonical action is a dot-separated lowercase string `<namespace>.<verb>`, for example `fs.write`, `process.exec`, `http.post`, `mail.send`. The namespace registry is in Section 19.1.

### 6.2 Resources

Producers MUST emit canonical resource identifiers:

- **File system:** absolute, normalized paths, with the home directory expanded, `.` and `..` segments collapsed, and symbolic links resolved where the observer can resolve them. A path MAY be prefixed with a scheme naming the workspace, for example `repo:app/src/auth.ts`, when the scheme is declared by the profile.
- **URLs:** scheme, lowercase host and path, with the resolved host class (Section 19.4) available to the verifier.
- **SaaS records:** `<provider>:<type>/<id>`, for example `salesforce:account/001xx000003DGb2`.

Verifiers MUST NOT rely on user-relative forms such as `~/` for any decision. *(Rationale: implementation experience showed that rules written against `~/.ssh/` let `/Users/alice/.ssh/` through.)*

### 6.3 Patterns

Action and resource patterns in claims use the following matching, and only this matching:

| Pattern | Matches value `v` when |
|---|---|
| `*` | always |
| `p*` (ends with `*`) | `v` starts with `p` |
| any other `p` | `v == p` |

A pattern `c` is **subsumed** by a pattern `p` when `p` is `*`, or `c == p`, or `p` ends with `*` and `c` with any trailing `*` removed starts with `p` without its trailing `*`.

Patterns are compared after canonicalization. Profiles MUST NOT introduce other wildcard syntaxes in v0.2.

---

## 7. Claim algebra

### 7.1 Order

For claim sets C₁ (child) and C₂ (parent), **C₁ ⊑ C₂** (C₁ is equal to or narrower than C₂) holds if and only if all of the following hold:

1. every action pattern in C₁ is subsumed by some action pattern in C₂;
2. every resource pattern in C₁ is subsumed by some resource pattern in C₂;
3. every data flow in C₁ is in C₂ (absent `data` is the empty set);
4. `C₁.ceiling ≤ C₂.ceiling`;
5. `C₁.exp ≤ C₂.exp`, and `C₁.nbf ≥ C₂.nbf` when `C₂.nbf` is present;
6. `C₁.purpose == C₂.purpose`, or `C₂.purpose` is absent;
7. every pattern in `C₂.deny_actions` is subsumed by some pattern in `C₁.deny_actions`, and likewise for `deny_resources` (the child denies at least everything the parent denies);
8. the depth rule (Section 7.2) holds;
8. when `C₂.budget` is present, `C₁.budget ≤ C₂.budget`, where an absent `C₁.budget` is taken to equal `C₂.budget`.

### 7.2 Delegation depth

`depth` is the number of further delegation hops permitted below the object that carries it.

- An absent `depth` on a **mandate** means unbounded.
- If the parent's `depth` is present and greater than 0, the child's `depth` MUST be present and strictly less than the parent's.
- If the parent's `depth` is present and equal to 0, the parent MUST NOT be delegated further. A child of it violates I1.
- If the parent's `depth` is absent, the child's `depth` MAY be absent.

### 7.3 Meet

The meet **C₁ ⊓ C₂** is computed component-wise:

- actions: the patterns in C₁ that are subsumed by some pattern in C₂;
- resources: likewise;
- data: the intersection;
- ceiling: the lower of the two;
- `exp`: the earlier; `nbf`: the later;
- purpose: C₁'s if present, else C₂'s;
- `deny_actions` and `deny_resources`: the **union** of both, so that no hop and no intent can lift a deny.

The **effective claims** of an invocation are the meet of every claim set on its chain, from the root mandate to its `authority_ref`, and then met with the IntentCertificate's claims when `intent_ref` is present.

### 7.4 Satisfaction

An executed-effect body x **satisfies** claim set C (written x ⊨ C) if and only if:

1. `x.action` matches some action pattern in C;
2. `x.action` matches no pattern in `C.deny_actions`;
3. `x.resource` matches some resource pattern in C;
4. `x.resource` matches no pattern in `C.deny_resources`;
5. `x.effect ≤ C.ceiling`;
6. every data flow in `x.released` is in `C.data`;
7. `x.t ≤ C.exp`, and `x.t ≥ C.nbf` when `C.nbf` is present.

### 7.5 Properties *(informative)*

- **Monotonicity:** adding a hop never widens effective claims.
- **Decidability:** ⊑, ⊓ and ⊨ use only pattern subsumption, set inclusion and comparisons.
- **Mediation soundness:** a conforming PEP only substitutes a mediated body m when `m ⊨ effective claims`.

---

## 8. Invariants

Each invariant states a property of a chain of evidence. Section 10 defines the order in which they are checked and the outcome for each failure.

| ID | Name | Statement | When broken |
|---|---|---|---|
| **I1** | Attenuation | Every delegation's claims ⊑ its parent's claims. | `violated` |
| **I2** | Effect within authority | The executed effect matches the declared (or mediated) effect, satisfies the effective claims, and stays within every risk budget on the chain unless a bound approval covers it. | `violated` |
| **I3** | Interpretation | The invocation was interpreted by an approved mapping (`curated` or `customer`) whose version matches the pinned version, when pins exist. | `unresolved` |
| **I4** | Influence | Content withheld by a pre-execution quarantine did not reach any later invocation unless the principal promoted it; and a non-`read` invocation influenced by content that is not signed-and-trusted (Section 5.11) was confirmed by the principal. | `violated` if executed, otherwise `unresolved` |
| **I5** | Release | Every data flow released is permitted by the effective claims. | `violated` |
| **I6** | Liveness | No mandate or delegation on the chain was revoked, per signed revocation evidence, at or before the time of the invocation. | `violated` |
| **I7** | Evidence | All evidence the evaluation needs is present, well-formed, signed by a key holding a permitted role, and fresh where freshness is required; recorded accounting matches recomputation. | `unresolved` (`violated` for an accounting mismatch) |
| **I8** | Approval binding | An approval cited by an invocation matches the executed effect body (without `t`), is within its validity window, is unconsumed, and is used only once. | `violated` |
| **I9** | Self-protection | No agent invocation targets, or executes against, a protected resource: guardrail configuration, keys, agent instruction files, or the evidence store. | `violated` |
| **I10** | Observer independence | An effect of class `write_shared` or above names its actor and was observed by a party other than that actor, at assurance L1 or higher. | `unresolved` |
| **I11** | No orphan effects | Every effect links to an invocation in the packet, and no effect exists for an invocation that a signed decision denied or held. | `violated` |

### 8.1 Protected resources (I9)

A resource is protected when it matches any entry in the Protected Resource registry (Section 19.7) or any path the deployment declares as protected. At minimum a deployment MUST declare as protected:

- its own PEP and guardrail configuration;
- its signing keys;
- its evidence store.

Matching for I9 uses canonical resources (Section 6.2). Implementations MUST evaluate I9 against both the declared resource and, when present, the executed resource.

---

## 9. Risk-budget accounting

A `budget` bounds autonomy in points, in addition to scope.

### 9.1 Cost of an effect

```
cost(x) = base(x.effect) × mult(x) × rev(x)
```

- **base**: from the Effect Cost registry (Section 19.3). Initial values: `read` 0, `write_local` 1, `write_shared` 3, `external_send` 5, `destructive` 10, `financial` 20.
- **mult(x)**: the largest Data Multiplier (Section 19.2) among the data classes in `x.released`, or 1 if none. Initial values: `public`, `internal`, `source` 1; `confidential` 2; `secret`, `phi`, `pci` 5. Unknown classes count as 1.
- **rev(x)**: 1 if `x.effect` is `read`, or if `x.reversible` is `true` and `x.effect` is not `external_send`; otherwise 3.

### 9.2 Spending

Invocations in a packet are processed in order. Each mandate or delegation that carries `budget` keeps a running total of points spent by preserved invocations under it.

For an invocation whose effect has cost c:

1. If the invocation carries `budget_spent` and it is not equal to c, the result is `violated` (I7).
2. If any node on the chain carries `budget`, and that node's running total plus c exceeds its `budget`, and the invocation has no `approval_ref`, the result is `violated` (I2).
3. Otherwise c is added to the running total of every node on the chain.

An approval that passes I8 authorizes the overspend. At decision time a PEP MUST respond to a would-be overspend with `step_up`, never a silent `deny`.

A mediated effect is charged at the cost of the mediated body.

---

## 10. Evaluation procedure

### 10.1 Inputs and outputs

- **Inputs:** a packet; a key set mapping `kid` to public key and algorithm; optionally, a protected-resource list and revocation status sources.
- **Output:** a list of **results**, each `{ "id": <ref>, "outcome": <outcome>, "invariant": <ID or "-">, "reason": <string> }`.

A verifier MUST be deterministic (P8).

### 10.2 Per-invocation evaluation

For each invocation `i` **in packet order**, the verifier MUST apply the following checks in order and record the **first** outcome that applies. "Verified" below means: the proof is present and valid **and** the signing key holds a role permitted for the object's kind (Section 12.5).

```
 1. Resolve chain: start at objects[i.authority_ref]; follow .parent until absent
    (stopping at a repeated id). If the chain is empty, or its first
    element is not a mandate                                           → unresolved  I7  "no root mandate"
 2. If i.intent_ref is present and no intent with that id exists       → unresolved  I7
    If any chain element, i, the interpretation (if present) or the
    intent (if cited) is not verified                                  → unresolved  I7
 3. If no interpretation exists for i.interpretation_ref, or its
    source is not "curated" or "customer"                              → unresolved  I3
 4. If pinned_adapters is non-empty and
    pinned_adapters[interp.adapter] ≠ interp.version                   → unresolved  I3
 5. For each consecutive pair (parent, child) in the chain,
    if not child.claims ⊑ parent.claims                                → violated    I1
 6. Liveness (Section 5.12):
    a verified revocation of a chain element with t ≤ i.t, or a
    verified status with revoked_at ≤ i.t                              → violated    I6
    an unverified revocation targeting a chain element                 → unresolved  I7
    a chain element with revocation.status_ref and no verified
    status for it with as_of ≥ i.t                                    → unresolved  I7
 7. If i.declared.resource is protected (Section 8.1)                  → violated    I9
 8. Let E = every effect with e.invocation = i.id, in packet order.
 9. Let U = the ids in i.influenced_by that do not name a verified
    finding labelled "trusted". If U is non-empty,
    i.declared.effect ≠ read, and i.principal_confirmed is not true    → violated    I4 if E is non-empty
                                                                         unresolved  I4 otherwise
10. If E is empty                                                      → unresolved  I7  "no effect receipt"
11–14. For each e in E, with x = e.executed:
    11. if e is not verified                                           → unresolved  I7
    12. if i.declared.effect ≥ write_shared:
          if i.actor is absent                                         → unresolved  I10
          if e.observed_by = i.actor or e.assurance = L0               → unresolved  I10
    13. if i.mediated is present: if canon(x) ≠ canon(i.mediated)     → violated    I2
        else if x.action ≠ i.declared.action
             or x.resource ≠ i.declared.resource                       → violated    I2
        if x.resource is protected                                     → violated    I9
    14. let C = effective claims of i (Section 7.3);
        if not x ⊨ C: if the first failing condition is a released
        data flow                                                      → violated    I5
                      otherwise                                        → violated    I2
    Let B = the distinct bodies among the x, compared without t.
15. If i.approval_ref is present:
      if no such approval exists, or it is not verified                → unresolved  I7
      for each body x in B:
        approval.effect_digest ≠ SHA-256(canon(x without t)), or
        approval.consumed is true, or
        approval.expiry < max(i.t, x.t), or approval.nbf > i.t, or
        the approval was already used in this packet for a different
        invocation or body                                             → violated    I8
16. Apply risk-budget accounting (Section 9.2) with cost = Σ cost(x)
    over B                                                             → violated I7 or I2, if it fails
17. Otherwise                                                          → preserved   -
```

**Quarantine check (before step 1).** Let Q be the findings named in the `quarantined` member of every verified decision with `mode: quarantine` and `phase: pre_execution`, each attached to the position of its decision's invocation in packet order. If `i` comes later in packet order than the decision that quarantined a finding listed in `i.influenced_by`, and `i.principal_confirmed` is not true, the result is `violated` (I4), "quarantined content reached the agent". This applies whatever the invocation's effect class: a quarantine is a promise that the content never reached the model at all.

The checks in step 14 MUST be evaluated in the order of Section 7.4, so that the reported invariant is deterministic. If any object needed by a step is malformed (a missing required member, or a time in an invalid form), the result for that invocation is `unresolved` (I7).

Evaluating every receipt (steps 11–14) means that an extra effect recorded against an authorized invocation cannot hide behind the first, legitimate receipt. Several observers recording the same effect (for example, the host at L1 and the receiving system at L3) yield one body in B, so the effect is approved and charged once.

### 10.3 Decision reconciliation

After all invocations, for each verified ContinuityDecision `d` whose `mode` is `deny` or `hold` **and whose `phase` is `pre_execution`** (post-execution and simulated decisions can neither confirm nor contradict a block):

- If an effect exists with `invocation = d.invocation`, the result for that invocation is replaced with `violated`, I11, "effect despite deny" (enforcement was contradicted).
- Otherwise, if `d.enforcement.fail_mode` is `closed` or `d.enforcement.applied` is `confirmed`, the result for that invocation is replaced with `preserved`, `-`, "denied; no effect".
- Otherwise the result is left unchanged (it is `unresolved`, I7, because no effect receipt exists and the deny cannot be shown to have held).

### 10.4 Orphan effects

For each effect whose `invocation` does not match any invocation in the packet, the verifier MUST add a result `{ id: <effect id>, outcome: violated, invariant: I11, reason: "bypass" }`.

### 10.5 Packet verdict

The **packet verdict** is:

- `violated` if any result is `violated`;
- otherwise `unresolved` if any result is `unresolved`;
- otherwise `preserved`.

Its **deciding invariant** is that of the first result, in result order, with the verdict's outcome. Verifiers MUST report every result, not only the verdict.

### 10.6 Lineage checks

Section 10.2 also applies these lineage checks (Section 5.9.1):

- in step 2: if any id in `i.derived_from` does not name an invocation that comes **earlier** in the packet, the result is `unresolved` (I7);
- in step 14, after the claim checks: for an effect body x with a `recipient`, every carried class `d` whose flow `d->x.recipient` is not in the effective claims' `data` makes the result `violated` (I5).

### 10.7 State across packets

Approval single use (I8) and risk budgets (Section 9) span more than one packet when a verifier evaluates a stream of packets, for example a day of activity sent in hourly batches. A verifier MAY therefore keep **state**:

```json
{ "approvals_used": { "<approval id>": ["<invocation id>", "<body digest>"] },
  "spent":          { "<mandate or delegation id>": <points> } }
```

- On entry, `approvals_used` seeds the record of approval use, and `spent` seeds each node's running total.
- On exit, the verifier returns the updated state.
- Within one stream, state MUST be passed from each packet's evaluation to the next, in time order.

State is the verifier's own bookkeeping, not evidence. A third party that wants to reproduce a result needs the same state, so verifiers that rely on it SHOULD publish it alongside their results, signed with their own key. A conformance vector MAY include a `state` member, which a verifier passes in before evaluating that vector's packet.

---

## 11. Decision modes and enforcement

### 11.1 Decision order for PEPs

A PEP deciding on an invocation before execution MUST apply, in order:

1. **Hard denies:** invalid authority (I7 on the chain), I9, and I4 or I5 when the predicted effect would break them.
2. **Continuity outcome** on the predicted effect: `violated` → `deny` or `hold`; `unresolved` → `hold` or `step_up`.
3. **Authority:** the effective claims cover the predicted effect and the risk budget allows it (otherwise `step_up`).
4. **Safety advice** from semantic engines, which MAY only move the mode up the order below.
5. **Mode:** in `observe`, the PEP records the decision and allows the action.

Modes are ordered `allow < mediate < step_up < hold < deny`. Advice (P5) MUST NOT move a decision down this order.

`quarantine` is about content rather than the action, so it sits outside this order: a PEP MAY quarantine a tool's output and, separately, allow or block the call. It MUST record the quarantine as its own `pre_execution` decision naming the withheld findings (Section 5.13).

Every decision a PEP makes before execution MUST carry `phase: pre_execution`. Decisions derived from audit logs or other after-the-fact sources MUST carry `phase: post_execution` and MUST NOT be reported, in any interface, as having blocked or prevented the action.

A PEP MAY replace steps 3–4 with `mediate`: it substitutes a narrower body m with `m ⊨ effective claims` and records m in the invocation's `mediated` member.

### 11.2 Host encoding

A PEP running in a host MUST record the host's capabilities in `enforcement.host_supports` and its failure behaviour in `enforcement.fail_mode`.

- On a host without `ask`, a `step_up` or `hold` MUST be encoded as `deny` with a reference to an out-of-band approval, recorded as `encoded_as: "deny+approval_link"`. A retry after approval MUST cite an ApprovalBinding that satisfies I8.
- On a host without a fail-closed option, `fail_mode` MUST be `open`, and the deployment MUST NOT claim the Enforce conformance class (Section 15.1) without a compensating control (for example, a sandbox, an egress proxy or a credential broker) that is itself recorded in the enforcement context.
- A PEP that errors MUST return a deny decision to the host, not a transport error, because many hosts treat transport errors as non-blocking.

---

## 12. Cryptography and encoding

### 12.1 Canonical form

The canonical form `canon(o)` of an object is its JSON Canonicalization Scheme serialization [RFC8785], encoded as UTF-8.

*Note:* JCS sorts members by **UTF-16 code unit**, not by code point, and serializes numbers exactly as ECMAScript's `Number.prototype.toString`. Generic "sorted keys, no whitespace" serializers get both wrong for some inputs. The vector `jcs-canonical-form--unicode-keys--floats` contains member names on both sides of the surrogate range and non-integer numbers, and fails on any implementation that does not follow RFC 8785 exactly. Producers SHOULD still avoid integers above 2^53, which ECMAScript cannot represent exactly.

### 12.2 Signing

The signing input of an object is `canon(o′)`, where `o′` is `o` with the `proof` member removed.

- **Ed25519** [RFC8032] is REQUIRED for verifiers and RECOMMENDED for producers. `sig` is the 64-byte signature in lowercase hex.
- **ES256** is OPTIONAL.
- A key's algorithm is fixed by its key-set entry. A verifier MUST reject a proof whose `alg` differs from the key's algorithm (no algorithm negotiation).
- Hybrid post-quantum signatures (ML-DSA) are OPTIONAL for archival profiles.

Deployments MAY instead wrap objects in COSE_Sign1 [RFC9052] over deterministic CBOR [RFC8949], or in JWS over the canonical form. A CDDL definition of the v0.2 objects (`schemas/amep-v0.2.cddl`) and JSON Schemas (`schemas/v0.2/`) are published alongside this document.

### 12.3 Digests

`SHA-256(canon(o))`, as lowercase hex, is used for approval digests and content hashes.

### 12.4 Key discovery

A party publishing AMEP keys SHOULD serve a key set at `/.well-known/amep-keys.json`:

```json
{ "issuer-1": { "kid": "issuer-1", "alg": "Ed25519", "x": "<32-byte public key, hex>",
                "roles": ["issuer", "approver"],
                "nbf": 1767225600, "exp": 1798761600, "revoked": false } }
```

Verifiers MUST reject signatures made with a key outside its `nbf`–`exp` interval or marked revoked, using a trusted timestamp (RFC 3161 or Roughtime) where the signature time is disputed.

### 12.5 Signer roles

A valid signature only shows that a key signed an object. It does not show that the key's holder was entitled to make that statement. Without roles, a compromised host key could mint its own mandate or approve its own action, and the evidence would still verify. Every key in a key set MUST therefore carry `roles`, and a verifier MUST treat an object as unsigned unless its signing key holds a role permitted for the object's kind:

| Object kind | Permitted signer roles |
|---|---|
| `mandate`, `revocation`, `status` | `issuer` |
| `delegation`, `intent` | `issuer`, `host` |
| `interpretation`, `invocation`, `decision` | `host` |
| `effect` | `observer` |
| `approval` | `approver` |
| `finding` | `host`, `observer` |

Deployments SHOULD keep `approver` keys in hardware bound to a person (for example, a WebAuthn authenticator), and SHOULD give `host` and `observer` roles to different keys, so that one compromised key cannot both act and attest.

### 12.6 Transparency *(informative)*

High-assurance profiles register AMEP objects or periodic checkpoints as SCITT signed statements [SCITT-ARCH], with witness cosigning, so that selective logging and equivocation become detectable.

---

## 13. Bindings (informative summary)

Each binding is specified in a companion document under `spec/bindings/`: `authzen.md`, `mcp.md` and `host-profile.md` are drafted; the others are planned. Token and envelope formats that can carry AMEP authority and evidence are specified separately as profiles under `spec/profiles/` (Section 14.1).

| Binding | Mapping |
|---|---|
| **OpenID AuthZEN** | Invocation ⇄ evaluation request (subject, action, resource, context). ContinuityDecision ⇄ decision plus `amep` evidence refs. `step_up` ⇄ Access Request and Approval profile. `mediate` and receipts ⇄ obligations `amep.obligation.rewrite_input`, `amep.obligation.emit_effect_receipt`, `amep.obligation.snapshot_before`. |
| **OAuth** | Mandates and delegations from RFC 8693 token exchange (`act`, `may_act`), Rich Authorization Requests `authorization_details`, Transaction Tokens, and Cross App Access / ID-JAG. |
| **MCP** | Extension advertised in capability negotiation. `_meta` keys `amep.mandate_ref` and `amep.invocation_id` plus W3C trace context. Tool results MAY carry `amep.effect_receipt` (L3). Adapter manifests derived from `tools/list` and annotations count as `provider_hint` only. |
| **Agent hosts (`amep-host`)** | Prompt submission → IntentCertificate; sub-agent start → Delegation; pre-tool hook → Invocation + ContinuityDecision (with `rewrite_input` for mediation); post-tool hook → ExecutedEffectReceipt (L1); configuration change → I9; instruction loading → ContentFinding. Each host binding MUST publish its capability declaration (Section 11.2). |
| **OpenTelemetry** | `amep.*` span attributes alongside the GenAI semantic conventions. |
| **A2A** | Delegation records carried in task messages. |
| **AP2 (payments)** | Intent and Cart Mandates as PrincipalMandate and ApprovalBinding sources. |
| **IETF AUDIT** | AUDIT Interaction, Action, Delegation and Authorization Transition records carry the facts; AMEP is the continuity-evaluation profile over them. |

---

## 14. Profiles

A profile selects required objects and invariants for a domain. A profile MAY tighten, but MUST NOT loosen, any requirement of this core.

| Profile | Required objects | Invariants evaluated |
|---|---|---|
| **AMEP-Lite** | Invocation, ExecutedEffectReceipt, ContinuityDecision (signed, correlated) | I2, I3, I7 |
| **AMEP-Coding** | Lite + IntentCertificate, Delegation, ContentFinding; `amep-host` binding | I1–I4, I7–I11 |
| **AMEP-MCP** | Lite + AdapterInterpretation from pinned manifests; MCP binding | I2, I3 (with pinning), I7, I11 |
| **AMEP-SaaS** | Lite + L2/L3 receipts, data classes | I2, I5, I7, I10 |
| **AMEP-Payments** | AP2 mapping; ApprovalBinding with `presence` ≠ `none` | I2, I7, I8 |
| **AMEP-Health** | Data classes including `phi`; purpose binding | I2, I5, I7 |

### 14.1 Token and envelope profiles

AMEP evidence has exactly one mandatory format: objects canonicalized with JCS and signed with Ed25519 (Section 12). This guarantees that any two conformant implementations can verify each other's evidence. Token and envelope profiles describe how existing formats can **carry** AMEP authority or evidence. They never replace the mandatory format.

| Profile | Role | Document |
|---|---|---|
| **AMEP-Biscuit** | Preferred carrier for mandates and delegations: public-key verifiable, attenuable offline, with a constrained fact vocabulary that maps onto AMEP claims. | `spec/profiles/biscuit.md` |
| **AMEP-Macaroon** | Operational grants only. Macaroons are verified with a shared secret, so they are never third-party evidence; a verified Macaroon grant is restated as a signed AMEP mandate or delegation. | `spec/profiles/macaroon.md` |
| **AMEP-PASETO** | Transport envelope (`v4.public` or `v4.local`) around AMEP objects that already carry their own proof. | `spec/profiles/paseto.md` |
| **AMEP-UCAN** | Carrier for mandates and delegations between parties identified by DIDs. Holder-bound rather than bearer, so the token itself may be included in evidence. | `spec/profiles/ucan.md` |
| **AMEP-VC** | Wraps AMEP evidence as W3C Verifiable Credentials for external audit exchange. | `spec/profiles/vc-data-integrity.md` |

---

## 15. Conformance

### 15.1 Conformance levels

Conformance combines two questions: **where AMEP sits in a workflow** (an implementation's maturity) and **what another party can check independently** (its verifier interoperability). Each level includes every requirement of the levels below it.

| Level | Name | Requirements | Checked by |
|---|---|---|---|
| **0** | Observation | Emits Invocation and ExecutedEffectReceipt objects that validate against the schemas and are signed per Section 12. Decisions derived from logs carry `phase: post_execution`. | Schema validation; signatures verify |
| **1** | Mandate attached | Every Invocation cites an `authority_ref` that resolves to a signed mandate chain, or the packet shows the missing mandate (which evaluates to `unresolved`, I7). | Verifier finds no "no root mandate" results except where declared |
| **2** | Pre-execution decision | A PEP decides before governed actions and emits signed ContinuityDecisions with `phase: pre_execution` and an `enforcement` context. It runs fail-closed, or records a compensating control (Section 11.2). | Decision reconciliation (Section 10.3) |
| **3** | Delegated attenuation | Delegations and intents are emitted, narrow per Section 7, and (optionally) are carried in a token profile (`spec/profiles/`). | I1 holds on every chain |
| **4** | Independent verification | The implementation's verifier, or a third-party one, implements Section 10 and passes every vector in the conformance suite, returning the expected outcome **and** invariant. | The conformance suite |
| **5** | Cross-vendor interoperability | At least two independently written implementations pass the same suite version, and packets produced by one verify in the other without product-specific code. | Cross-verification of exchanged packets |

**Assurance qualifier.** An implementation at Level 2 or above MAY add **"Attested"** when its effects of class `write_shared` or above are observed at L2 or L3 and registered with a transparency service (Section 12.6).

**Verifier-only implementations** (auditor tools, libraries) claim Level 4 directly, as "Level 4 (Verifier)".

A claim of conformance MUST name the specification version, the level, any qualifier, the profile(s), and the version of the conformance suite passed. For example: *"AMEP v0.2 Level 2, Attested, AMEP-Coding profile, suite 0.2.0"*.

### 15.2 Conformance suite

The suite consists of:

- `vectors/keys.json`: the public keys used by the vectors;
- `vectors/positive/*.json`: packets that MUST evaluate to `preserved`;
- `vectors/must-reject/*.json`: packets that MUST evaluate to the stated `violated` or `unresolved` outcome and invariant.

Each vector file has the form:

```json
{ "name": "<description>",
  "expect": { "outcome": "violated", "invariant": "I6" },
  "packet": { ... } }
```

A Verifier passes a vector when the packet verdict and deciding invariant (Section 10.5) equal `expect`. Suite v0.2.0 has 95 vectors (25 positive, 70 must-reject); Appendix B lists them. Two independently written reference verifiers (Python, and JavaScript run both under Node.js and in the browser with WebCrypto) agree on all 95. Every vector packet except `malformed-timestamp` validates against both the JSON Schemas in `schemas/v0.2/` and the CDDL.

### 15.3 Requirements on changes

Every normative change to this specification MUST be accompanied by at least one positive and one must-reject vector that distinguish the new behaviour from the old.

---

## 16. Versioning and extensibility

- The specification, schemas and suite are versioned together using Semantic Versioning. Before 1.0, a minor version MAY contain breaking changes; after 1.0, breaking changes require a major version and a deprecation window of at least six months.
- A packet MAY declare `"amep_version": "0.2"`. Verifiers SHOULD reject packets declaring a major/minor version they do not implement.
- Extension members MUST use the `x-` prefix, or a reverse-DNS prefix (for example, `com.example.field`). Extensions MUST NOT change the outcome of the evaluation in Section 10. Extensions that need to change outcomes are profiles (Section 14).

---

## 17. Security considerations

- **Adversarial models (P0).** All guarantees assume models may lie. Invocations MUST be signed by the host or PEP, never by a key the model can use.
- **Key compromise and role confusion.** Signer roles (Section 12.5) limit what a single stolen key can forge: a host key cannot mint mandates or approvals, and an observer key cannot declare invocations.
- **Evidence omission by the assembler.** A packet's assembler may leave out unfavourable objects. AMEP limits what omission achieves: a missing receipt, status or signature yields `unresolved`, and revocable mandates require a fresh signed status (Section 5.12). Omission of *entire* invocations and their effects is detected only by I11 against an independent effect log, which is why high-assurance profiles need L2/L3 observers and transparency (Section 12.6).
- **Self-reporting.** Records produced by the actor alone are insufficient for high-impact effects (I10). Deployments SHOULD raise assurance to L2/L3 for `external_send` and above.
- **Canonicalization attacks.** Non-canonical resource forms enable bypasses (Section 6.2). Non-canonical JSON enables signature confusion; verifiers MUST verify over the canonical form they compute, never over bytes supplied in the packet.
- **Approval replay and TOCTOU.** Approvals bind the digest of the exact executed effect (I8) and are single-use.
- **Fail-open enforcement.** See Section 11.2. A verifier SHOULD treat an effect that contradicts a signed deny as bypass evidence (I11).
- **Guardrail tampering.** Agent writes to hook configuration, keys, instruction files or the evidence store are violations (I9).
- **Selective logging and equivocation.** Producers SHOULD include sequence numbers and heartbeats; high-assurance profiles SHOULD use transparency logs with witnesses (Section 12.5). An absent record is `unresolved`, never `preserved`, which limits but does not eliminate the effect of suppression.
- **Time manipulation.** Revocation and expiry depend on time. Producers SHOULD use trusted time sources; verifiers SHOULD treat clock skew beyond a declared tolerance as `unresolved`.
- **Algorithm downgrade.** Algorithms are pinned per key (Section 12.2).
- **Cross-audience replay.** Profiles SHOULD bind mandates to an audience and invocations to a session.
- **Token theft.** Mandates bound to keys SHOULD use proof of possession (DPoP or mTLS).
- **Compromised adapters or observers.** High-assurance profiles SHOULD require more than one independent observer for `destructive` and `financial` effects.
- **Insider abuse of the control plane.** Changes to protected resources and pinned adapters SHOULD require two-person approval.
- **Supply chain.** Reference implementations SHOULD publish signed releases with SLSA provenance.

---

## 18. Privacy considerations

Effect records can contain personal data. A verifier needs only canonical actions, resource identifiers, data-class labels and digests. Producers SHOULD detach and hash payloads, SHOULD encrypt fields per data class, and MAY use selective disclosure (SD-JWT or BBS+) for exports to auditors or customers. Retention SHOULD be enforced with retention-bound keys (crypto-shredding). Principal identifiers SHOULD be pseudonymous in exported packets unless the recipient needs to identify the person.

---

## 19. Registries

Until AMEP moves to a standards body, registries are maintained in the repository under `registries/`. Registration policy: **Specification Required**, reviewed by the maintainers.

### 19.1 Action namespaces

| Namespace | Meaning |
|---|---|
| `fs` | File system |
| `process` | Process execution |
| `http` | HTTP requests |
| `mail` | Email and messaging |
| `vcs` | Version control |
| `db` | Database |
| `pay` | Payments |
| `saas` | Generic SaaS record operations |

### 19.2 Data classes and multipliers

| Data class | Multiplier |
|---|---|
| `public` | 1 |
| `internal` | 1 |
| `source` | 1 |
| `confidential` | 2 |
| `secret` | 5 |
| `phi` | 5 |
| `pci` | 5 |

### 19.3 Effect classes and base costs

| Effect class | Base cost |
|---|---|
| `read` | 0 |
| `write_local` | 1 |
| `write_shared` | 3 |
| `external_send` | 5 |
| `destructive` | 10 |
| `financial` | 20 |

### 19.4 Recipient classes

`self`, `internal`, `partner`, `external`, `public`.

### 19.5 Assurance levels

`L0`, `L1`, `L2`, `L3` (Section 5.1.4).

### 19.6 Interpretation sources

| Source | Approved for I3 |
|---|---|
| `curated` | yes |
| `customer` | yes |
| `provider_hint` | no |
| `judge` | no |
| `none` | no |

### 19.7 Protected resources (initial entries)

Path segments: `/.claude/`, `/.codex/`, `/.cursor/`, `/.gemini/`, `/.git/hooks/`, `/.ssh/authorized_keys`.
File names: `AGENTS.md`, `CLAUDE.md`, `.mcp.json`, `.zshrc`, `.bashrc`.
Plus the deployment's own guardrail configuration, keys and evidence store (Section 8.1).

### 19.8 Obligation types

`amep.obligation.emit_effect_receipt`, `amep.obligation.rewrite_input`, `amep.obligation.snapshot_before`.

### 19.9 Vector identifiers

The file names in Appendix B, without extension, are stable identifiers.

---

## 20. References

### 20.1 Normative

- **[RFC2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119.
- **[RFC8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174.
- **[RFC8032]** Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032.
- **[RFC8785]** Rundgren, A., Jordan, B. and S. Erdtman, "JSON Canonicalization Scheme (JCS)", RFC 8785.
- **[RFC3339]** Klyne, G. and C. Newman, "Date and Time on the Internet: Timestamps", RFC 3339.

### 20.2 Informative

- **[RFC8610]** CDDL. **[RFC8949]** CBOR. **[RFC9052]** COSE.
- **[RFC8693]** OAuth 2.0 Token Exchange.
- **[AUTHZEN]** OpenID AuthZEN Authorization API 1.0.
- **[SCITT-ARCH]** IETF SCITT Architecture.
- **[AUDIT-ARCH]** draft-kuehlewind-audit-architecture.
- **[TRACE-CONTEXT]** W3C Trace Context.
- **[MCP]** Model Context Protocol specification.
- **[A2A]** Agent2Agent protocol. **[AP2]** Agent Payments Protocol.
- **[VC-DM-2]** W3C Verifiable Credentials Data Model 2.0.

---

## Appendix A. Worked example: revoked root with live child

A user's mandate `m-1` allows `fs.*` and `process.exec` on `repo:app/*` until t=100, with depth 2. The host delegates `d-1` (only `fs.write` on `repo:app/src/*`, until t=90, depth 1) to a sub-agent. The user revokes `m-1` at t=5. At t=10 the sub-agent writes `repo:app/src/auth.ts`, observed by the host at L1.

| Step | Check | Result |
|---|---|---|
| 1 | Chain `m-1 → d-1`, root is a mandate | pass |
| 2 | Signatures on `m-1`, `d-1`, `i-1`, `a-1` | pass |
| 3–4 | Interpretation `curated`, no pins | pass |
| 5 | `d-1 ⊑ m-1` (narrower actions, resources, validity; depth 1 < 2) | pass |
| 6 | Signed revocation of `m-1` at t=5 ≤ i-1.t=10 | **violated, I6** |

Packet verdict: `violated`, I6. The sub-agent's own delegation was valid; its authority died with its root. (Vector `must-reject/revoked-root-with-live-child`.)

---

## Appendix B. Conformance vector index (suite v0.2.0)

<!-- vector-index:start -->
*Generated by `tools/vector_index.py`; regenerate it whenever the suite changes.*

Suite: 95 vectors (25 positive, 70 must-reject).

**Positive (expect `preserved`):** `approved-adapter-revision--pinned`, `budget-from-earlier-packets-still-within-limit`, `build-cleanup-within-scope`, `delegation-adds-a-deny`, `deny-honoured-on-fail-closed-host--no-effect`, `derived-data-sent-to-an-allowed-recipient`, `fresh-revocation-status`, `independently-observed-high-impact-effect`, `influence-confirmed-by-principal`, `influenced-read-only-action`, `jcs-canonical-form--unicode-keys--floats`, `mediated-effect-honored`, `mutation-influenced-only-by-trusted-content`, `quarantined-content-promoted-by-the-principal`, `reversible-write-is-cheaper`, `revoked-after-the-action--still-preserved`, `rfc-3339-timestamps`, `risk-budget-exceeded--human-approved`, `same-effect-observed-twice--host-and-backend`, `simulated-deny-is-not-enforcement`, `two-hop-chain-within-bounds`, `valid-bound-approval`, `valid-preserved-flow`, `validity-window-and-purpose-carried-through`, `within-risk-budget`.

**Must-reject:**

| Invariant | Outcome | Vectors |
|---|---|---|
| I1 | violated | `delegation-adds-data-class`, `delegation-changes-purpose`, `delegation-depth-not-decreasing`, `delegation-drops-nbf`, `delegation-extends-validity`, `delegation-from-a-zero-depth-parent`, `delegation-removes-a-deny`, `delegation-widens-resources`, `delegation-widens-risk-budget`, `delegation-without-depth-under-bounded-parent`, `expand-then-shrink-delegation` |
| I2 | violated | `budget-spent-in-earlier-packets`, `cumulative-spend-exceeds-budget`, `declared----executed--path-retarget`, `denied-action`, `destructive-command-drift--a3`, `effect-after-mandate-validity`, `effect-before-validity--nbf`, `effect-on-a-denied-resource`, `effect-outside-delegated-scope`, `intent-cannot-lift-a-deny`, `intent-narrower-than-grant`, `lying-adapter-caught-by-backend--l3`, `mediated-effect-not-honored`, `rfc-3339-effect-after-expiry`, `risk-budget-exceeded-without-approval`, `second-effect-outside-declared` |
| I3 | unresolved | `interpretation-from-provider-hint-only`, `unapproved-adapter-revision`, `unknown-interpretation` |
| I4 | violated | `injection-driven-mutation`, `quarantined-content-reached-the-agent--a1`, `unsigned-finding-claims-trusted` |
| I5 | violated | `data-leaving-after-a-read--a5`, `secret-released-externally--i5` |
| I6 | violated | `revoked-root-with-live-child`, `status-shows-revoked-before-action` |
| I7 | unresolved | `deny-on-fail-open-host--no-effect-record`, `forged-mandate--attacker-key`, `identity-only-authorization--no-mandate`, `intent-reference-unresolved`, `invocation-signed-by-unknown-key`, `lineage-reference-not-found`, `malformed-timestamp`, `mandate-minted-by-host-key`, `missing-effect-receipt`, `missing-parent-lineage`, `post-execution-decision-cannot-claim-a-block`, `revocable-mandate-without-status`, `self-approval-signed-by-host-key`, `stale-revocation-status`, `tampered-effect-receipt`, `unsigned-approval`, `unsigned-intent`, `unsigned-invocation`, `unsigned-revocation-on-the-chain` |
| I7 | violated | `recorded-budget-spend-mismatch` |
| I8 | violated | `approval-digest-mismatch--toctou`, `approval-replay--consumed`, `approval-reused-across-packets`, `approval-reused-for-a-second-invocation`, `stale-approval--expired` |
| I9 | violated | `guardrail-write--i9`, `guardrail-write-via-absolute-path--i9`, `mediated-into-a-guardrail-path--i9` |
| I10 | unresolved | `high-impact-effect-without-actor`, `self-reported-high-impact-effect` |
| I11 | violated | `audit-only-discovery-of-an-unknown-agent--a6`, `bypass--effect-without-invocation`, `deny-contradicted-by-executed-effect` |
<!-- vector-index:end -->

**Planned for v0.3:** unknown MCP endpoint; MCP manifest rug-pull; tool shadowing; compound command; obfuscated execution; script indirection; GET with side effects; GraphQL mutation via POST; key/token read; agent impersonation; self-approval without presence; approval-fatigue loop; taint exfiltration via an allowed channel; memory-poisoned sleeper mutation; revocation quiescence breach; mediation-proof mismatch; approval reuse across packets.

---

## Appendix C. Relationship to other work (informative)

| Work | Relationship |
|---|---|
| OAuth Token Exchange, Transaction Tokens, Cross App Access / ID-JAG | Sources of mandates and delegation. AMEP verifies that effects stayed within them. |
| OpenID AuthZEN (+ Approval, Obligations) | Decision transport. A ContinuityDecision is an AuthZEN decision plus evidence. |
| IETF AUDIT | Record layer. AMEP is the continuity-evaluation profile over AUDIT records (see `draft-…-audit-continuity-evaluation`). |
| IETF SCITT | Transparency for AMEP objects and checkpoints. |
| draft-sharif-agent-audit-trail | Logging format that can supply Invocation and Effect evidence. |
| Agent Receipts (W3C VC) | One possible encoding of ExecutedEffectReceipt. |
| ISO/IEC 24970 | AI system logging information model; AMEP is offered as an agentic profile. |
| MCP, A2A | Carriage of AMEP references. |
| AP2 | Payments mandates map to PrincipalMandate and ApprovalBinding. |
| IGAC, CaMeL, FIDES, Progent | Enforcement techniques that can emit AMEP evidence. |
| Macaroons, Biscuit, UCAN | **Capability tokens with built-in attenuation.** They and AMEP share the same rule, that delegated authority may only narrow (AMEP's I1), but they enforce it differently. In a token, attenuation is structural: a holder can add restrictions (macaroon caveats, Biscuit blocks, UCAN proofs) but cannot remove them, so a widened token never verifies. AMEP instead records delegations as separately signed claim sets and has the verifier check ⊑ afterwards, so a widening is *detected* (`violated`, I1) rather than made impossible. The two compose: a deployment MAY carry the PrincipalMandate and Delegations as Biscuit or UCAN tokens, map their facts or capabilities onto AMEP claims, and keep AMEP for what tokens do not cover (interpretation, intent, independently observed effects, approvals bound to effects, and the three-valued outcome). Biscuit and Macaroon profiles are specified in Section 14.1; a UCAN profile is planned. |
| PASETO | **Envelope.** `v4.public` tokens use Ed25519 and can carry signed AMEP objects in transit (Section 14.1). |
| W3C Verifiable Credentials, Data Integrity | **Audit exchange format** for AMEP evidence (Section 14.1). |
| AgentDojo, MasDrift | Benchmarks; AMEP's benchmark profile reports results in a common format. |

---

## Appendix D. Changes from v0.1

- Added P0 (untrusted-model assumption) and P9 (mediation).
- Added IntentCertificate, ContentFinding and the enforcement context of ContinuityDecision.
- Added invariants I8 (approval binding), I9 (self-protection), I10 (observer independence) and I11 (no orphan effects).
- Added risk-budget accounting (Section 9).
- Made canonical resource identifiers normative (Section 6.2).
- Defined a deterministic evaluation order and packet verdict (Section 10).
- Defined conformance levels and a 95-vector suite.

**Within v0.2 drafts:**

- *draft.1:* attenuation now enforces `nbf`, `purpose` and the depth rules; cited intents must exist and be signed; I9 also applies to the executed resource.
- *draft.2:* signer roles (Section 12.5); signed revocations and revocation status (Section 5.12); `actor` required for high-impact effects; every effect receipt of an invocation is evaluated; approval digests exclude `t`, with a validity window and single use; findings count as trusted only when signed; RFC 3339 times; exact RFC 8785 canonicalization; JSON Schemas per object; AuthZEN, MCP and host bindings.
- *draft.3:* `phase` on every decision, so detection is never presented as mediation; `quarantine` decisions for untrusted content; deny lists in claims (`deny_actions`, `deny_resources`) that only grow along a chain; conformance Levels 0–5 with an "Attested" qualifier; Biscuit, Macaroon, PASETO and Verifiable Credential profiles; a mapping from common product decision labels; vectors for the injection-quarantine, destructive-drift and audit-only scenarios.
- *draft.4:* data lineage (`accessed`, `recipient`, `derived_from`; Sections 5.9.1 and 10.6), which detects data leaving after a read; verifier state across packets (Section 10.7); a UCAN profile; a second, independent JSON Schema validator.

---

## Appendix E. Open issues

- **E.1 Workflow-level outcomes.** Composition and disclosure across many invocations (WorkflowContinuityDecision) are reserved for v0.3.
- **E.2 Revocation quiescence.** A window Δ for revocations still propagating is needed for I6 in distributed deployments.
- **E.3 Signed verifier state.** State across packets (Section 10.7) is the verifier's own bookkeeping. A standard signed format for publishing it is not yet defined.
- **E.4 Token-profile vectors.** The Biscuit, Macaroon and UCAN profiles have no conformance vectors yet. They need a profile-aware verifier that maps tokens onto claims, built on reference token libraries.
- **E.5 Lineage completeness.** A verifier can check the lineage it is given (Section 5.9.1) but cannot detect lineage a host failed to record.

*Resolved in draft.2:* exact JCS, approval timing and key-to-role binding, and the reference-verifier divergences found in draft.1. *Resolved in draft.3:* the capability-token profile (Biscuit, Macaroon), and CDDL validation: the CDDL is checked with the `cddl` tool and every vector validates against it (`tools/validate_cddl.py`). That check found and fixed a clash between AMEP's time type and the `time` type built into the CDDL prelude. *Resolved in draft.4:* state across packets, data leaving after a read, the UCAN profile, and a second JSON Schema validator (the `jsonschema` library now runs alongside the built-in one, and the two must agree on every vector).
