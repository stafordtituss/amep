# Agentic Mandate Evidence Protocol (AMEP™) — Core Specification

| | |
|---|---|
| **Document** | `amep-core` |
| **Version** | 0.3.0-draft.1 (working draft; v0.2 packets evaluate as before, see Section 16) |
| **Date** | 2026-11-22 |
| **Status** | Public Draft. Not endorsed by any standards body. |
| **Author and editor** | Staford Titus Selvaraj (Independent) |
| **Repository** | https://github.com/stafordtituss/amep |
| **DOI** | [10.5281/zenodo.24317758](https://doi.org/10.5281/zenodo.24317758) (all versions) |
| **IETF** | [draft-stafordtituss-agentic-mandate-evidence](https://datatracker.ietf.org/doc/draft-stafordtituss-agentic-mandate-evidence/) |
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

This document is the **core**: data model, claim algebra, invariants, evaluation, cryptography and conformance. Bindings (Section 13) and profiles (Section 14) are summarized here and specified in companion documents. Objects marked *reserved* in Section 5.15 are named so that implementations do not collide with them, but are not normative in v0.2.

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
| `call_statements` | CallStatement objects (Section 5.14) *(v0.3)* |
| `pinned_adapters` | map of adapter id → approved version |

Object `id`s are unique within a packet (v0.3): a packet in which two objects share an `id` is malformed, and every invocation in it is `unresolved` (I7). Otherwise a receipt or statement could be read as evidence for the wrong object.

Unknown members whose names begin with `x-` MUST be ignored by verifiers. Unknown members without the prefix SHOULD cause a verifier to report a warning and MUST NOT change the outcome.

### 5.3 Claims

A claim set states what may be done. It appears in mandates, delegations and intents.

| Field | Type | Req. | Meaning |
|---|---|---|---|
| `actions` | array of action patterns | **yes**³ | Canonical actions permitted (Section 6). |
| `resources` | array of resource patterns | **yes**³ | Canonical resources permitted (Section 6). |
| `grants` | array of `{actions, resources}` | **yes**³ | *(v0.3)* Authority as a union of products: each grant permits its actions on its resources, and no action of one grant on a resource of another. |
| `data` | array of data flows | no | Data flows permitted. Absent means none. |
| `ceiling` | effect class | **yes** | Highest effect class permitted. |
| `exp` | time | **yes** | End of validity. |
| `nbf` | time | no | Start of validity. Absent means unbounded below. |
| `purpose` | string | no | Purpose token. Absent means unrestricted. |
| `deny_actions` | array of action patterns | no | Actions forbidden even if `actions` would allow them. Absent means none. |
| `deny_resources` | array of resource patterns | no | Resources forbidden even if `resources` would allow them. Absent means none. |
| `depth` | unsigned integer | no | Remaining delegation depth (Section 7.2). |
| `budget` | unsigned integer | no | Risk budget in points (Section 9). |
| `limits` | array of limits | no | Caps on quantities, such as money moved or records read, per call and per period (Section 7.6). *(v0.3)* |
| `audiences` | array of audience patterns | no | *(v0.3.2)* The services at which the authority may be exercised, such as `tool:reports-api`. Absent means any. |

³ A claim set carries either `actions` and `resources`, or `grants`. In an AMEP 0.3 packet, `grants` beside `actions` or `resources`, an empty `grants`, or a grant that is not exactly `{actions, resources}` with non-empty lists, is malformed: `unresolved` (I7). In an unversioned packet `grants` is also malformed (`unresolved`, I7). It is an AMEP 0.3 member, and ignoring it, as v0.2 ignores unknown members, could widen authority the producer meant to narrow.

**Audiences** *(v0.3.2)*. A presentation bound to one service can be replayed to another, with an action and resource that are both in scope; without an audience in the claims, that effect is `preserved`. `audiences` binds the authority to the services it may be exercised at, with the pattern syntax of resources (Section 6). Where the effective claims carry `audiences`:
- every receipt MUST record, in its executed body, the `audience` the effect was sent to; otherwise `unresolved` (I7), gap `audience`;
- an effect whose `audience` matches none of them is outside authority: `violated` (I2);
- a delegation under a parent with `audiences` MUST carry `audiences` within the parent's; otherwise `violated` (I1);
- along a chain the effective audiences are the intersection.

`audiences` is an AMEP 0.3 member: in an unversioned packet it is malformed (`unresolved`, I7), as for `grants`, because a v0.2 verifier would ignore it and widen authority. Audience may also be folded into resource names (for example `tool:reports-api/reports/…`), but two producers may encode that differently; `audiences` is the one stated form. From stafordtituss/amep#16, found by running the delegation suite of delegation-control-bench (scenario VC-03).

Denies let a claim set say "everything under this prefix except…", which allow-lists alone cannot express. Denies only ever grow along a chain (Section 7.1), and an intent cannot lift one (Section 7.3).

**Grants** *(v0.3)*. `actions` and `resources` permit every action on every resource: a product. Many grants are not products. For example, read the documents, and write the reports but not the documents. One product can express that only by widening it. `grants` lists several products, and their union is the authority. Plain `actions` and `resources` are one grant, so the two forms mix along a chain:
- An executed effect satisfies the claims when one grant permits both its action and its resource (I2).
- A delegation is narrower than its parent when each of its grants lies within one grant of the parent (I1). This never accepts a widening. It may reject a child grant that only the union of several parent grants covers; split such a grant to match.
- Along a chain, the effective authority is the pairwise intersection of the nodes' grants.

Motivated by comparing AMEP with the Delegation Receipt Protocol (draft-nelson-agent-delegation-receipts), whose scopes allow (operation, resource) pairs (`interop/drp/`).

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
| `declared` | **yes** | `{ action, resource, effect }`: canonical action, canonical resource, effect class. It may also carry `scope` (Section 5.8.2). |
| `mediated` | no | An executed-effect body (Section 5.9) that a PEP substituted. |
| `influenced_by` | no | Array of ContentFinding `id`s whose content was in the agent's context. |
| `principal_confirmed` | no | `true` if the host says the principal confirmed this invocation after seeing the influence. On its own it confirms nothing: the confirmation is the principal's signed approval (Section 5.11.1). *(v0.3.3)* |
| `derived_from` | no | `id`s of **earlier** invocations whose outputs fed this one (Section 5.9.1). |
| `budget_spent` | no | Points charged for this invocation (Section 9). |
| `args_digest` | no | SHA-256 (lowercase hex) of the canonical form of the arguments the host sent with the call (Section 5.14). *(v0.3)* |
| `reserve` | no | `{ amount, unit }`, as in Section 5.9.2: the most this call can move in the unit. While the call has no known outcome, it is held against the period limits on its chain in later packets (Section 7.6, rule 6). Without it, an unknown outcome holds an unknown amount. *(v0.3)* |
| `operation` | no | An identifier for the logical operation this call attempts, the same on every attempt: a retry, or a re-run under a fresh authorization, carries the operation of the first attempt. A string of 1 to 256 characters, chosen by the host or the agent's runtime (Section 5.8.1). *(v0.3.2)* |
| `correlation` | no | Section 4.3. |
| `proof` | **yes**¹ | Signed by the host or PEP, not by the model. |

#### 5.8.1 Operation identity *(v0.3.2)*

An agent whose call has an unknown outcome (the response was lost, or the host crashed after dispatch) may try again, often under a fresh authorization: a new approval, a new token or a new mandate. Without a record that the second call is the same logical operation as the first, a verifier evaluates it on its own, and if both took effect, the operation ran twice with no rule broken. `operation` is that record. Its rules, applied after every other check on the invocation so that they never hide a violation:

1. **One operation takes effect at most once.** If an invocation with effect receipts carries an operation that an earlier invocation already took effect under (in this packet, or in an earlier one through state, Section 10.7), the result is `violated` (I2), "executed twice", blamed on the agent.
2. **An unknown outcome holds the operation.** An invocation with no effect receipts and no `not_executed` statement holds its operation, unless the operation is already held or done. A later invocation of a held operation is `unresolved` (I7), gap `held_outcome` naming the holding invocation, whatever authorization it carries: a fresh authorization doesn't clear the hold.
3. **A hold is released** when the holding invocation is shown not executed (a `not_executed` statement, Section 5.14), or when it is shown to have taken effect, in which case the operation is done and rule 1 applies to the retry. **What counts as a showing:** a statement that verifies, signed by an observer, and, for a call of class `write_shared` or above, one that meets I10 (Section 5.14, rule 5): from a party other than the actor: not signed by the key that signed the invocation, and under another operator where operators are named. A statement signed only on the actor's side shows nothing, whatever name it gives in `observed_by`, so the outcome stays unknown and every hold stays: the operation, its approval (Section 5.10) and its reserve against period limits (Section 7.6, rule 6). A release must not rest on the word of the party that benefits from it.
4. **Other operations proceed.** A hold blocks only invocations of the same operation.

`operation` is chosen by the party that retries, so it binds only what that party records: an agent that retries under a new operation identifier evades these rules. A verifier SHOULD therefore require it of hosts that retry, and a gateway that retries on the agent's behalf SHOULD reuse the identifier. This rule came from a review by Andrii (Radiolaria) on the OpenID AIIM list, comparing AMEP with a host that binds authorization to operation identity.


#### 5.8.2 Calls whose effects aren't known in advance *(v0.3.3)*

A call usually names its one effect in `declared`, and every effect receipt for it must match that action and resource exactly; one that doesn't is `violated` (I2), charged to the server. Some calls can't name their effects in advance. A shell command such as `npm install` writes files chosen by the program it runs, not by the agent. Under the exact rule, every one of those writes reads as a departure charged to the server, whether or not it was within the grant.

`declared.scope` is for such calls: `{ actions, resources }`, each a non-empty list of patterns (Section 6), the same shape as a grant (Section 5.3). `action`, `resource` and `effect` still name the call itself, for example `process.exec` on `cmd:npm install`, declared `write_local`. With a scope, an effect receipt matches the declaration when:
1. its action matches one of `scope.actions`;
2. its resource matches one of `scope.resources`;
3. its effect class is at most `declared.effect`.

An effect that matches is then judged against the effective claims like any other. One outside the grant is `violated` (I2), charged to the agent, since the agent chose to run the call. An effect that doesn't match the scope is `violated` (I2), charged to the server, as before.

A scope makes nothing permitted that the claims don't permit. It only decides whose departure an unexpected effect is. `scope` is an AMEP 0.3 member: in an unversioned packet, or when it isn't exactly `{actions, resources}` with non-empty lists, the packet is malformed (`unresolved`, I7). Ignoring it, as v0.2 ignores unknown members, would change which party a departure is charged to. Found while importing Kilo Code sessions (`interop/kilo/`).

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
| `invocation_digest` | no | SHA-256 of the canonical form of the signed invocation, **including its proof**, that this effect results from (Section 5.14). *(v0.3)* |
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
| `audience` | no | *(v0.3.2)* The service the effect was sent to, as the observer saw it. REQUIRED where the effective claims carry `audiences` (Section 5.3). |
| `t` | **yes** | Time of execution. |

#### 5.9.2 Quantities *(v0.3)*

The executed-effect body MAY carry `value`, the quantity the effect moved or touched:

| Field | Req. | Meaning |
|---|---|---|
| `amount` | **yes** | An exact decimal **string**: `0` or a digit 1–9 followed by at most 38 digits, optionally a `.` and 1–18 digits. No sign, exponent or leading zeros. For money it is the total debited from the principal, fees included; with currency conversion, the debit side. In a `caip19:` unit the amount is an **integer in the asset's smallest unit** (as the chain records it, for example 100 USDC is `"100000000"`), with no fractional part, so no decimals lookup is needed and a uint128 fits. |
| `unit` | **yes** | `namespace:identifier`, matching `[a-z][a-z0-9-]{0,31}:[!-~]{1,128}`. Money uses `iso4217:` (for example `iso4217:EUR`) or `caip19:` followed by a CAIP-19 asset id. Other quantities use, for example, `count:records`, `count:messages` or `bytes:…`. Units are compared as exact strings; a Verifier never converts between units. |
| `period_spent` | no | The observer's own totals, including this effect, in the same unit, **keyed by period length in seconds**. Each total is `{ from, total }`: the start of the window it covers, and the amount. For example: `{"86400": {"from": 1767225600, "total": "80.00"}, "2592000": {"from": 1765152000, "total": "1030.00"}}`. One figure can't be both a daily and a monthly total. Signed with the receipt; counted only for a limit that names this observer in `counted_by`, and only when `from` is the start of that limit's window (Section 7.6). A bare amount in place of `{ from, total }` names no window, so it never counts as a limit's total. |

Amounts are compared as exact decimals, never as binary floating point. A Producer MUST encode amounts as strings; a `value` that does not match this grammar makes the result `unresolved` (I7). Refunds are separate effects: an amount is never negative, so one effect cannot offset another.

#### 5.9.1 Data lineage

`released` records the data flows an effect *declares*. An agent that reads a confidential document and then posts "a summary" to an external service may declare no release at all. Lineage closes that gap:

- An effect that reads data records the data classes it obtained in `accessed`.
- An invocation whose input came from earlier steps lists them in `derived_from`.
- An effect that sends or writes somewhere records the `recipient` class.

The **carried classes** of an invocation are the `accessed` classes of its own effects, plus the carried classes of every earlier invocation it is `derived_from`, transitively. For each effect with a `recipient` r, every class d among its own `accessed` classes and the carried classes of the invocations it is derived from produces the flow `d->r`, which MUST be permitted by the effective claims' `data`. Otherwise the result is `violated` (I5).

Hosts that cannot track precisely which outputs fed which inputs MUST be conservative: list in `derived_from` every earlier invocation of the same session whose output entered the agent's context. Lineage that is missing cannot be detected by a verifier. This is one reason profiles that handle sensitive data (AMEP-SaaS, AMEP-Health) require L2/L3 observers at the egress point.

### 5.10 ApprovalBinding (`kind: "approval"`)

A human approval bound to one exact effect, or to the exact effects of one call (an **operation approval**, v0.3).

| Field | Req. | Meaning |
|---|---|---|
| `id`, `kind` | **yes** | |
| `effect_digest` | **yes**² | Lowercase hex SHA-256 of the canonical form (Section 12.1) of the approved executed-effect body **with its `t` member removed, and with `value.period_spent` removed** (v0.3). |
| `effect_digests` | **yes**² | *(v0.3)* For an operation approval: a non-empty array of such digests, one per approved effect of one invocation. A digest listed *n* times approves *n* executions of that body. |
| `presence` | **yes** | `webauthn`, `chat_user`, `host_ui` or `none`. |
| `approver` | no | Identifier of the approver. |
| `resource_version` | no | Version of the resource at approval time (for example, an ETag or commit hash). |
| `nbf` | no | Time before which the approval may not be used. |
| `expiry` | no | Time after which the approval is void. Producers SHOULD set it. |
| `consumed` | no | `true` once the approval has been used. |
| `proof` | **yes**¹ | Signed by a key with role `approver` (Section 12.5). |

² Exactly one of `effect_digest` and `effect_digests` is present. An approval with both, with an empty or malformed `effect_digests`, or with neither, is malformed: `unresolved` (I7).

The digest excludes `t`, and the observer's running totals in `value.period_spent`, so that an approval can be issued before execution, when neither is known yet. Time is bound instead by the approval's `nbf`–`expiry` window, which MUST contain both the invocation time and the execution time. An approval is **single use**: within a packet, one approval MAY cover only one invocation and one executed effect. The same effect recorded by several observers counts once, but if one observer records the approved body more than once, the approval was used for several effects: `violated` (I8) (v0.3). Verifiers that see approvals across packets SHOULD track use across packets too.

An **operation approval** (v0.3) covers one invocation whose call has several effects, for example one admission for an operation that writes two files. Every executed effect of that invocation MUST match a listed digest, and no body MAY be executed more often than it is listed; otherwise the result is `violated` (I8). An approved effect that was not executed is not a violation: the call did less than was approved. The approval is single use like any other, so a second invocation that cites it, such as a retry of the same operation, is `violated` (I8). Motivated by Takao Sato's VATE reference case 1 for openid/authzen#795 (a lost response and its recovery). A verifier that does not implement operation approvals finds no `effect_digest`, and never returns `preserved` for one. Earlier reference verifiers returned `unresolved` (Python) or `violated` (JavaScript).

**Held approvals** *(v0.3)*. An invocation that cites an approval may reach the receipt check of Section 10.2 (its chain, signatures and interpretation verified) with no receipt and no `not_executed` call statement. The call may have run under the approval, so the Verifier **holds** the approval for that invocation, within the packet and across packets through verifier state (Section 10.7).
- While the approval is held, another invocation whose effects it would cover is `unresolved` (I7), with gap `held_outcome` naming the holding invocation. It is not `preserved`: if the holder's receipts later appear, the approval was used twice.
- A later packet that contains the holding invocation decides it afresh and replaces the hold:
  - with its receipts, the approval is used by the holder, and another invocation's use of it is `violated` (I8) as before;
  - with a `not_executed` statement, the hold is released and the approval is free;
  - if its outcome is still unknown, the hold stays.
- Checks that decide `violated` (the approval is not bound to the effect, is consumed, has expired or is not yet valid) come first. A held approval only turns what would otherwise be `preserved` into `unresolved`.

**Facts are counted completely; blame is charged once** *(v0.3.2)*. Checks that decide `violated` come before any hold, in both the approval and the operation rules (Section 5.8.1), and an approval's use is recorded before its hold is checked, so no hold hides a double use. An operation is done once a receipt for it verifies and no statement contradicts it, even if the call is `violated` for another reason. A call that is `violated` is charged once, for its first violation, and its use of an approval is not counted against later calls: a later call is judged on what it could see, and the double use is already reported on the earlier call. That holds only while the earlier call stays `violated`. If a later packet resolves its violation, its use of the approval MUST be counted again, so that the double use is not left charged to nobody. These orderings were found by checking the rules exhaustively against the reference verifier (`formal/`); the last point is from Brennan Zambo's review of #24.

This follows Takao Sato's VATE case 2, accepted work interrupted (openid/authzen#795). Without it, a second runtime that re-ran an interrupted operation under the same single-use admission came out `preserved`, and only later evidence revealed the double use. It is the approval counterpart of held limits (Section 7.6, rule 6).

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

#### 5.11.1 Principal confirmation *(v0.3.3)*

A call shaped by untrusted content (rule 9 of Section 10.1), or one that received quarantined content (Section 10.1, quarantine check), is cleared only when the principal confirmed it after seeing that content. The confirmation is an ApprovalBinding (Section 5.10) that the invocation cites in `approval_ref`, signed by an `approver` key, with `findings`: the ids of every finding the principal was shown. It names the principal of the chain's root mandate as `approver`, and its `presence` is `webauthn` or `chat_user`: `host_ui` and `none` would be the host vouching for itself again. Binding the approver *key* to the principal needs a record from key to principal, which AMEP doesn't define yet; until it does, a profile that needs that binding issues approver keys per principal. Like any approval it is bound to the executed effect and is single use (Section 5.10).

`principal_confirmed: true` on the invocation is signed by the host, which is the party being judged, so it never clears a call on its own. When it is present without a confirmation that covers the findings, the result is `unresolved` (I4), gap `principal_confirmation`. The host's word is enough to ask for the record, never enough to clear the call. Without the flag, the results are as before: `violated` (I4) when effects exist, otherwise `unresolved`. This came from tclancy's review (stafordtituss/amep#34). Before it, a host-signed flag turned an injection-driven write from `violated` into `preserved`, the same shape as the self-signed deny fixed in #15.

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

1. A **signed** revocation, or a signed status with `revoked_at`, at or before the invocation time **or the time of any effect of the invocation** makes the result `violated` (I6). *(v0.3: effect times were added. A "preserved" result now establishes that authority was in force when each effect occurred, not only when the call was made. Raised by Cliff Singletary on the IETF audit list, 19 November 2026.)*
2. An **unsigned or unverifiable** revocation targeting the chain makes the result `unresolved` (I7). It can neither be trusted nor safely ignored.
3. For every chain element that carries `revocation.status_ref`, the packet MUST contain a signed status with `as_of` at or after the invocation time **and at or after each effect's time**. Otherwise the result is `unresolved` (I7).

#### 5.12.1 Propagation window *(v0.3)*

A mandate or delegation MAY declare `revocation.window`, a non-negative number of seconds, at most 3600, signed with it. When a revocation of that node takes effect at time r, an invocation or effect at time t with r ≤ t < r + window is still within the authority as granted: the window is part of the grant the issuer signed, so the result is `preserved`, and its reason names the revocation and the window. At or after r + window it is `violated` (I6). A window larger than 3600 seconds is malformed (`unresolved`, I7), so that a window cannot be used to keep revoked authority alive indefinitely. *(v0.3.3)* Until v0.3.3 an action inside the window was `unresolved`, with gap `revocation_settled`. tclancy pointed out (stafordtituss/amep#35) that nothing is missing in that case: no record could settle it, so a consumer that routes `unresolved` to "fetch more evidence" would chase a record that doesn't exist. An absent window is 0, which is the behaviour of rule 1. Because the window is part of the signed node, a packet's assembler cannot widen it.

*(v0.3.5)* Such a result also carries `within_window`: `{"ref": <the revoked node's id>, "revoked_at": <the revocation's time, as the revocation or status gives it>, "window": <seconds>}`, naming the first revocation whose window it fell inside. A Verifier MUST include it on a `preserved` result exactly when an invocation or effect of that result fell inside a window, and MUST NOT include it otherwise. A consumer can then count actions inside a window apart from actions before any revocation, without parsing the reason; this case's reason code is `preserved_within_declared_window`. The code was asked for in OWASP/Agentic-Evidence#21, and the structured member by tclancy (stafordtituss/amep#41).

The 3600-second bound is the most any grant may declare. A profile (Section 14) MAY set a lower maximum, and treat a grant that declares more as malformed under that profile.

Profiles that need high assurance SHOULD require `revocation.status_ref` on every mandate.


#### 5.12.2 Clocks of different operators *(v0.3.4)*

A revocation's time is reported by the authority source, and an effect's by its observer. When the two are different operators, their times come from different clocks, and AMEP can't order them more finely than those clocks agree. A key in the key set MAY declare `clock_skew`: the most, in seconds, by which the times its signer reports may differ from true time, from 0 to 3600. A larger value, or one that isn't a number, is malformed (`unresolved`, I7). The skew comes from the key set, never from the packet, so a packet's assembler can't widen it.

For each revocation of a node on the chain, at time r, and an invocation or effect at time t:
- let the boundary be b = r + window, using the node's propagation window (Section 5.12.1), or r where there is none;
- let the skew be the sum of the `clock_skew` declared by the key that signed the revocation (or the status) and by the key that signed the invocation or effect.

If the skew is greater than zero, the two keys are not one party (the same key, or keys of the same operator, Section 12.5), and |t − b| ≤ skew, then the result is `unresolved` (I6), gap `ordering`. Which side of the boundary the action fell on is not established. Otherwise the rules of Sections 5.12 and 5.12.1 apply unchanged. With no `clock_skew` declared, nothing changes.

From the `unordered-revocation` variant of the OWASP Agentic Evidence scenario D (OWASP/Agentic-Evidence#21), where the revocation and the write carry times from separate clocks. Tracked as stafordtituss/amep#43. Before v0.3.4, AMEP compared the two numbers as if one clock had produced both.
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

**Quarantine.** `mode: quarantine` means the PEP withheld untrusted content from the agent (typically by replacing a tool's output before the model saw it). The tool call itself may have run. A verified `pre_execution` quarantine names the withheld findings in `quarantined`. Any **later** invocation, in packet order, that lists a quarantined finding in `influenced_by` shows that the content reached the agent anyway; unless the principal confirmed it (Section 5.11.1), the result is `violated` (I4), whatever the invocation's effect class.

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

### 5.14 CallStatement (`kind: "call_statement"`) *(v0.3)*

The observer's signed account of one call. Receipts say what was executed. A call statement also says what *was not*, and how many receipts belong to the call, so that a missing receipt can be told apart from an effect that never happened. It also binds the call to one exact signed invocation and to the arguments the executing party received.

| Field | Req. | Meaning |
|---|---|---|
| `id`, `kind` | **yes** | |
| `invocation` | **yes** | `id` of the invocation. |
| `observed_by` | **yes** | Identifier of the observer, as in its receipts. |
| `disposition` | **yes** | `completed`, `not_executed` (nothing was executed), or `failed_after_effects` (the call failed after executing the effects it counts). |
| `effect_count` | **yes** | Number of receipts this observer issued for the call. `0` when `not_executed`. |
| `t` | **yes** | Time of the statement. |
| `invocation_digest` | no | As in Section 5.9: binds the statement to the exact signed invocation. |
| `args_digest` | no | SHA-256 of the canonical form of the arguments the observer received. |
| `proof` | **yes**¹ | Signed by a key with role `observer`. |

Rules (applied in Section 10.2: rules 1 to 5 at step 9a, before the receipts are checked; rule 6 at step 14a, after them):

1. A statement that does not verify, has an unknown `disposition`, a negative or non-integer `effect_count`, or `not_executed` with a non-zero `effect_count` makes the result `unresolved` (I7).
2. A statement or receipt whose `invocation_digest` differs from the digest of the invocation in the packet is not evidence for that invocation: `unresolved` (I7). A genuine receipt for one call therefore cannot be presented for another call that reuses its `id`.
3. If the invocation carries `args_digest` and a statement's `args_digest` differs, the call was changed between the host and the observer: `violated` (I2), or `unresolved` (I7) when the statement says `not_executed`.
4. A receipt for an invocation that a statement says was `not_executed` is equivocation: `violated` (I11).
5. With no receipts and a verified `not_executed` statement, the invocation provably had no effect, and its evaluation ends with `preserved`. For a call declared `write_shared` or above, the statement must come from an observer other than the actor: it must not name the actor in `observed_by`, must not be signed by the key that signed the invocation, and, where the key set names operators (Section 12.5), must be signed by a key whose operator differs from that of the invocation's key; otherwise `unresolved` (I10). *(v0.3.2)* The key test applies whatever `observed_by` says: a host key that also has the `observer` role is still the actor.
6. For each statement, if its observer issued more receipts than `effect_count`, the result is `violated` (I7); if fewer, `unresolved` (I7): a receipt was lost or withheld.

Statements are OPTIONAL in the core; bindings MAY require them. The MCP binding requires them from every server that advertises revision 0.3 of the evidence extension.

**Minting.** Receipts and statements MUST be produced on the execution path: by the code that performs the effect, as it performs it, and before the result is returned. A receipt reconstructed afterwards from logs or traces attests to the logging pipeline, not to the effect, and MUST NOT claim an assurance level above L1. L3 requires a `backend_receipt` from the system that executed the effect.

### 5.15 Reserved objects (informative)

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
9. when `C₂.budget` is present, `C₁.budget ≤ C₂.budget`, where an absent `C₁.budget` is taken to equal `C₂.budget`;
10. for every limit in `C₂.limits` and every limit in `C₁.limits` with the same `unit` and `actions`: `C₁.per_call ≤ C₂.per_call` when both are present, and `C₁.per_period ≤ C₂.per_period` when both are present with the same `period`. A child MAY add limits. *(v0.3)*

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

The **effective claims** of an invocation are the meet of every claim set on its chain, from the root mandate to its `authority_ref`, and then met with the IntentCertificate's claims when `intent_ref` is present. The meet is folded from the root, and at each step the narrower set is C₁: starting from the root's claims A, each later element's claims C give C ⊓ A, and the intent's claims I give I ⊓ A. Folding the other way (A ⊓ C) keeps the root's broad patterns that the child doesn't subsume and loses the child's narrower ones, so an ordinary chain can come out empty. (Clarified after an independent implementation, stafordtituss/amep#18.)

### 7.4 Satisfaction

An executed-effect body x **satisfies** claim set C (written x ⊨ C) if and only if:

1. `x.action` matches some action pattern in C;
2. `x.action` matches no pattern in `C.deny_actions`;
3. `x.resource` matches some resource pattern in C;
4. `x.resource` matches no pattern in `C.deny_resources`;
5. `x.effect ≤ C.ceiling`;
6. every data flow in `x.released` is in `C.data`;
7. `x.t ≤ C.exp`, and `x.t ≥ C.nbf` when `C.nbf` is present.

### 7.6 Limits *(v0.3)*

A limit caps a quantity (Section 5.9.2). The risk budget (Section 9) bounds autonomy in points across unlike effects; a limit bounds an amount in one unit. Both apply.

| Field | Req. | Meaning |
|---|---|---|
| `unit` | **yes** | The unit capped. |
| `per_effect` | no | Maximum amount of one effect. |
| `per_call` | no | Maximum total of all effects of one invocation (one tool call), in the unit. |
| `per_period`, `period` | together | Maximum total within a period of `period` seconds. Periods are fixed windows starting at the node's `nbf`, or at time 0 when `nbf` is absent. |
| `counted_by` | no | The observer whose `period_spent` covers all of this node's spending in the unit, for example the bank that executes every payment. Only that observer's totals count. |
| `actions` | no | Action patterns the limit applies to. Absent: the limit applies to every `financial` effect. |

For every effect x of the invocation (Section 10.2, with each observer's receipts counted separately), every node N on the chain (and the intent) that carries `limits`, and the limits of N that apply to x:

1. If x carries no `value`: `unresolved` (I7).
2. If no applicable limit has x's unit: `violated` (I2) when x is `financial` or its unit is a money unit (an asset N does not authorize); otherwise `unresolved` (I7).
3. If `amount > per_effect`, or the sum of the amounts of the invocation's effects under that limit exceeds `per_call`, and the invocation has no approval that passed I8: `violated` (I2).
4. Each limit keeps its own running total per window, so two limits in one unit and period with different `actions` are separate caps. The period total is the Verifier's running total (in this packet, plus verifier state across packets, Section 10.7) plus `amount`. If the limit names x's observer in `counted_by`, and x carries `period_spent` for the limit's `period` whose `from` is the start of the window that contains x (the node's `nbf`, or 0, plus a whole number of periods): when that figure is below the running total, `violated` (I7, the counting observer's accounting is inconsistent); otherwise it is the total. A figure for another window, or one that names no window, isn't the limit's total. The observer's own window can start anywhere, so taking it for the limit's window could understate the total, or blame an honest observer. If the total exceeds `per_period` without an approval that passed I8: `violated` (I2).
5. If no total from the counting observer applies and the Verifier has no earlier state for that window: `unresolved` (I7). A window's total is known once verifier state seeds it, or once a counting observer's own figure for that window (rule 4) anchors it; effects after that, from any observer, add to it. A figure from an observer the limit doesn't name never anchors it, and effects counted within this packet alone never do. (Clarified after an independent implementation, stafordtituss/amep#18.) A packet's assembler could leave out earlier effects, and an observer that is not named in `counted_by` sees only its own share of the principal's spending, so a period total is never assumed to start at zero or taken from a partial view.
6. *Unknown outcomes are held.* An invocation may reach the receipt check of Section 10.2 (its chain, signatures and interpretation verified) with no receipt and no `not_executed` call statement. Such a call may still have moved value. Only a verified invocation is held, so evidence that doesn't verify can't place holds. For each node N on its chain, and each period limit of N that applies to its declared effect, the Verifier records a **hold** in its state (Section 10.7): the invocation's `reserve` if it is in the limit's unit, otherwise an unknown amount. In each later packet, every hold whose invocation is not in that packet counts toward the same window's total.
   - If the total, plus the holds, exceeds `per_period` without an approval that passed I8: `unresolved` (I7), gap `held_outcome` for the held invocation.
   - If a hold's amount is unknown, and the effect has no approval that passed I8: `unresolved` (I7), gap `held_outcome`. The total can't be bounded.

   An approval that passed I8 authorizes its effect to go over the limit, so holds don't block it.

   The result is `unresolved`, not `violated`, because the held call may not have executed. A later packet that contains the held invocation replaces its hold:
   - with its receipts, which then count like any others;
   - with a `not_executed` statement, which releases it;
   - or with a new hold, if its outcome is still unknown.

   A hold is never counted twice.

**Every applicable limit is checked.** For each effect, every limit of every node on the chain (and of the intent) that applies to it is evaluated before the result is decided, and a `violated` result beats an `unresolved` one, as across results (Section 10.5). Two mandates that list the same limits in a different order therefore get the same verdict.

Rules 1–5 follow a review by Carlos Vendrell Felici (Zealynx Security), stafordtituss/amep#10, of the first v0.3 draft, in which `per_call` capped one effect, one `period_spent` stood for every period, any observer's total was taken as the principal's, `caip19:` amounts were ambiguous, and limits differing only in `actions` shared one total.

Carlos Vendrell Felici's rerun of that review against this draft (stafordtituss/amep#10, 23 November 2026) showed two more gaps, which the rules above now close:
- the verdict depended on the order the limits were listed in;
- `period_spent` didn't say which window it covered.

Rule 6 follows the cross-institution example of finos/ai-governance-framework#421, where siddhartha-mangsatabam set the requirement that "a slice with an unknown outcome stays counted until reconciliation shows it was booked or not booked". Without it, a lost instruction in one packet left no trace in verifier state, and a later packet holding only the retry was `preserved` though the principal might be over the limit.


An approval authorizes exceeding a limit for its one effect. The approved amount still counts toward the period total, so one approval cannot unlock later unapproved spending.

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
| **I6** | Liveness | No mandate or delegation on the chain was revoked, per signed revocation evidence, at or before the time of the invocation **or of any of its effects** (v0.3). A revocation still inside the revoked node's declared propagation window does not yet apply (Section 5.12.1, v0.3.3). | `violated` |
| **I7** | Evidence | All evidence the evaluation needs is present, well-formed, signed by a key holding a permitted role, and fresh where freshness is required; recorded accounting matches recomputation. | `unresolved` (`violated` for an accounting mismatch) |
| **I8** | Approval binding | An approval cited by an invocation matches the executed effect body (without `t`), is within its validity window, is unconsumed, and is used only once. | `violated` |
| **I9** | Self-protection | No agent invocation targets, or executes against, a protected resource: guardrail configuration, keys, agent instruction files, or the evidence store. | `violated` |
| **I10** | Observer independence | An effect of class `write_shared` or above names its actor and was observed by a party other than that actor, at assurance L1 or higher: its receipt is not signed by the key that signed the invocation *(v0.3.2)*, and where the key set names operators (Section 12.5), the observer's key and the invocation's host key also have different operators. A receipt from the actor's side is corroborated, not self-reported, when observers independent of the actor recorded the same executed body (ignoring `t`) at least as many times, since the same effect recorded by several observers is one effect (Section 10.2) *(v0.3.4)*. | `unresolved` |
| **I11** | No orphan effects | Every effect links to an invocation in the packet, and no effect exists for an invocation that a signed decision denied or held. | `violated` for an effect despite a deny or a `not_executed` statement; `unresolved` for an effect whose invocation is not in the packet (Section 10.4, v0.3.3) |

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
    i.declared.effect ≠ read, and no principal confirmation covers U
    (Section 5.11.1):  if i.principal_confirmed is true                 → unresolved  I4 (principal_confirmation)
                       otherwise                                       → violated    I4 if E is non-empty
                                                                         unresolved  I4 otherwise
9a. Call statements (Section 5.14), rules 1 to 5, in that order. A verified
    not_executed statement with no receipts ends the evaluation here
    (rule 5).
10. If E is empty                                                      → unresolved  I7  "no effect receipt"
11–14. For each e in E, with x = e.executed:
    11. if e is not verified                                           → unresolved  I7
    12. if i.declared.effect ≥ write_shared:
          if i.actor is absent                                         → unresolved  I10
          if e.observed_by = i.actor or e.assurance = L0               → unresolved  I10
          if e's key = i's key                                          → unresolved  I10
          if operator(e's key) = operator(i's key), both declared       → unresolved  I10
    13. if i.mediated is present:
          if canon(x) ≠ canon(i.mediated)                              → violated    I2
        otherwise (no i.mediated):
          if x.action ≠ i.declared.action
             or x.resource ≠ i.declared.resource                       → violated    I2
        if x.resource is protected                                     → violated    I9
    14. let C = effective claims of i (Section 7.3);
        if not x ⊨ C: if the first failing condition is a released
        data flow                                                      → violated    I5
                      otherwise                                        → violated    I2
    Let B = the effects among the x (v0.3): receipts are grouped by observer and by body compared without t and
        value.period_spent; a body occurs as often as the most any one observer recorded it. The same effect seen by
        several observers is one effect; two receipts from one observer are two effects. (Until v0.3 identical bodies
        were always merged, so two equal payments in one call counted as one; found by C. Vendrell Felici,
        stafordtituss/amep#10.)
14a. Call statements, rule 6 (Section 5.14): each statement's effect_count
    against the receipts from its observer.
15. If i.approval_ref is present:
      if no such approval exists, or it is not verified                → unresolved  I7
      for each body x in B:
        approval.effect_digest ≠ SHA-256(canon(x without t)), or
        approval.consumed is true, or
        approval.expiry < max(i.t, x.t), or approval.nbf > i.t, or
        the approval was already used in this packet for a different
        invocation or body                                             → violated    I8
15a. Limits (Section 7.6), for every applicable limit of every node on the
    chain and of the intent.
16. Apply risk-budget accounting (Section 9.2) with cost = Σ cost(x)
    over B                                                             → violated I7 or I2, if it fails
17. Otherwise                                                          → preserved   -
```

**Quarantine check (before step 1).** Let Q be the findings named in the `quarantined` member of every verified decision with `mode: quarantine` and `phase: pre_execution`, each attached to the position of its decision's invocation in packet order. If `i` comes later in packet order than the decision that quarantined a finding listed in `i.influenced_by`, and no principal confirmation covers those findings (Section 5.11.1), the result is `unresolved` (I4, gap `principal_confirmation`) if `i.principal_confirmed` is true, and otherwise `violated` (I4), "quarantined content reached the agent". This applies whatever the invocation's effect class: a quarantine is a promise that the content never reached the model at all.

The checks in step 14 MUST be evaluated in the order of Section 7.4, so that the reported invariant is deterministic. If any object needed by a step is malformed (a missing required member, or a time in an invalid form), the result for that invocation is `unresolved` (I7).

Evaluating every receipt (steps 11–14) means that an extra effect recorded against an authorized invocation cannot hide behind the first, legitimate receipt. Several observers recording the same effect (for example, the host at L1 and the receiving system at L3) yield one body in B, so the effect is approved and charged once.

### 10.3 Decision reconciliation

After all invocations, for each verified ContinuityDecision `d` whose `mode` is `deny` or `hold` **and whose `phase` is `pre_execution`** (post-execution and simulated decisions can neither confirm nor contradict a block):

- If an effect exists with `invocation = d.invocation`, the result for that invocation is replaced with `violated`, I11, "effect despite deny" (enforcement was contradicted).
- Otherwise, if `d.enforcement.fail_mode` is `closed` or `d.enforcement.applied` is `confirmed`, and the invocation is declared `write_shared` or above, an `unresolved` result for it is replaced with `unresolved`, I10, need `independent_observer`. Both fields are declared by the host that signed the decision, so they never settle that nothing was executed, for any effect class. A `not_executed` call statement from an observer settles it, and the invocation's own evaluation already applies it (Section 5.14, rule 5; for `write_shared` and above the observer must not be the actor, I10) *(v0.3)*.
- Otherwise the result is left unchanged. With neither a receipt nor a `not_executed` statement it is `unresolved`, I7: the deny cannot be shown to have held. A deny never replaces a `violated` result.

### 10.4 Orphan effects

For each effect whose `invocation` does not match any invocation in the packet, the verifier MUST add a result `{ id: <effect id>, outcome: unresolved, invariant: I11 }`, with gap `invocation` naming the missing invocation, and no blame. *(v0.3.3)* The effect may be a bypass, or the packet's assembler may have left its invocation out. AMEP can't tell the two apart from the packet, because it doesn't assume a packet is complete (Section 13, `LIMITS.md` section A). Until v0.3.3 this was `violated`, charged to the host. tclancy pointed out (stafordtituss/amep#36) that this blamed an honest host whenever an assembler dropped an invocation. A record that the set of invocations for the period is complete, such as a sealed gateway log, would let a verifier conclude a bypass; AMEP doesn't define one yet. An effect that contradicts a signed deny or a `not_executed` statement is still `violated` (I11): there, the invocation is present.

### 10.5 Packet verdict

The **packet verdict** is:

- `violated` if any result is `violated`;
- otherwise `unresolved` if any result is `unresolved`;
- otherwise `preserved`.

Its **deciding invariant** is that of the first result, in result order, with the verdict's outcome. Verifiers MUST report every result, not only the verdict.

A `preserved` result inside a propagation window also carries `within_window` (Section 5.12.1, v0.3.5). It names the revocation, and does not change the verdict.

#### 10.5.1 Blame and evidence gaps *(v0.3)*

Each result carries two further members. Both are derived only from the signed evidence. A Verifier MUST NOT infer blame that the evidence does not show.

**`blame`** (on `violated` results; otherwise null) names the party whose own signed record is the first to depart from authority:

| Value | Meaning | Examples |
|---|---|---|
| `agent` | The acting agent asked for, or acted on, something the authority did not allow. Its request was declared through the host. | Effect outside claims (I2), release (I5), guardrail target (I9), untrusted influence (I4), approval misuse (I8), limits and budgets exceeded, acting after revocation (I6) |
| `delegator` | A delegation widened what its parent granted. | Attenuation (I1) |
| `host` | The host or PEP failed at its own role. | An effect despite its signed deny (I11), quarantined content passed on (I4), a recorded spend that doesn't match (I7) |
| `transport` | The call the server received differs from the one the host signed. | `args_digest` mismatch (Section 5.14) |
| `server` | The executing party's own records contradict the authorized call, or each other. | Declared ≠ executed, or mediated ≠ executed (I2); receipts contradicting `not_executed` (I11); more receipts than its call statement counts, or an inconsistent period total (I7) |

**`gaps`** (on `unresolved` results; otherwise empty) lists the evidence that would let the evaluation continue, as `{need, ref}`, with `cause` on signature gaps (below). `ref` is the id of the object concerned, or `-`. Values of `need`:

| Value | Meaning |
|---|---|
| `well_formed_packet` / `well_formed_evidence` | The packet or an object is malformed (Section 12.1). A corrected packet is needed. |
| `root_mandate`, `intent`, `lineage`, `invocation` | A referenced object is missing. For `invocation`, this includes an effect whose invocation is not in the packet (Section 10.4). |
| `signature`, `receipt_signature`, `call_statement_signature`, `revocation_signature` | A required signature is missing or invalid, or the signer lacks the role. |
| `interpretation`, `interpretation_pin` | An approved interpretation, or the pinned adapter revision, is needed (I3). |
| `revocation_status` | A fresh signed status is needed (I7). |
| `ordering` | A revocation and an action, timed by different operators' clocks, fall within their declared skew of each other: which came first is needed, from a shared clock or a smaller skew (I6, Section 5.12.2). |
| `receipt`, `receipt_observer`, `receipt_binding` | A receipt is missing, names no observer, or is bound to another invocation. |
| `call_statement`, `call_statement_binding`, `unaltered_call` | A well-formed call statement bound to this invocation is needed, or a call that arrived unaltered. |
| `actor`, `independent_observer` | The actor, or an observer other than the actor, is needed (I10). |
| `principal_confirmation` | The principal's signed confirmation of an influenced action, naming the findings shown, is needed (I4, Section 5.11.1). |
| `approval` | A signed approval is needed. |
| `value`, `period_total` | A quantity in the limited unit, or a period total from the counting observer or earlier state, is needed (Section 7.6). |
| `held_outcome` | An earlier invocation's outcome is needed: its receipts or a `not_executed` statement. It is held against this period total (Section 7.6, rule 6), or it holds the approval this invocation cites (Section 5.10, held approvals). *(v0.3)* |
| `reserve` | The invocation's `reserve` is malformed (Section 5.8). *(v0.3)* |
| `verifier_support` | The packet uses a claim member this Verifier does not implement (Section 16). |

**`cause`** *(v0.3)*. A gap whose `need` is `signature`, `receipt_signature`, `call_statement_signature` or `revocation_signature` also carries `cause`, saying why the signature was refused. No other gap carries it. When several objects' signatures are refused, it is the cause for the first of them, in the order the evaluation checks them. A Verifier MUST determine it in this order:

| Value | Condition |
|---|---|
| `missing` | The object is absent, or has no `proof` object. |
| `unknown_key` | The proof's `kid` is not a string naming a key in the key set. |
| `role` | The key holds no role permitted to sign this kind of object (Section 12.5). |
| `key_status` | The key is marked revoked, or the object's own time falls outside the key's `nbf`–`exp` interval (Section 12.4). |
| `invalid` | Anything else: the algorithm, the proof version, the encoding, the strict acceptance rule (Section 12.2), or the signature itself fails. |

A signature under a key the verifier was not given, such as an attacker's own key, is `unknown_key`. A key substituted in the key set itself cannot be detected from the packet; that is the key set's provenance (Section 12.4).

Both reference verifiers return identical `blame` and `gaps` for every result of every conformance vector, which `tools/compare_verifiers.py` checks.

### 10.6 Lineage checks

Section 10.2 also applies these lineage checks (Section 5.9.1):

- in step 2: if any id in `i.derived_from` does not name an invocation that comes **earlier** in the packet, the result is `unresolved` (I7);
- in step 14, after the claim checks: for an effect body x with a `recipient`, every carried class `d` whose flow `d->x.recipient` is not in the effective claims' `data` makes the result `violated` (I5).

### 10.7 State across packets

Approval single use (I8) and risk budgets (Section 9) span more than one packet when a verifier evaluates a stream of packets, for example a day of activity sent in hourly batches. A verifier MAY therefore keep **state**:

```json
{ "approvals_used": { "<approval id>": ["<invocation id>", "<body digest>"] },
  "spent":          { "<mandate or delegation id>": <points> },
  "period_totals":  { "<node id>|<unit>|<period>|<window>[|<actions>]": "<amount>" },
  "held":           { "<invocation digest>": { "invocation": "<invocation id>",
                                               "amounts": { "<period total key>": "<amount>" | null } } },
  "approvals_held": { "<approval id>": { "invocation": "<invocation id>", "digest": "<invocation digest>" } },
  "operations_held": { "<operation>": { "invocation": "<invocation id>", "digest": "<invocation digest>" } },
  "operations_done": { "<operation>": { "invocation": "<invocation id>", "digest": "<invocation digest>" } } }
```

- On entry, `approvals_used` seeds the record of approval use, `spent` seeds each node's running total, and `period_totals` seeds each limit window's total (Section 7.6).
- `held` *(v0.3)* lists invocations whose outcome was unknown when their packet was evaluated, with the amount each holds against each period total: its `reserve`, or `null` when unknown (Section 7.6, rule 6). A hold is keyed by the invocation's digest (Section 5.14), so it is released only by that exact signed invocation.
- `approvals_held` *(v0.3)* lists approvals held for an invocation whose outcome was unknown (Section 5.10, held approvals). An entry whose `digest` is the digest of an invocation in the packet is set aside, because the packet decides that invocation afresh.
- `operations_held` and `operations_done` *(v0.3.2)* record, per operation, the attempt whose outcome is unknown and the attempt that took effect (Section 5.8.1). As with `approvals_held`, an entry whose `digest` is the digest of an invocation in the packet is set aside.
- On exit, the verifier returns the updated state.
- Within one stream, state MUST be passed from each packet's evaluation to the next, in time order.

State is the verifier's own bookkeeping, not evidence. A third party that wants to reproduce a result needs the same state, so verifiers that rely on it SHOULD publish it alongside their results, signed with their own key. A conformance vector MAY include a `state` member, which a verifier passes in before evaluating that vector's packet.

### 10.8 Verdict records *(v0.3)*

A verifier MAY publish what it concluded as a **verdict record**: a statement that names the exact packet and key set it evaluated and gives, for the packet and for each result, the outcome, the deciding invariant, `blame` and `gaps` (Section 10.5.1). A party that has the packet and the key set can re-run any conforming verifier and get the same record, so a record can be checked without trusting its signer. A party that does not have them can still rely on the signer's word, as it would on any attestation.

The record is the predicate of an in-toto Statement v1 [IN-TOTO], with predicate type `https://github.com/stafordtituss/amep/verdict/v0.3`:

```json
{ "_type": "https://in-toto.io/Statement/v1",
  "subject": [ { "name": "amep-packet", "digest": { "sha256": "<SHA-256 of the packet bytes>" } } ],
  "predicateType": "https://github.com/stafordtituss/amep/verdict/v0.3",
  "predicate": {
    "packet":   { "sha256": "<SHA-256 of the packet bytes>" },
    "keyset":   { "sha256": "<SHA-256 of the JCS form of the key set>" },
    "verdict":  { "outcome": "violated", "invariant": "I2", "blame": "agent", "gaps": [] },
    "results":  [ { "id": "<invocation id>", "outcome": "violated", "invariant": "I2", "blame": "agent", "gaps": [] } ],
    "verifier": { "name": "<implementation>", "version": "<version>" } } }
```

- `packet.sha256` is computed over the exact bytes the verifier evaluated, before parsing, so a record also covers packets that are not well formed (Section 12.1).
- `keyset.sha256` is computed over the JCS form (Section 12.1) of the key set as the verifier received it.
- `verdict` is the packet verdict of Section 10.5. `blame` is `null` unless the outcome is `violated`; `gaps` is empty unless it is `unresolved`.
- `results` lists every result in evaluation order, with the same members, plus the invocation `id` (`"-"` for a packet-level result, such as a packet that does not parse).
- Reasons are free text and differ between implementations, so they are not part of the record.
- `verifier` is OPTIONAL and names the implementation. It is the only member that two conforming verifiers MAY fill differently: with `verifier` removed, the JCS forms of their records for the same inputs MUST be identical.
- When a verifier uses state across packets (Section 10.7), the record does not cover the state; the verifier SHOULD publish the state it used alongside the record.

A signed record is the statement's JCS form carried in a DSSE envelope [DSSE] with payload type `application/vnd.in-toto+json`, signed with Ed25519 over the DSSE pre-authentication encoding. The strict acceptance rule of Section 12.2 applies to its signatures. A verifier of an envelope MUST check the signature before parsing the payload, and MUST parse the payload under the rules of Section 12.1.

For policy engines that consume in-toto Simple Verification Results [SVR], a verifier MAY also publish the verdict as an SVR (predicate type `https://in-toto.io/attestation/svr/v0.2`) about the same subject. Its only AMEP property is `AMEP_VERDICT_PRESERVED`, listed when the packet verdict is `preserved`; a `violated` or `unresolved` packet gets an SVR with no properties, and the verdict record carries the detail. Its `verifier.policies` name the key set (by the same digest as `keyset.sha256`) and the AMEP version whose rules were applied. An SVR names its verifier and the time of verification, so it is not deterministic; with `verifier.id` and `timeCreated` removed, two conforming verifiers produce identical SVRs.

A verdict record is a statement by its signer, not evidence of what the agent did. It does not take the place of the packet in a dispute: the packet is the evidence and the record is one verifier's reading of it.

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

*Note:* JCS sorts members by **UTF-16 code unit**, not by code point, and serializes numbers exactly as ECMAScript's `Number.prototype.toString`. Generic "sorted keys, no whitespace" serializers get both wrong for some inputs. The vector `jcs-canonical-form--unicode-keys--floats` contains member names on both sides of the surrogate range and non-integer numbers, and fails on any implementation that does not follow RFC 8785 exactly.

**Number range.** JSON does not distinguish integers from other numbers, and implementations parse numbers differently: ECMAScript maps every number to an IEEE 754 double, while other languages keep integers exact. A number whose magnitude exceeds 2^53 − 1, the safe-integer range of I-JSON [RFC7493], can therefore canonicalize to different bytes in different Verifiers, so that the same signed packet verifies in one and not in another, and one approval digest can cover two different values. Producers MUST NOT emit such numbers. A Verifier MUST treat a packet that contains one, anywhere, as malformed: every invocation in it is `unresolved` (I7). The range applies to every number, because a Verifier cannot tell `1e21` from `1000000000000000000000` after parsing. Values whose exact identity matters, such as amounts and identifiers, SHOULD be strings (for example `"amount": "1200.00"`); the amounts of Section 5.9.2 MUST be.

**Well-formedness (v0.3).** A Verifier MUST treat a packet as malformed, making every invocation `unresolved` (I7), when:

- an object has two members with the same name. RFC 7493 requires unique names, and parsers disagree on duplicates (first wins, last wins, error): a packet carrying `"resource"` twice could be verified under one value and displayed under the other. Until v0.3 both reference verifiers silently kept the last value;
- a string or member name contains a lone surrogate or a noncharacter (RFC 7493 Section 2.1);
- an `action` or `resource`, or a pattern in `actions`, `resources`, `deny_actions` or `deny_resources`, contains a control character (U+0000–U+001F, U+007F–U+009F) or is not in Unicode Normalization Form C. Verifiers never normalize identifiers; a Producer MUST emit them in NFC, so that two identifiers that look the same also compare the same;
- nesting exceeds 32 levels, an array has more than 4096 elements, a string exceeds 8192 bytes of UTF-8, or a member name exceeds 256 bytes.

**Number literals.** Two decimal literals that denote the same double (for example `1200` and `1200.0000000000000001`) share one canonical form and one approval digest. A Verifier that parses packets from text SHOULD reject a non-integer number literal whose decimal value differs from the double it denotes. The reference packages do this in their command-line tools (`parse_strict`, `parseStrict`).

### 12.2 Signing

The signing input of an object is `canon(o′)`, where `o′` is `o` with the `proof` member removed.

- **Ed25519** [RFC8032] is REQUIRED for verifiers and RECOMMENDED for producers. `sig` is the 64-byte signature in lowercase hex.
- **ES256** is OPTIONAL.
- A key's algorithm is fixed by its key-set entry. A verifier MUST reject a proof whose `alg` differs from the key's algorithm (no algorithm negotiation).
- Hybrid post-quantum signatures (ML-DSA) are OPTIONAL for archival profiles.

Deployments MAY instead wrap objects in COSE_Sign1 [RFC9052] over deterministic CBOR [RFC8949], or in JWS over the canonical form. A CDDL definition of the v0.2 objects (`schemas/amep-v0.2.cddl`) and JSON Schemas (`schemas/v0.2/`) are published alongside this document.

**Version-2 proofs (v0.3).** A proof MAY carry `"v": 2`. Its signing input is domain-separated:

```
"AMEP-v0.3" 0x00 kind 0x00 canon(o′)
```

where `kind` is the object's `kind` (empty if absent). A signature that the same key made over the same canonical bytes for another object kind, or for another system, therefore never verifies as this object. A proof without `v` (or with `v: 1`) signs `canon(o′)`, exactly as in v0.2. Relabelling a version-1 signature as version 2 changes the signing input, so it fails. A packet that declares `"amep_version": "0.3"` MUST use version-2 proofs on every object, and a Verifier MUST treat any other proof in such a packet as invalid.

**Exact Ed25519 acceptance (v0.3).** Ed25519 libraries disagree on edge cases. With OpenSSL 3.6, the identity public key (`01` followed by 31 zero bytes) accepts the signature R = identity, S = 0 for every message, while OpenSSL 4.1 rejects it, so two conforming Verifiers returned different verdicts on one packet. Before calling a library, a Verifier MUST reject:

- a signature whose S (its last 32 bytes, little-endian) is not less than the group order L = 2^252 + 27742317777372353535851937790883648493;
- a public key A or commitment R (the signature's first 32 bytes) whose encoding is non-canonical (y ≥ 2^255 − 19 after clearing the top bit) or is a point of small order (y ∈ {0, 1, p − 1} or one of the two y values of the order-8 points);
- a key `x` that is not exactly 64, or a `sig` that is not exactly 128, lowercase hexadecimal digits.

### 12.3 Digests

`SHA-256(canon(o))`, as lowercase hex, is used for approval digests and content hashes.

### 12.4 Key discovery

A party publishing AMEP keys SHOULD serve a key set at `/.well-known/amep-keys.json`:

```json
{ "issuer-1": { "kid": "issuer-1", "alg": "Ed25519", "x": "<32-byte public key, hex>",
                "roles": ["issuer", "approver"],
                "nbf": 1767225600, "exp": 1798761600, "revoked": false } }
```

Verifiers MUST reject signatures made with a key outside its `nbf`–`exp` interval or marked revoked, using a trusted timestamp (RFC 3161 or Roughtime) where the signature time is disputed. A key whose `revoked` member is present and not `false` is revoked. A key MAY also declare `clock_skew` (Section 5.12.2) *(v0.3.4)*. An object is placed in the interval by its own time: `t`, or `executed.t` for an effect receipt; the interval includes `nbf` and excludes `exp`, and a malformed time places it outside. An object with no time of its own (a mandate, a delegation, an interpretation) can be checked for revocation only, so a key set SHOULD mark a compromised key revoked rather than rely on its `exp`. The refusal's cause is `key_status` (Section 10.5.1). *(v0.3.1; before it, both reference verifiers left this check to key discovery, and accepted a revoked key given to them directly.)*

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
| `call_statement` | `observer` *(v0.3)* |

Deployments SHOULD keep `approver` keys in hardware bound to a person (for example, a WebAuthn authenticator), and SHOULD give `host` and `observer` roles to different keys, so that one compromised key cannot both act and attest.

**Operators** *(v0.3)*. A key MAY carry `operator`, an identifier of the organisation that controls it. Different keys, and the different identifiers their records use, can still belong to one party. When the key that signed an effect receipt or a `not_executed` statement and the key that signed the invocation both carry `operator` and the values are equal, the observer is not independent of the host, and I10 is not met. A key set that names no operators leaves I10 to the identifiers in the records and to the keys themselves: a record signed by the invocation's own key is the actor's *(v0.3.2)*. Deployments that rely on I10 SHOULD name the operator of every `host` and `observer` key.

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

A Verifier passes a vector when the packet verdict and deciding invariant (Section 10.5) equal `expect`. Suite v0.3.5 has 298 vectors (79 positive, 219 must-reject); Appendix B lists them. Where a vector's `expect` also has `within_window` (Section 5.12.1), a Verifier passes only if the verdict carries that member with that value, or, where it is null, carries none. Two reference verifiers, written separately by the same author (Python, and JavaScript run both under Node.js and in the browser with WebCrypto), agree on all 298. Because they share an author, their agreement does not rule out a shared misreading of this specification; an implementation by another party is the stronger test. One exists: zambo-amep-verify 0.1.0, written by Brennan Zambo from this specification and the vectors alone, without reading either reference verifier, agrees with all 228 single-packet vectors of the core suite (stafordtituss/amep#18). Cross-packet state (Section 10.7) and the two interop suites are not yet implemented there. Suite v0.2.1 adds 16 vectors found by mutation analysis of the reference evaluator (`paper/eval/mutation.py`): each distinguishes a rule, or the inclusive edge of a time, budget or approval-window bound, that no earlier vector isolated. Suite v0.2.2 adds 3 vectors in which an agent acts directly under a mandate whose validity uses RFC 3339 times. Suite v0.2.3 adds 4 vectors for the number range of Section 12.1. Suite v0.3.0 adds 111 vectors for the v0.3 rules (Section 16) and for the fixes from independent review (see CHANGELOG.md). Suite v0.3.1 adds 5 vectors for key status (Section 12.4): a revoked issuer or observer key, and a key used before its `nbf` or at its `exp`, from a report by Andrii (Radiolaria) on the OpenID AIIM list. Suite v0.3.2 adds 5 vectors for operation identity (Section 5.8.1), from the same review, and 5 for audience binding (Section 5.3), from stafordtituss/amep#16. Suite v0.3.2 also has 12 payment-limit vectors written by Carlos Vendrell Felici (stafordtituss/amep#30), the first by an outside author, and 4 for admissions (Section 8, I10). Suite v0.3.3 adds 6 vectors for calls whose effects aren't known in advance (Section 5.8.2), and 8 from tclancy's review (stafordtituss/amep#34 to #36, and his follow-up on #39), which also changed the expected outcome of 5 vectors: two principal confirmations now carry the principal's signed approval, two effects without an invocation in the packet are `unresolved`, and an effect inside a propagation window is `preserved`. Suite v0.3.4 adds 2 vectors for corroborated receipts (I10), the actor's own receipt beside an independent receipt of the same effect, and 4 for clocks of different operators (Section 5.12.2), both found while mapping the OWASP Agentic Evidence scenarios. Suite v0.3.5 pins `within_window` on the two vectors inside a window, and adds 1 vector in which a revocation after the effect leaves a window unused, so the result carries none. Every vector packet except `malformed-timestamp` validates against both the JSON Schemas in `schemas/v0.2/` and the CDDL.

### 15.3 Requirements on changes

Every normative change to this specification MUST be accompanied by at least one positive and one must-reject vector that distinguish the new behaviour from the old.

---

## 16. Versioning and extensibility

- The specification, schemas and suite are versioned together using Semantic Versioning. Before 1.0, a minor version MAY contain breaking changes; after 1.0, breaking changes require a major version and a deprecation window of at least six months.
- A packet MAY declare `"amep_version": "0.2"`. Verifiers SHOULD reject packets declaring a major/minor version they do not implement.
- Extension members MUST use the `x-` prefix, or a reverse-DNS prefix (for example, `com.example.field`). Extensions MUST NOT change the outcome of the evaluation in Section 10. Extensions that need to change outcomes are profiles (Section 14).
- **Unknown claim members (v0.3).** In a packet that declares `"amep_version": "0.3"`, a claim member (or a member of a limit) that is neither defined by this specification nor an extension member makes the result `unresolved` (I7). A Verifier that ignored a constraint it does not implement would report `preserved` for evidence the constraint forbids: a silent downgrade. Packets without `amep_version` (or with `"0.2"`) keep the v0.2 behaviour, so existing producers are unaffected.
- A Verifier MUST treat a packet that declares an `amep_version` other than `"0.2"` or `"0.3"` as malformed (`unresolved`, I7).
- **Compatibility of v0.3.5.** No outcome changes. A `preserved` result inside a propagation window gains the member `within_window`, and so do verdict records (Section 10.5); a consumer that ignores unknown members is unaffected.
- **Compatibility of v0.3.3.** Three outcomes change, each closing a case where a verdict said more than its evidence (stafordtituss/amep#34 to #36):
  - a host-signed `principal_confirmed` no longer clears an influenced or quarantine-crossing call by itself;
  - an effect whose invocation is not in the packet is `unresolved`, not `violated`;
  - an effect inside a declared propagation window is `preserved`, not `unresolved`.

  Producers that relied on the flag add the principal's signed approval with `findings` (Section 5.11.1). `declared.scope` (Section 5.8.2) is additive.
- **Compatibility of v0.3.** Every v0.2 conformance vector keeps its verdict, with one deliberate exception that closes a gap: revocation status must be fresh as of each effect's time (Section 5.12, rule 3), so the vector `status-current-as-of-the-action` now carries a status as of the effect. The v0.3 rules that change outcomes for packets without new members (duplicate names, Unicode and bounds, the Ed25519 acceptance rule, liveness at effect time) close security gaps. Grants (Section 5.3) are additive in the same way: claims with `actions` and `resources` are evaluated exactly as before, and a verifier that does not implement `grants` returns `unresolved` for a v0.3 claim set that uses it (an unknown claim member, Section 16), never `preserved`. An unversioned packet that uses `grants` is `unresolved` too: it is the one case where this revision decides a packet differently from a v0.2 verifier, which would ignore the member. No packet produced for v0.2 carries it. Operation approvals (Section 5.10) are additive: an approval with `effect_digest` is evaluated exactly as before, and a verifier that does not implement `effect_digests` never returns `preserved` for an approval that uses it. Held approvals (Section 5.10) change a verdict only where an invocation cites an approval already cited by a call whose outcome is unknown: that invocation is `unresolved` instead of `preserved`. No other verdict changes. Holds (Section 7.6, rule 6) change only what verifier state carries from one packet to the next. A packet evaluated with state that has no `held` member is decided exactly as before, and a well-formed `reserve` changes no packet's own verdict. A verifier that does not implement holds ignores `reserve` and keeps no holds. Within one packet, a call with an unknown outcome is `unresolved` either way. Across packets, such a verifier can still return `preserved` while an earlier outcome is unknown: that is the gap the rule closes. **Observer totals must name their window** (Section 5.9.2, `{ from, total }`). A bare `period_spent` figure, valid in earlier drafts of v0.3, no longer counts as a limit's total. Its packet is then decided from verifier state, or is `unresolved` (I7): it fails closed, and is never `preserved` on that figure alone. Limits are checked independently of their order (Section 7.6), so a packet whose deciding invariant depended on the order may now report the `violated` result that the order had hidden.

---

## 17. Security considerations

- **Adversarial models (P0).** All guarantees assume models may lie. Invocations MUST be signed by the host or PEP, never by a key the model can use.
- **Key compromise and role confusion.** Signer roles (Section 12.5) limit what a single stolen key can forge: a host key cannot mint mandates or approvals, and an observer key cannot declare invocations.
- **Evidence omission by the assembler.** A packet's assembler may leave out unfavourable objects. AMEP limits what omission achieves: a missing receipt, status or signature yields `unresolved`, and revocable mandates require a fresh signed status (Section 5.12). Omission of an *entire* invocation shows only as an independently observed effect whose invocation is absent: `unresolved` (I11), naming the missing invocation (Section 10.4). Concluding a bypass from it would need a record that the invocations are complete, which is why high-assurance profiles need L2/L3 observers and transparency (Section 12.6).
- **Self-reporting.** Records produced by the actor alone are insufficient for high-impact effects (I10). Deployments SHOULD raise assurance to L2/L3 for `external_send` and above.
- **Canonicalization attacks.** Non-canonical resource forms enable bypasses (Section 6.2). Non-canonical JSON enables signature confusion; verifiers MUST verify over the canonical form they compute, never over bytes supplied in the packet.
- **Approval replay and TOCTOU.** Approvals bind the digest of the exact executed effect (I8) and are single-use.
- **Fail-open enforcement.** See Section 11.2. A verifier SHOULD treat an effect that contradicts a signed deny as bypass evidence (I11).
- **Self-declared enforcement.** A deny's `fail_mode` and `applied` are declared by the host that signs the decision, so Section 10.3 never treats them as showing that nothing was executed. A deny with no effect is `preserved` only on a `not_executed` statement from an observer (Section 5.14); without one it stays `unresolved`. Deployments that want denied calls to come out `preserved` SHOULD have the enforcement point or gateway issue call statements (Section 5.14) for every governed call.
- **Guardrail tampering.** Agent writes to hook configuration, keys, instruction files or the evidence store are violations (I9).
- **Selective logging and equivocation.** Producers SHOULD include sequence numbers and heartbeats; high-assurance profiles SHOULD use transparency logs with witnesses (Section 12.5). An absent record is `unresolved`, never `preserved`, which limits but does not eliminate the effect of suppression.
- **Time manipulation.** Revocation and expiry depend on time. Producers SHOULD use trusted time sources; verifiers SHOULD treat clock skew beyond a declared tolerance as `unresolved`.
- **Algorithm downgrade.** Algorithms are pinned per key (Section 12.2).
- **Parser and signature differentials (v0.3).** Two Verifiers that parse or verify the same bytes differently can be played against each other. AMEP closes the cases found so far by rule: unique member names, exact number literals, NFC identifiers, input bounds (Section 12.1), and one exact Ed25519 acceptance rule (Section 12.2).
- **Cross-protocol signature reuse (v0.3).** Version-2 proofs are domain-separated (Section 12.2), so a key that also signs data outside AMEP cannot have those signatures presented as AMEP evidence.
- **Unbounded quantities (v0.3).** Scope and ceiling do not bound how much an in-scope effect moves: a payment of any amount to an allowed payee, or a read of every record of an allowed table. Limits (Section 7.6) bound it, and a period total is never assumed to start at zero.
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
- **[RFC7493]** Bray, T., Ed., "The I-JSON Message Format", RFC 7493.
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
- **[IN-TOTO]** in-toto Attestation Framework, Statement v1.
- **[DSSE]** Dead Simple Signing Envelope, v1.
- **[SVR]** in-toto Attestation Framework, Simple Verification Result predicate, v0.2.

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

## Appendix B. Conformance vector index (suite v0.3.0)

<!-- vector-index:start -->
*Generated by `tools/vector_index.py`; regenerate it whenever the suite changes.*

Suite: 298 vectors (79 positive, 219 must-reject).

**Positive (expect `preserved`):** `action-under-a-mandate-with-rfc-3339-validity`, `amep-0-3-extension-claim-member-is-ignored`, `amep-0-3-packet-with-domain-separated-proofs`, `an-independent-operation-proceeds-while-another-is-held`, `approval-still-matches-when-the-bank-adds-its-running-total`, `approval-used-at-its-expiry-instant`, `approval-valid-from-the-instant-of-the-action`, `approved-adapter-revision--pinned`, `approved-payment-is-not-blocked-by-a-held-call`, `budget-from-earlier-packets-still-within-limit`, `build-cleanup-within-scope`, `bulk-read-within-the-record-limit`, `caip19-amount-at-the-largest-uint128`, `caip19-amount-of-25-digits--exactly-at-the-limit`, `call-failed-after-its-effects--counts-consistent`, `call-statement-and-receipt-bound-to-the-signed-invocation`, `command-writes-within-its-declared-scope-and-the-grant`, `converted-payment-within-the-limit-in-the-debit-currency`, `delegation-adds-a-deny`, `delegation-adds-a-stricter-limit`, `delegation-expiring-with-its-parent`, `delegation-keeps-the-parent-s-full-budget`, `deny-honoured-on-fail-closed-host--no-effect`, `derived-data-sent-to-an-allowed-recipient`, `effect-at-the-first-instant-of-validity`, `effect-at-the-last-instant-of-validity`, `effect-sent-to-the-audience-the-claims-name`, `extension-number-at-the-largest-i-json-integer`, `fresh-revocation-status`, `grants--an-effect-within-one-of-the-mandate-s-grants`, `grants--delegation-grants-within-a-plain-mandate`, `held-approval-released-when-the-earlier-call-is-shown-not-executed`, `held-call-later-reported-not-executed-releases-its-hold`, `held-call-within-the-period-limit`, `high-impact-call-reported-not-executed-by-an-independent-observer`, `high-impact-deny-on-a-fail-closed-host--reported-not-executed-by-an-independent-observer`, `high-impact-effect-observed-by-a-key-of-another-operator`, `identifier-in-nfc-with-non-ascii-characters`, `independently-observed-high-impact-effect`, `influence-confirmed-by-principal`, `influenced-read-only-action`, `jcs-canonical-form--unicode-keys--floats`, `limits-differing-only-in-actions-keep-separate-totals`, `mediated-effect-honored`, `mutation-influenced-only-by-trusted-content`, `nesting-at-the-depth-bound`, `observer-totals-are-kept-per-period--both-within`, `one-approval-for-a-two-effect-operation`, `operation-approval--an-approved-effect-not-executed`, `operation-approval-listing-one-body-twice--executed-twice`, `payment-over-the-per-call-limit-with-a-bound-approval`, `payment-through-a-second-service-within-the-total-in-verifier-state`, `payment-within-the-per-call-limit`, `payments-within-the-period-limit--observer-total-consistent`, `per-effect-caps-each-effect-of-a-call`, `propagation-window-of-exactly-an-hour`, `quarantined-content-promoted-by-the-principal`, `receipt-signed-within-the-observer-key-s-validity-interval`, `retry-after-the-first-attempt-is-shown-not-executed`, `reversible-write-is-cheaper`, `revocation-and-effect-on-different-operators--clocks--outside-their-skew`, `revoked-after-the-action--still-preserved`, `revoked-after-the-effect--with-a-declared-propagation-window`, `revoked-after-the-last-effect`, `revoked-mid-action--inside-the-declared-propagation-window`, `rfc-3339-timestamps`, `risk-budget-exceeded--human-approved`, `same-effect-observed-twice--host-and-backend`, `self-reported-high-impact-effect-corroborated-by-an-independent-observer`, `signed-statement-that-nothing-was-executed`, `simulated-deny-is-not-enforcement`, `status-current-as-of-the-action`, `two-hop-chain-within-bounds`, `unversioned-packet-keeps-v0-2-handling-of-unknown-claim-members`, `valid-bound-approval`, `valid-preserved-flow`, `validity-window-and-purpose-carried-through`, `well-formed-packet-given-as-text`, `within-risk-budget`.

**Must-reject:**

| Invariant | Outcome | Vectors |
|---|---|---|
| I1 | violated | `delegation-adds-data-class`, `delegation-changes-purpose`, `delegation-depth-not-decreasing`, `delegation-drops-nbf`, `delegation-extends-validity`, `delegation-from-a-zero-depth-parent`, `delegation-raises-the-per-call-limit`, `delegation-removes-a-deny`, `delegation-widens-actions`, `delegation-widens-its-parent-s-audiences`, `delegation-widens-resources`, `delegation-widens-risk-budget`, `delegation-without-depth-under-bounded-parent`, `expand-then-shrink-delegation`, `grants--delegation-wider-than-every-mandate-grant` |
| I2 | violated | `action-outside-delegated-actions`, `approved-payment-still-counts-toward-the-period-limit`, `arguments-rewritten-in-transit`, `budget-spent-in-earlier-packets`, `caip19-amount-in-the-asset-s-smallest-unit`, `caip19-amount-of-25-digits--one-unit-over-the-limit`, `command-effect-above-its-declared-class`, `command-write-outside-its-declared-scope`, `command-write-within-its-declared-scope-but-outside-the-grant`, `converted-payment-over-the-limit-in-the-debit-currency`, `cumulative-spend-exceeds-budget`, `declared----executed--path-retarget`, `delegation-s-stricter-limit-is-enforced`, `denied-action`, `destructive-command-drift--a3`, `effect-after-a-mandate-s-rfc-3339-expiry`, `effect-after-mandate-validity`, `effect-before-a-mandate-s-rfc-3339-nbf`, `effect-before-validity--nbf`, `effect-class-above-delegated-ceiling`, `effect-on-a-denied-resource`, `effect-outside-delegated-scope`, `grants--action-from-one-grant--resource-from-another`, `held-call-later-shown-executed-counts-toward-the-limit`, `high-impact-effect-outside-authority--recorded-only-by-a-key-of-the-actor-s-own-operator`, `high-impact-effect-outside-authority--recorded-only-by-the-actor`, `in-scope-bulk-read-over-the-record-limit`, `intent-cannot-lift-a-deny`, `intent-narrower-than-grant`, `limit-order--the-daily-limit-listed-first`, `limit-order--the-monthly-limit-listed-first`, `lying-adapter-caught-by-backend--l3`, `mediated-effect-not-honored`, `observer-s-own-month-is-not-held-against-it`, `observer-totals-are-kept-per-period--day-within--month-over`, `one-effect-over-the-per-effect-limit`, `one-operation-executed-twice`, `payment-in-an-asset-the-mandate-does-not-authorize`, `payment-over-the-per-call-limit-without-approval`, `payment-through-a-second-service-adds-to-the-total-in-verifier-state`, `payments-each-within-the-per-call-limit-but-over-the-period-limit`, `payments-through-two-services-against-one-cap`, `per-call-caps-the-whole-call--not-each-effect`, `period-limit-carried-across-packets-in-verifier-state`, `presentation-replayed-to-another-audience`, `rfc-3339-effect-after-expiry`, `risk-budget-exceeded-without-approval`, `second-effect-outside-declared`, `two-identical-payments-in-one-call-count-twice-toward-the-period-limit`, `two-identical-payments-in-the-same-second-count-twice-toward-the-period-limit`, `violation-outranks-unresolved-in-one-packet` |
| I3 | unresolved | `interpretation-from-provider-hint-only`, `unapproved-adapter-revision`, `unknown-interpretation` |
| I4 | unresolved | `influence-confirmed-only-by-the-host-s-flag`, `principal-confirmation-by-an-approver-other-than-the-principal`, `principal-confirmation-signed-by-a-host-key`, `principal-confirmation-that-does-not-name-the-finding`, `principal-confirmation-with-host-ui-presence`, `quarantined-content-promoted-only-by-the-host-s-flag` |
| I4 | violated | `injection-driven-mutation`, `quarantined-content-reached-the-agent--a1`, `unsigned-finding-claims-trusted` |
| I5 | violated | `data-leaving-after-a-read--a5`, `secret-released-externally--i5` |
| I6 | unresolved | `effect-within-the-clocks--skew-of-the-end-of-the-propagation-window`, `revocation-and-effect-on-different-operators--clocks--within-their-skew` |
| I6 | violated | `deny-on-a-fail-closed-host-does-not-clear-an-invocation-under-revoked-authority`, `revoked-at-the-instant-of-the-action`, `revoked-between-invocation-and-effect--singletary-case-1`, `revoked-between-two-effects-of-one-invocation--singletary-case-3`, `revoked-exactly-at-the-effect-time--singletary-case-2`, `revoked-mid-action--after-the-propagation-window`, `revoked-root-with-live-child`, `status-shows-revocation-at-the-instant-of-the-action`, `status-shows-revoked-before-action` |
| I7 | unresolved | `a-monthly-figure-does-not-settle-a-daily-limit`, `a-period-limit-without-a-counting-observer-needs-earlier-state`, `a-total-from-an-observer-the-limit-does-not-name-is-not-the-principal-s-total`, `amep-0-3-claim-member-the-verifier-does-not-understand`, `amep-0-3-limit-member-the-verifier-does-not-understand`, `amep-0-3-packet-with-a-version-1-proof`, `amount-in-exponent-form`, `amount-with-40-integer-digits`, `amount-with-a-leading-zero`, `amount-written-as-a-json-number`, `approval-held-for-an-earlier-call-with-an-unknown-outcome`, `approval-with-neither-effect-digest-nor-effect-digests`, `arguments-rewritten-in-transit--nothing-executed`, `audiences-in-an-unversioned-packet`, `caip19-amount-with-a-fractional-part`, `call-statement-bound-to-another-invocation`, `call-statement-signed-by-a-host-key`, `call-statement-with-a-negative-effect-count`, `call-statement-with-an-unknown-disposition`, `clock-skew-longer-than-an-hour`, `control-character-in-an-identifier`, `declared-scope-in-an-unversioned-packet`, `declared-scope-with-an-empty-list`, `deny-on-a-fail-closed-host-with-no-other-record`, `deny-on-fail-open-host--no-effect-record`, `duplicate-member-name-in-a-signed-effect-body`, `duplicate-member-name-in-an-extension-member`, `earlier-call-with-an-unknown-outcome-holds-the-period-limit`, `extension-float-1e21--outside-the-safe-range`, `extension-number-2-53---1--which-ecmascript-cannot-represent`, `extension-number-at-2-53--outside-i-json`, `forged-mandate--attacker-key`, `grants--an-empty-list`, `grants-beside-actions-and-resources`, `held-call-without-a-reserve-leaves-the-period-total-unbounded`, `identifier-not-in-nfc--decomposed-accent`, `identity-only-authorization--no-mandate`, `intent-reference-names-a-non-intent-object`, `intent-reference-unresolved`, `invocation-signed-by-unknown-key`, `limited-payment-whose-receipt-records-no-amount`, `lineage-reference-not-found`, `lone-surrogate-in-a-string`, `malformed-approval-hold-in-verifier-state`, `malformed-limit--period-without-per-period`, `malformed-timestamp`, `mandate-minted-by-host-key`, `mandate-signed-by-a-revoked-issuer-key`, `missing-effect-receipt`, `missing-parent-lineage`, `negative-amount`, `nesting-beyond-the-depth-bound`, `noncharacter-in-a-string`, `not-executed-statement-that-counts-effects`, `observer-figure-for-another-window-does-not-count`, `observer-figure-that-names-no-window-does-not-count`, `operation-approval-that-also-has-effect-digest`, `operation-approval-with-an-empty-list`, `period-limit-without-an-observer-total-or-earlier-state`, `post-execution-decision-cannot-claim-a-block`, `propagation-window-longer-than-an-hour`, `receipt-does-not-record-the-audience-the-claims-are-bound-to`, `receipt-replayed-from-another-invocation`, `receipt-signature-with-s----l--malleated`, `receipt-signed-at-the-observer-key-s-expiry`, `receipt-signed-before-the-observer-key-s-nbf`, `receipt-signed-by-a-revoked-observer-key`, `receipt-that-names-no-observer`, `receipt-under-a-small-order--identity--public-key`, `receipt-under-a-small-order--order-2--public-key`, `record-limit--quantity-reported-in-another-unit`, `reserve-with-a-numeric-amount`, `retry-of-an-operation-whose-first-attempt-has-an-unknown-outcome`, `retry-under-a-fresh-mandate-is-still-held-for-the-first-attempt`, `revocable-mandate-without-status`, `self-approval-signed-by-host-key`, `stale-revocation-status`, `statement-promises-two-receipts--one-present`, `status-current-at-the-invocation-but-stale-at-the-effect`, `string-beyond-the-size-bound`, `tampered-effect-receipt`, `two-objects-with-the-same-id`, `unsigned-approval`, `unsigned-call-statement`, `unsigned-intent`, `unsigned-invocation`, `unsigned-revocation-on-the-chain`, `unsupported-amep-version`, `unversioned-packet-with-grants`, `value-given-as-a-string-instead-of-an-object`, `version-1-signature-relabelled-as-version-2` |
| I7 | violated | `more-receipts-than-the-call-statement-counts`, `observer-period-total-below-the-recorded-payments`, `recorded-budget-spend-mismatch` |
| I8 | violated | `a-held-approval-does-not-hide-an-effect-the-approval-doesn-t-cover`, `an-approval-of-the-amount-before-fees-does-not-bind-the-debit`, `approval-digest-mismatch--toctou`, `approval-not-yet-valid`, `approval-replay--consumed`, `approval-reused-across-packets`, `approval-reused-for-a-second-invocation`, `effect-outside-the-operation-approval`, `held-approval--the-earlier-call-is-shown-executed--so-the-second-use-is-a-double-use`, `one-approval--the-approved-payment-executed-twice-in-one-call`, `one-approval--the-approved-payment-executed-twice-in-the-same-second`, `operation-approval-covers-a-body-once--executed-twice`, `operation-approval-expired-before-the-second-effect`, `operation-approval-spent-again-by-a-retried-invocation`, `stale-approval--expired` |
| I9 | violated | `guardrail-write--i9`, `guardrail-write-via-absolute-path--i9`, `mediated-into-a-guardrail-path--i9` |
| I10 | unresolved | `high-impact-call-reported-not-executed-only-by-a-key-of-the-host-s-own-operator`, `high-impact-call-reported-not-executed-only-by-the-actor`, `high-impact-deny-on-a-fail-closed-host--no-independent-record`, `high-impact-effect-observed-only-by-a-key-of-the-host-s-own-operator`, `high-impact-effect-within-authority--recorded-only-by-the-actor`, `high-impact-effect-without-actor`, `self-report-of-two-executions--one-independently-observed`, `self-reported-high-impact-effect`, `the-actor-s-own-record-says-something-else-was-executed`, `write-shared-call-reported-not-executed-only-by-the-actor`, `write-shared-effect-only-self-reported` |
| I11 | unresolved | `audit-only-discovery-of-an-unknown-agent--a6`, `bypass--effect-without-invocation` |
| I11 | violated | `deny-contradicted-by-executed-effect`, `deny-on-a-fail-closed-host-contradicted-by-an-observed-effect`, `receipt-contradicts-a-not-executed-statement` |
<!-- vector-index:end -->

**Planned for v0.3:** unknown MCP endpoint; MCP manifest rug-pull; tool shadowing; compound command; obfuscated execution; script indirection; GET with side effects; GraphQL mutation via POST; key/token read; agent impersonation; self-approval without presence; approval-fatigue loop; taint exfiltration via an allowed channel; memory-poisoned sleeper mutation; revocation quiescence breach; mediation-proof mismatch; approval reuse across packets.

---

## Appendix C. Relationship to other work (informative)

| Work | Relationship |
|---|---|
| OAuth Token Exchange, Transaction Tokens, Cross App Access / ID-JAG | Sources of mandates and delegation. AMEP verifies that effects stayed within them. |
| OpenID AuthZEN (+ Approval, Obligations) | Decision transport. A ContinuityDecision is an AuthZEN decision plus evidence. |
| IETF AUDIT | Record layer. AMEP is the continuity-evaluation profile over AUDIT records (see `draft-stafordtituss-agentic-mandate-evidence`). |
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
- *Suite v0.2.3 (normative, Section 12.1):* numbers whose magnitude exceeds 2^53 − 1 are malformed, so every invocation in a packet containing one is `unresolved` (I7); Verifiers parsing text SHOULD reject number literals a double cannot represent exactly. Previously only producers were advised to avoid such integers, and the two reference verifiers canonicalized 2^53 + 1 differently (Python exactly, JavaScript as 2^53), returning different verdicts on the same signed packet. 4 vectors (1 positive, 3 must-reject); the JCS vector's large float changes from `1e21` to `1e15`, inside the range.
- *Suite v0.2.2 (no normative change):* 3 vectors for an agent acting directly under a mandate with RFC 3339 `exp` and `nbf`. Both reference verifiers compared the effect time with the unconverted string on this path; Python returned `unresolved`/I7 and JavaScript never detected an effect outside the window. Found by the AgentDojo experiment (`experiments/agentdojo`).
- *Suite v0.2.1 (no normative change):* 16 vectors added from mutation analysis of the reference evaluator, covering the action-widening and effect-ceiling rules, write_shared as high impact, intent references to non-intent objects, approval `nbf`, verdict precedence within a packet, and the inclusive edge of every time, budget and approval-window bound.

---

## Appendix E. Open issues

- **E.1 Workflow-level outcomes.** Composition and disclosure across many invocations (WorkflowContinuityDecision) are reserved for v0.3.
- **E.2 Revocation quiescence.** A window Δ for revocations still propagating is needed for I6 in distributed deployments.
- **E.3 Signed verifier state.** State across packets (Section 10.7) is the verifier's own bookkeeping. A standard signed format for publishing it is not yet defined.
- **E.4 Token-profile vectors.** The Biscuit, Macaroon and UCAN profiles have no conformance vectors yet. They need a profile-aware verifier that maps tokens onto claims, built on reference token libraries.
- **E.5 Lineage completeness.** A verifier can check the lineage it is given (Section 5.9.1) but cannot detect lineage a host failed to record.

*Resolved in draft.2:* exact JCS, approval timing and key-to-role binding, and the reference-verifier divergences found in draft.1. *Resolved in draft.3:* the capability-token profile (Biscuit, Macaroon), and CDDL validation: the CDDL is checked with the `cddl` tool and every vector validates against it (`tools/validate_cddl.py`). That check found and fixed a clash between AMEP's time type and the `time` type built into the CDDL prelude. *Resolved in draft.4:* state across packets, data leaving after a read, the UCAN profile, and a second JSON Schema validator (the `jsonschema` library now runs alongside the built-in one, and the two must agree on every vector).
