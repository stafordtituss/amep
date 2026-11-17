# AMEP Profile: UCAN (`AMEP-UCAN`)

| | |
|---|---|
| **Document** | `amep-profile-ucan` |
| **Version** | 0.2.0-draft.4 |
| **Status** | Public Draft. Companion to `spec/amep-v0.2.md` (the "core"). |
| **Author** | Staford Titus Selvaraj |

The key words MUST, SHOULD and MAY are used as in BCP 14 (RFC 2119, RFC 8174).

*Note:* field names and policy syntax below follow the UCAN 1.0 delegation specification. Implementers MUST check them against the current UCAN text before relying on this draft; Appendix E.4 of the core tracks the conformance vectors still needed.

## 1. Purpose

UCAN (User-Controlled Authorization Networks) delegations are signed by the delegator's key and addressed to a specific audience key. Each delegation in a chain narrows the command and adds policy conditions. Unlike Macaroons and Biscuit, a UCAN is **not a bearer token**: using it requires a signature from the audience's key. That makes UCAN chains safe to include in evidence packets, and a natural carrier for AMEP mandates and delegations between parties identified by DIDs.

As with every AMEP profile, the token is the **source** of signed AMEP Mandate and Delegation objects. It never replaces them.

## 2. Structure

| UCAN delegation field | AMEP |
|---|---|
| `iss` (delegator DID) | signer of the AMEP object; its key MUST hold role `issuer` (root) or `issuer`/`host` (later hops) in the AMEP key set |
| `aud` (delegate DID) | Delegation `delegate` (or mandate `subject_agent` for the root) |
| `sub` (subject DID) | mandate `principal` when `iss` equals `sub` (the root delegation) |
| `cmd` | `actions` (Section 3) |
| `pol` | `resources`, `deny_actions`, `deny_resources`, `ceiling`, `data` (Section 4) |
| `nbf`, `exp` | `nbf`, `exp` |
| `meta.amep_depth` | `depth` (UCAN has no depth limit of its own) |
| `meta.amep_budget` | `budget` |
| content identifier of the delegation | AMEP object `id`, and the revocation `target` |

The root delegation (where `iss` equals `sub`) maps to the PrincipalMandate. Each later delegation maps to one Delegation, in chain order.

## 3. Commands

UCAN commands are `/`-separated paths, and a delegation of a command also covers every command below it. AMEP actions map as follows:

| UCAN `cmd` | AMEP action pattern |
|---|---|
| `/` | `*` |
| `/fs` | `fs.*` |
| `/fs/write` | `fs.write` |

A child delegation's `cmd` MUST equal, or be below, its parent's. That is UCAN's own rule, and it is AMEP's I1 for actions.

## 4. Policy statements (normative subset)

A UCAN policy is a list of statements, all of which must hold. AMEP-conformant delegations MUST use only the following statement forms, evaluated against the AMEP authorizer facts (`.resource`, `.action`, `.effect_rank`, `.released`):

| Statement | AMEP claim |
|---|---|
| `["like", ".resource", "<pattern>"]` | one entry of `resources` |
| `["or", [ ["like", ".resource", "<p1>"], ["like", ".resource", "<p2>"] ]]` | several entries of `resources` |
| `["not", ["like", ".resource", "<pattern>"]]` | one entry of `deny_resources` |
| `["not", ["like", ".action", "<pattern>"]]` | one entry of `deny_actions` |
| `["<=", ".effect_rank", <n>]` | `ceiling`, using the ranks `read`=0 … `financial`=5 |
| `["all", ".released", ["or", [ ["==", ".", "<flow>"], … ]]]` | `data` |

Patterns use a trailing `*` only, as in core 6.3.

UCAN applies every policy in a chain to an invocation, so the claims of a delegation are the **meet** of its own statements and those of every delegation above it (core 7.3). A delegation containing any other statement form cannot be mapped. A profile-aware verifier MUST treat its chain as `unresolved` (I7, "unmappable token").

## 5. Relationship to the AMEP packet

Mandate and Delegation objects derived from a UCAN carry:

```json
"token": { "format": "ucan", "block": 1, "digest": "<lowercase hex SHA-256 of the encoded delegation>", "value": "<base64url of the encoded delegation>" }
```

`value` MAY always be included, because a UCAN cannot be used without the audience's key. A profile-aware verifier verifies each delegation's signature, maps it per Sections 2–4, and compares the result with the AMEP object's `claims`. Any mismatch is `unresolved` (I7).

## 6. Revocation

A UCAN revocation names the content identifier of a delegation. The revoking party MUST also publish a signed AMEP Revocation (core 5.12) targeting the corresponding Mandate or Delegation `id`, so that verifiers without UCAN support reach the same result.

## 7. Security considerations

- DIDs used as `iss` must resolve to keys that appear, with the right roles, in the AMEP key set the verifier uses. A verifier MUST NOT accept a key only because a DID document lists it.
- Keep the policy subset small. General UCAN policies can express conditions whose narrowing a verifier cannot decide.
