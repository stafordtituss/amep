# AMEP Profile: Macaroons (`AMEP-Macaroon`)

| | |
|---|---|
| **Document** | `amep-profile-macaroon` |
| **Version** | 0.2.0-draft.4 |
| **Status** | Public Draft. Companion to `spec/amep-v0.2.md` (the "core"). |
| **Author** | Staford Titus Selvaraj |

The key words MUST, SHOULD and MAY are used as in BCP 14 (RFC 2119, RFC 8174).

## 1. Purpose and hard limit

Macaroons are bearer tokens whose holders can add caveats (restrictions) without contacting the issuer. They suit fast, short-lived operational grants inside one organization.

**Hard rule.** A Macaroon is verified with the issuer's **shared secret** (an HMAC chain). Anyone able to verify it is also able to mint one. A Macaroon therefore MUST NOT be used as third-party evidence that a mandate was valid. It may be the **source** of a mandate or delegation. It must never be the only proof of one.

A party holding the root secret that verifies a Macaroon grant MUST restate it as signed AMEP objects (a PrincipalMandate and, per added caveat set, a Delegation), signed with a key holding role `issuer` (core 12.5). Those signed objects are the evidence.

## 2. Canonical caveats (normative)

First-party caveats in the `amep.` namespace use the grammar `amep.<field> <op> <value>`, with single spaces and values exactly as in the AMEP claim model:

| Caveat | AMEP claim | Combination rule when repeated |
|---|---|---|
| `amep.principal = <id>` | mandate `principal` | must all be equal |
| `amep.agent = <id>` | `subject_agent` / `delegate` | must all be equal |
| `amep.action in <p1>,<p2>,…` | `actions` | intersect |
| `amep.resource in <p1>,<p2>,…` | `resources` | intersect |
| `amep.deny_action <pattern>` | `deny_actions` | union |
| `amep.deny_resource <pattern>` | `deny_resources` | union |
| `amep.data in <flow>,…` | `data` | intersect |
| `amep.ceiling <= <class>` | `ceiling` | lowest |
| `amep.purpose = <p>` | `purpose` | must all be equal |
| `amep.exp <= <RFC 3339 time>` | `exp` | earliest |
| `amep.nbf >= <RFC 3339 time>` | `nbf` | latest |
| `amep.depth <= <n>` | `depth` | lowest |
| `amep.budget <= <n>` | `budget` | lowest |

Because every caveat on a Macaroon must hold, the claims a Macaroon grants are the **meet** of its caveats (core 7.3). Adding caveats can only narrow, which matches I1.

A verifier MUST reject a Macaroon carrying an `amep.` caveat it does not recognize. That is standard Macaroon behaviour, and it prevents silently ignored restrictions.

### 2.1 Caveats that are not claims

Some product caveats express checks rather than claims. They map to AMEP evidence objects instead:

| Product caveat | AMEP equivalent |
|---|---|
| "approval required for mutating actions" | `ceiling` at or below `write_local`, with `step_up` above it; the approval is an ApprovalBinding (core 5.10) |
| maximum risk level | `ceiling` and/or `budget` (core 9) |
| content trust level | I4: untrusted findings require principal confirmation (core 5.11) |
| "receipt required" | the profile in use requires an ExecutedEffectReceipt (core 14) |

### 2.2 Third-party caveats

| Third-party caveat (discharged by) | AMEP evidence the discharger SHOULD also emit |
|---|---|
| approval service / human reviewer | ApprovalBinding signed by an `approver` key |
| content scanner | ContentFinding signed by a `host` or `observer` key |
| tool registry / MCP gateway | AdapterInterpretation with `source: curated`, plus adapter pinning |
| data classification service | data classes on the effect body (`released`) |
| egress / DLP broker | ExecutedEffectReceipt at assurance L2 |

## 3. Relationship to the AMEP packet

The restated Mandate or Delegation object records its source:

```json
"token": { "format": "macaroon", "digest": "<lowercase hex SHA-256 of the serialized macaroon>" }
```

The Macaroon itself MUST NOT appear in evidence packets. It is a live bearer credential, and verifying it would need the root secret anyway.

## 4. Example

```
location: https://grants.example
identifier: m-1
caveats:
  amep.principal = user:alice
  amep.action in fs.read,process.exec
  amep.resource in repo:app/*
  amep.deny_resource repo:app/secrets/*
  amep.ceiling <= read
  amep.exp <= 2026-11-17T23:00:00Z
```

The grant service verifies the Macaroon and emits mandate `m-1` with the same claims, signed by its `issuer` key and carrying the `token` digest.

## 5. Security considerations

- Root secrets SHOULD be derived per tenant from a KMS and rotated. A leaked root secret lets the holder mint any grant.
- Grants SHOULD live minutes, not days, and be bound to a session.
- Never log or export a Macaroon. Log its digest.
