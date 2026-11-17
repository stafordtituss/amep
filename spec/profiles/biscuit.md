# AMEP Profile: Biscuit (`AMEP-Biscuit`)

| | |
|---|---|
| **Document** | `amep-profile-biscuit` |
| **Version** | 0.2.0-draft.4 |
| **Status** | Public Draft. Companion to `spec/amep-v0.2.md` (the "core"). |
| **Author** | Staford Titus Selvaraj |

The key words MUST, SHOULD and MAY are used as in BCP 14 (RFC 2119, RFC 8174).

## 1. Purpose

Biscuit is a bearer authorization token with public-key signatures, offline attenuation, and a Datalog policy language. It is the **preferred** way to carry AMEP mandates and delegations, because anyone with the issuer's public key can verify it, and because a holder can narrow it without contacting the issuer.

This profile defines:

1. a **constrained fact and check vocabulary**, so that every conformant Biscuit maps onto exactly one AMEP claim set;
2. how the token relates to the signed AMEP Mandate and Delegation objects in a packet;
3. what a verifier does when the two disagree.

Biscuit never replaces AMEP evidence. The packet still contains signed Mandate and Delegation objects (core 5.4, 5.5). The token is their **source**, and a profile-aware verifier checks that they agree.

## 2. Structure

| Biscuit part | AMEP object |
|---|---|
| Root key | A key with role `issuer` in the AMEP key set (core 12.5), algorithm Ed25519. |
| Authority block | The PrincipalMandate. |
| Each attenuation block | One Delegation, in chain order. |
| Block revocation identifier | The `id` used as a revocation `target` (core 5.12). |

## 3. Authority block vocabulary (normative)

The authority block MUST contain exactly these facts (optional ones may be omitted), and no others in the `amep_` namespace:

| Fact | AMEP claim | Notes |
|---|---|---|
| `amep_version("0.2")` | — | Required. |
| `mandate_id($id)` | `id` | Required. |
| `principal($p)` | `principal` | Required. |
| `subject_agent($a)` | `subject_agent` | |
| `allow_action($pattern)` | one entry of `actions` | At least one. Patterns per core 6.3. |
| `allow_resource($pattern)` | one entry of `resources` | At least one. |
| `deny_action($pattern)` | one entry of `deny_actions` | |
| `deny_resource($pattern)` | one entry of `deny_resources` | |
| `data_flow($flow)` | one entry of `data` | `"class->recipient"`. |
| `ceiling($class)` | `ceiling` | Required. One of the core 5.1.3 classes. |
| `purpose($p)` | `purpose` | |
| `depth($n)` | `depth` | |
| `budget($n)` | `budget` | |

Validity is expressed with the standard Biscuit time check, and nothing else:

```
check if time($t), $t <= 2026-11-17T23:00:00Z;   // exp
check if time($t), $t >= 2026-11-17T09:00:00Z;   // nbf (optional)
```

The authority block MUST also contain the AMEP enforcement rules below, so that a standard Biscuit authorizer enforces the mandate directly:

```
check if action($a), allow_action($p), $a.starts_with($p.trim_end("*")) or $p == "*";
check if resource($r), allow_resource($p), $r.starts_with($p.trim_end("*")) or $p == "*";
reject if action($a), deny_action($p), $a.starts_with($p.trim_end("*")) or $p == "*";
reject if resource($r), deny_resource($p), $r.starts_with($p.trim_end("*")) or $p == "*";
check if effect_rank($n), ceiling_rank($c), $n <= $c;
```

with `ceiling_rank($c)` derived from `ceiling` using the order `read`=0, `write_local`=1, `write_shared`=2, `external_send`=3, `destructive`=4, `financial`=5.

*Note:* these rules express core 6.3's trailing-`*` pattern semantics. If an implementation's Biscuit library lacks `trim_end`, it MUST store patterns with the `*` already removed in a parallel fact (`allow_action_prefix`) and match on that. Exact syntax is checked against the Biscuit library used by the conformance suite (see core Appendix E.7).

## 4. Attenuation block vocabulary (normative)

An attenuation block represents one Delegation. It MUST contain `delegation_id($id)` and MAY contain `delegate($d)` and `depth($n)`. Its narrowing MUST be expressed **only** with checks of the following forms. Each maps to a narrowing of one claim:

| Check form | Narrows |
|---|---|
| `check if action($a), [ "p1", "p2" ].contains($a);` (exact names) or `check if action($a), $a.starts_with("prefix");` | `actions` |
| `check if resource($r), $r.starts_with("prefix");` | `resources` |
| `reject if action($a), $a.starts_with("prefix");` | adds to `deny_actions` |
| `reject if resource($r), $r.starts_with("prefix");` | adds to `deny_resources` |
| `check if effect_rank($n), $n <= k;` | lowers `ceiling` |
| `check if released($f), [ … ].contains($f);` | narrows `data` |
| `check if time($t), $t <= T;` / `$t >= T;` | shortens `exp` / raises `nbf` |
| `check if purpose("p");` | fixes `purpose` (only if the parent has none, or the same) |

Biscuit's design already guarantees that an attenuation block cannot widen what the authority block allows: blocks can only add checks. A block that contains **any other** rule, check, or fact in the `amep_` namespace cannot be mapped to an AMEP claim set. A profile-aware verifier MUST treat such a chain as `unresolved` (I7, "unmappable token"). It MUST NOT guess.

Facts declared in attenuation blocks MUST NOT be trusted by authority-block rules. Implementations MUST use Biscuit's default scoping, which already prevents this, and MUST NOT add `trusting` clauses that widen it.

## 5. Authorizer (ambient) facts

When enforcing, a PEP provides these facts for the invocation being decided, from its canonical form (core 6):

```
action("fs.write");  resource("repo:app/src/auth.ts");  effect("write_local");  effect_rank(1);
released("source->internal");  time(2026-11-17T19:12:00Z);
```

The PEP MUST derive them from the AdapterInterpretation (core 5.7), never from the agent's own description of the call.

## 6. Relationship to the AMEP packet

A Mandate or Delegation object whose authority came from a Biscuit includes:

```json
"token": { "format": "biscuit", "block": 0, "digest": "<lowercase hex SHA-256 of the serialized token>" }
```

- `block` is `0` for the authority block, `n` for the n-th attenuation block.
- `value` (the base64url-encoded token) MAY be included **only** when the token has expired, or when it is bound to a holder key by a check that requires proof of possession. A live bearer token in an evidence packet can be replayed by anyone who reads the packet.
- The AMEP object's `claims` MUST equal the claim set obtained by mapping the corresponding block (Sections 3–4), met with its parent's claims.

A **profile-aware verifier**, when `token.value` is present:

1. verifies the Biscuit with the issuer's public key;
2. maps each block to a claim set;
3. compares it with the `claims` of the AMEP object at the same position.

Any mismatch is `unresolved` (I7, "claims do not match carried token"). When only `digest` is present, the verifier relies on the signed AMEP objects alone (the core behaviour), and SHOULD say that the token was not checked.

## 7. Revocation

Biscuit revocation identifiers identify blocks. An issuer that revokes a block MUST also publish a signed AMEP Revocation (core 5.12) whose `target` is the corresponding Mandate or Delegation `id`, so that verifiers without Biscuit support reach the same result.

## 8. Example

Authority block (mandate `m-1`):

```
amep_version("0.2"); mandate_id("m-1"); principal("user:alice");
allow_action("fs.*"); allow_action("process.exec");
allow_resource("repo:app/*"); deny_resource("repo:app/secrets/*");
data_flow("source->internal"); ceiling("write_local"); depth(2);
check if time($t), $t <= 2026-11-17T23:00:00Z;
// + the enforcement rules of Section 3
```

Attenuation block (delegation `d-1` to a sub-agent):

```
delegation_id("d-1"); delegate("agent:tests-writer"); depth(1);
check if action($a), ["fs.write"].contains($a);
check if resource($r), $r.starts_with("repo:app/tests/");
reject if resource($r), $r.starts_with("repo:app/tests/fixtures/prod/");
check if time($t), $t <= 2026-11-17T21:00:00Z;
```

Maps to the Delegation claims: `actions ["fs.write"]`, `resources ["repo:app/tests/*"]`, `deny_resources ["repo:app/secrets/*", "repo:app/tests/fixtures/prod/*"]`, `ceiling "write_local"`, `exp 2026-11-17T21:00:00Z`, `depth 1`.

## 9. Security considerations

- Biscuit tokens are bearer tokens. Keep them short-lived; bind high-risk grants to a holder key.
- Do not let semantic engines or agents author Datalog. Blocks are produced by the host or issuer from canonical claims.
- Restricting the check vocabulary is what makes Biscuit safe as a standard profile. Arbitrary Datalog can express policies whose narrowing no verifier can decide.
