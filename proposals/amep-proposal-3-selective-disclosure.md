# AMEP-Proposal-3: Selective disclosure

| | |
|---|---|
| **Status** | Draft for discussion |
| **Targets** | AMEP core v0.4 |
| **Author** | Staford Titus Selvaraj (editor) |
| **Created** | 2026-11-25 |
| **Discussion** | Issues in https://github.com/stafordtituss/amep |

## 1. Summary

**The idea:** let a producer sign a record so that some of its members can later be withheld without breaking the signature. The pattern is SD-JWT's (RFC 9901): salted digests of the members are signed, and the members themselves travel as separate disclosures.

**What a verifier then does:** it checks what was disclosed. Where a rule needs a member that was withheld, the result is `unresolved`, with gap `disclosure`, naming the member. Never `preserved`.

## 2. Motivation

An AMEP packet is evidence an organization may need to show to an auditor, a counterparty or a regulator. Some of what it carries shouldn't travel that far:
- a customer's file path or account in a `resource`;
- a recipient;
- a mandate's `purpose`;
- an approver's identifier.

Today the only options are to share the whole signed record, or to strip it and lose the signature.

The verdict rarely needs all of it. To show that a payment was within a limit, the verifier needs the amount and unit, not the payee's name. To show that a write was inside `repo:app/src/*`, it needs the resource, but the action approval only needs its digest.

## 3. The form

A producer marks members of a signed object as disclosable. In the signed object, each such member is replaced by its digest:

```json
{ "id": "e-1", "kind": "effect", "invocation": "i-1", "observed_by": "bank",
  "executed": { "action": "payments.send", "effect": "financial", "t": 11,
                "value": { "amount": "120.00", "unit": "iso4217:EUR" },
                "_sd": ["<b64url SHA-256 of disclosure 1>"] },
  "proof": { ... } }
```

Each disclosure is `[salt, member name, value]`, base64url-encoded as in SD-JWT, and carried in the packet's `disclosures` array. The signature covers the object with `_sd`, so withholding a disclosure leaves it valid. Revealing one shows the member was signed.

**Rules:**
1. **No disclosure for an undisclosable member.** Members that identify the object or bind it to others are never disclosable: `id`, `kind`, `invocation`, `invocation_digest`, `authority_ref`, `parent`, `approval_ref`, `effect`, `t`, `proof`. An `_sd` digest that discloses one of them makes the object malformed: `unresolved` (I7).
2. **Digests are checked first.** A disclosure whose digest isn't in an `_sd` array of the object it claims to belong to is ignored. Two disclosures for one member are malformed.
3. **The evaluator sees the object with disclosures re-inserted.** Then every rule runs as today.
4. **A rule that needs a withheld member** returns `unresolved` (I7), gap `{need: "disclosure", ref: "<object id>/<member>"}`. It never returns `preserved`.
5. **Approval digests** (spec 5.10) are computed over the effect body *with its disclosures re-inserted*. So an approval binds to what was approved, not to which members happen to be disclosed. To check the binding, the verifier needs every disclosure of the approved body; otherwise rule 4 applies.

## 4. What it does and doesn't hide

- **Hides:** a member's value, from a party not given its disclosure. The salt stops guessing over small domains, such as a known set of file names.
- **Doesn't hide:** that a member exists, or how many disclosable members an object has (the length of `_sd`). Producers MAY add decoy digests, as SD-JWT allows.
- **Doesn't hide anything from the signer,** or from anyone the holder gives disclosures to. It controls onward sharing, not collection.

## 5. Interaction with existing rules

| Rule | Needs | Withheld → |
|---|---|---|
| I2, effect within authority | `action`, `resource`, `effect` of the executed body; the claims they're checked against | `unresolved`, gap `disclosure` |
| Limits (7.6) | `value.amount`, `value.unit` | `unresolved`, gap `disclosure` |
| I5, release of data | `released`, `recipient`, `accessed` | `unresolved`, gap `disclosure` |
| I8, approval binding | the full approved body | `unresolved`, gap `disclosure` |
| I10, observer independence | `observed_by` and `actor` (disclosable), plus the keys (never disclosable) | The key test still runs. The name test returns a gap. |

**The verdict record** (spec 10.8) names the packet's digest. A record over a packet with fewer disclosures is a different record, for a different packet, so no one can pass off a partial view as the full one.

## 6. Why not alternatives

- **Hash-only redaction after signing:** it breaks the signature, or needs the signer to re-sign every view.
- **Zero-knowledge proofs over the whole evaluation:** stronger, but well beyond what any AMEP producer can deploy today. Salted-digest disclosure is what SD-JWT already deploys in AP2 checkouts, which AMEP verifies (`interop/ap2/`).

## 7. Next steps

1. Comments, especially from deployments that need to share packets across organizations.
2. Vectors:
   - a payment proven within its limit with the payee withheld (`preserved`);
   - the same with the amount withheld (`unresolved`, `disclosure`);
   - a disclosure for `invocation_digest` (malformed);
   - a disclosure not in `_sd` (ignored);
   - an approval checked over a partly withheld body (`unresolved`).
3. Implementation in both reference verifiers.
