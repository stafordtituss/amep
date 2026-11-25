# Provenza Proof of Authority as AMEP evidence: a gap report

**Pinned to:** Provenza **v0.5.0** (19 November 2026), pvp/1 (`docs/pvp/spec.md`, section 3.4), `docs/proof-of-authority.md`, and the schemas in `docs/pvp/schemas/`. Proof of Authority hasn't changed since 15 November.

**What this is:** an independent reading, requested by Provenza's maintainer in kironovlaziz-del/provenza#249. Provenza hasn't reviewed or endorsed it.

**What it's based on:** the published documents and schemas only. v0.5.0 ships no sample authority or completeness file, so nothing here has been run against a real file yet (section 5).

## 1. Two questions, side by side

| | Provenza Proof of Authority | AMEP |
|---|---|---|
| **Asks** | Who allowed this action? | Did what the action did stay within what was allowed? |
| **Ends at** | The decision, and the record of it, sealed in a signed log | The executed effect, as observed by a party other than the agent |
| **Completeness** | A completeness report: the seal chain shows these are all of an agent's recorded actions in a period | None in the core (`LIMITS.md`, section A) |

The two meet in the middle. Provenza's chain of authority is the left half of AMEP's chain, with signatures AMEP would accept, and in places stronger ones. AMEP adds the right half: the observed effect, judged against that authority.

## 2. Link by link

| Provenza link | AMEP object | Maps | Gap |
|---|---|---|---|
| **Task** (`provenza.mandate`): signed with a session key that the person's passkey certified; names `tools`, `valid_hours`, `task` | `mandate`, principal = the person | `tools` → `actions`; `issued_at + valid_hours` → `exp`; WebAuthn → a strong `issuer` proof | **No resource scope and no effect class:** a task grants tools, not resources. The AMEP mandate needs `resources` and `ceiling` from a deployment tool map, as for AER-1. **The task text** is human intent, which AMEP keeps as a `purpose` token, not as rules. |
| **Task ended** (`provenza.mandate.end`, or the replacing task) | `revocation` (spec 5.12), at the statement's `issued_at` | Exact: a signed end at a stated time. AMEP evaluates it at each effect's own time (I6) | None |
| **Policy release:** a bundle of agent rights, signed by an administrator quorum, chained from release 1 | A `mandate` from the organization, beneath the task | The bundle's allowed tools for the agent → `actions`. The release chain is a history AMEP has no counterpart for | **Resources and effect class** again. **Quorum signing:** AMEP has one signature per object, so a quorum maps to one issuer signature plus a profile rule. |
| **Delegation hops,** each signed by the delegating agent's key | `delegation` | Exact in shape | **Narrowing:** "a hop that names its tools passes this one on". AMEP needs every hop to be narrower than its parent (I1). Whether a hop that names *no* tools inherits all of them, and whether a hop can widen, should be stated. |
| **The agent's signed request** (`action.request`: agent, chain, type, tool, `input_sha256`, `mandate_id`, nonce) | `invocation`, signed by the host or agent key | `tool_name` → declared action, through the tool map; `mandate_id` → `authority_ref` | **`input_sha256` is not `args_digest`:** PVP hashes Provenza's own canonical form (sorted keys, ASCII with `\uXXXX` escapes), and AMEP's `args_digest` is RFC 8785. The two agree only for arguments that serialize identically under both (ASCII-only text, integers). A layout name next to the hash would let an importer say which, as AER-1 now does. |
| **Approval:** a person's passkey certifies a session key, which signs approval of exactly this call (agent, chain, type, tool, `input_sha256`) | `approval`, `presence: webauthn` | Presence is the strongest AMEP names | **What it binds:** the *request*, where AMEP binds the *executed effect* (`effect_digest`). An approved request that executed something else isn't caught by the approval alone. Maps to an approval over the invocation, with a gap until the effect is observed. |
| **Executed by a Provenza gateway** (`executed_by`) | `effect`, observer = the gateway | The gateway is a witness the agent doesn't control: the shape of I10 | **No executed-effect description:** the evidence holds ids, hashes and signatures, and no action, resource or effect class for what was done. The tool map supplies them, capped at L1. **No `not_executed` statement** for a refusal after an allowed check. |
| **Tool definition digest** | `interpretation` (I3) | The gateway checks the live definition against the hash pinned at approval | **Announced, not yet released** (provenza#249): the digest isn't in the evidence yet. When it is, it binds the interpretation to the definition actually called. |
| **Seal → audit record → signed checkpoint** (RFC 9162) | Transparency, spec 12.6 (informative) | Stronger than the AMEP core, which defines no log | AMEP has no rule that consumes a checkpoint. The record is integrity-protected, but AMEP can't yet use the inclusion. |
| **Completeness report** (seals *n..m* unbroken; the agent's actions in them are all of its recorded actions) | No counterpart | **Closes AMEP's completeness limit for the decision record:** no recorded action of that agent was left out | It covers *recorded actions*, not effects that bypassed Provenza. For effects, it pairs with an observer below the agent, such as an Observed Effect record (`interop/in-toto/OBSERVED-EFFECT.md`). |
| **Key revocations** (`GET /agents/key-revocations`) | Key status, spec 12.4 | Same question | Outside the receipt, so a verifier needs that history alongside the file. |

## 3. What an AMEP import would conclude, today

For an action with a full Proof of Authority (task, signed release, signed request, approval, gateway execution), given a deployment tool map:
- **The authority half is checkable,** and in places stronger than AMEP requires: passkey-certified tasks and approvals, a release chain, a log inclusion.
- **The effect half rests on the tool map and the gateway's word:** at most an L1 effect receipt.
- **High-impact calls stay `unresolved`** unless the gateway is run by an operator other than the agent's host (I10, spec 12.5).
- **Arguments bind to the call only when they serialize identically under both canonical forms.**

## 4. Small changes that would close most gaps

1. **Name the canonical form next to `input_sha256`,** as agreed for the tool-definition digest; or add an RFC 8785 hash beside it.
2. **Have the gateway record what it executed,** at least the target resource. Have it sign a "not executed" statement when it refuses after an allowed check.
3. **State delegation narrowing:** whether a hop's tools must be a subset of its parent's, and what a hop that names no tools inherits.
4. **Ship one sample authority file and one completeness file with test keys,** so an importer can be tested against the real format rather than the description.

## 5. Next step on AMEP's side

With sample files (item 4), an import profile in `packages/conformance` (`src/profiles/provenza.mjs`) as for AER-1 and protect-mcp:
- one AMEP packet per Proof of Authority file;
- the gaps above reported per action;
- the completeness report carried as the decision-record half of completeness, beside the Observed Effect reconciler.

The two together would let a verifier say three things: these are all of the agent's recorded actions, every write in the scope is accounted for, and each one was within authority.
