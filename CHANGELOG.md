# Changelog

Specification drafts, conformance-suite versions and package versions are listed together. Package versions follow PEP 440 (Python) and SemVer (npm).


## 0.3.2 (2026-11-26)

`amep-protocol` 0.3.2 on PyPI and `@stafordtituss/amep` 0.3.2 on npm, with suite v0.3.4: 297 core vectors (78 positive, 219 must-reject), 16 approval-path vectors and 20 delegation-continuity vectors, 333 in all, plus seven cross-packet sequences. Two fixes, both found by mapping the OWASP Agentic Evidence authorization-to-outcome scenarios (OWASP/Agentic-Evidence#2, #21; research note OWASP/Agentic-Evidence#22):
- **A corroborated receipt is not a self-report (I10).** The actor's own receipt beside an independent receipt of the same effect no longer leaves a high-impact call `unresolved`.
- **Clocks of different operators (I6, spec 5.12.2, #43).** A key may declare `clock_skew`. A revocation and an action from different operators within their combined skew of the deciding boundary are `unresolved`, gap `ordering`.

No existing vector's outcome changes. `keys.json` gains three keys.

## A corroborated receipt is not a self-report (I10), clocks of different operators (I6), and the OWASP Agentic Evidence scenarios (shipped in 0.3.2; 2026-11-26)

- **The gap, found while mapping the OWASP Agentic Evidence authorization-to-outcome scenarios** (OWASP/Agentic-Evidence#2, #21). For a high-impact call, an asserted `tool.result` from the executing side, beside an independent observation of the same write, came out `unresolved` (I10). Each receipt was judged on its own, so adding corroborating evidence weakened the verdict. That contradicts spec 10.2, under which the same effect recorded by several observers is one effect.
- **Now (I10):** a receipt from the actor's side is corroborated when observers independent of the actor recorded the same executed body, ignoring `t`, at least as many times. A self-report of more executions than were independently observed stays `unresolved`.
- **Clocks of different operators (spec 5.12.2, #43),** from the same mapping, its `unordered-revocation` variant. AMEP compared a revocation's time and an effect's time as if one clock had produced both.
  - A key may now declare `clock_skew` (0 to 3600 seconds) in the key set.
  - Where a revocation and an action signed under different operators fall within their combined skew of the boundary that decides the verdict, the result is `unresolved` (I6), gap `ordering`.
  - With no skew declared, nothing changes.
- **Suite v0.3.4:** 6 more core vectors (2 positive, 4 must-reject), 297 in all. No existing vector's outcome changes; `keys.json` gains three keys. The JSON Schemas and CDDL gain `clock_skew`.
- **`interop/owasp-agentic-evidence/`:** each evidence variant of scenarios A1 to A3, B1, B2, C, D1 to D3 and E1, E2 as an AMEP packet, with AMEP's verdict.

## 0.3.1 (2026-11-26)

`amep-protocol` 0.3.1 on PyPI and `@stafordtituss/amep` 0.3.1 on npm, with suite v0.3.3: 291 core vectors (76 positive, 215 must-reject), 16 approval-path vectors and 20 delegation-continuity vectors, 327 in all, plus seven cross-packet sequences. The sections below marked "shipped in 0.3.1" are what it contains. In brief:
- **Three verdicts that said more than their evidence**, from tclancy's review (#34, #35, #36):
  - a host-signed `principal_confirmed` no longer clears a finding by itself; the confirmation is the principal's own signed approval, naming the principal and made with the principal present (`webauthn` or `chat_user`);
  - an effect inside a declared propagation window is `preserved`, and windows are bounded at an hour;
  - an effect whose invocation is missing from the packet is `unresolved`, with no one blamed.
- **Calls whose effects aren't known in advance** (`declared.scope`, spec 5.8.2), found while importing Kilo Code sessions.
- **A seventh cross-packet sequence**, from Andrii Akhtanin's rerun of the 0.3.0 sequences.
- **Two import profiles in `amep-conformance`:**
  - Agent Receipts (#37), whose maintainers reviewed the profile's reading of their receipts in agent-receipts/obsigna#1204;
  - Kilo Code (#38).

**Outcomes that change from 0.3.0** (all from #34 to #36, each listed in the section below):
- `influence-confirmed-by-principal` and `quarantined-content-promoted-by-the-principal` stay `preserved`, but now carry the principal's signed confirmation;
- `bypass--effect-without-invocation` and `audit-only-discovery-of-an-unknown-agent--a6` become `unresolved` (I11);
- `revoked-mid-action--inside-the-declared-propagation-window` becomes `preserved`.

Every other vector keeps its outcome. Producers that relied on `principal_confirmed: true` alone must add the principal's signed approval with `findings` (spec 5.11.1).

## A seventh cross-packet sequence: restoring a violated call's approval use (shipped in 0.3.1; 2026-11-26)

- **From Andrii Akhtanin's rerun of 0.3.0** (OpenID AIIM list, 26 November): all 17 steps of the six sequences passed in both reference verifiers. He asked for the transition none of them showed. Spec 5.10 says a violated call's use of an approval isn't counted against later calls, but if a later packet resolves that violation, the use MUST be counted again.
- **`vectors/sequences/operation-state.json` now has 7 sequences.** In the new one:
  1. `i-1` is `violated` (I2), and its use of `ap-1` isn't counted;
  2. `i-2` then uses `ap-1` and is `preserved`;
  3. `i-1` is presented again without the contradicting receipt, its use comes back into the count, and it is `violated` (I8, "approval already used by i-2").

  Both reference verifiers already behaved this way; this pins it. No code changes.

## Review fixes from tclancy: three verdicts that said more than their evidence (shipped in 0.3.1; 2026-11-26)

tclancy found AMEP through the OpenSSF agenda request (ossf/ai-ml-security#61) and filed three findings the next day. All three are fixed here, each in both reference verifiers, with vectors.

- **#34: a host-signed flag cleared an injection finding.** `principal_confirmed: true` sits on the invocation, which only the host signs. So the host's own word turned an injection-driven write from `violated` into `preserved`, and the same applied to quarantined content.
  - Now (spec 5.11.1) the confirmation is an approval signed by the principal's approver key, naming in `findings` every finding the principal was shown. Like any approval it is bound to the executed effect and used once.
  - The flag alone leaves the call `unresolved` (I4), gap `principal_confirmation`.
  - The two positive vectors now carry the principal's signed approval. Four new must-reject vectors: the flag alone, twice; a confirmation that omits the finding; one signed by a host key.
- **#35: inside a propagation window, `unresolved` when nothing is missing.** The window is part of the grant the issuer signed, so an effect inside it is within the authority as granted. It is now `preserved`, and the reason names the revocation and the window.
  - Windows are bounded at 3600 seconds; a larger one is malformed (`unresolved`, I7).
  - The vector moves from must-reject to positive. Two new vectors cover the bound: one at exactly an hour, one over it.
- **#36: a missing invocation was read as proof of a bypass.** An effect naming an invocation absent from the packet was `violated` (I11), charged to the host. But AMEP doesn't assume a packet is complete (LIMITS.md, section A), so an assembler that dropped the invocation made an honest host look guilty.
  - It is now `unresolved` (I11), gap `invocation`, with no one blamed.
  - An effect despite a deny, or despite a `not_executed` statement, is still `violated`.
  - Two vectors change their expected outcome.
- **tclancy's follow-up on #39, also in this release:** the confirmation must name the chain's root principal as `approver` and have presence `webauthn` or `chat_user`, since `host_ui` and `none` would be the host vouching for itself. Two more must-reject vectors cover it. His other two notes are tracked for later: a structured member for the propagation window, and a completeness record modelled on signed heartbeats with sequence numbers (#41).
- **Suite v0.3.3:** 291 core vectors (76 positive, 215 must-reject), with both reference verifiers, the browser page and the bundled MCP suite in agreement. Five expected outcomes change, as listed. The JSON Schemas and CDDL gain `findings` on approvals.
- **Also fixed:**
  - this changelog named the npm package `amep-protocol`; it's `@stafordtituss/amep`;
  - the 0.3.0 sections still said "proposal, unreleased";
  - LIMITS.md still listed audience as missing, though audience binding shipped in 0.3.0.

## Calls whose effects aren't known in advance, and a Kilo Code demo (shipped in 0.3.1; 2026-11-26)

- **The gap, found while importing Kilo Code sessions (`interop/kilo/`):** every effect of a call had to match the call's declared effect exactly. A shell command can't name its writes in advance. So every write by an allowed `npm install` read as a departure charged to the server, the harmless ones included.
- **Now (spec 5.8.2):** `declared.scope`, `{actions, resources}` in the shape of a grant, lets such a call declare where its effects may land.
  - An effect within the scope, at most the declared class, is judged against the claims like any other. One outside the grant is `violated` (I2), charged to the agent.
  - An effect outside the scope is `violated` (I2), charged to the server, as before.
  - A scope permits nothing the claims don't.
  - It's an AMEP 0.3 member: in an unversioned packet, or when malformed, the result is `unresolved` (I7).
- **Suite v0.3.3:** 6 more core vectors (1 positive, 5 must-reject). The core suite now has 283 (74 positive, 209 must-reject). No existing vector changes. Both reference verifiers and the browser page agree on all 283.
- **Schemas:** `scope` in `declared`, in the JSON Schemas and the CDDL.
- **`packages/conformance/src/profiles/kilo.mjs`** maps a Kilo permission config to AMEP claims and `kilo export` tool parts to invocations:
  - `allow` rules become grants, `deny` rules a deny list, and `ask` grants nothing;
  - where the two differ, AMEP is stricter, and the profile says where.
- **`interop/kilo/`:** a five-call session, constructed in the shape of `kilo export`, with a workspace observer's record.
  - Kilo allowed `npm install`, and its install script rewrote the `Makefile`: `violated`, naming that one write.
  - A denied deploy is `unresolved` until the deployment target signs that nothing arrived.
- **Fix to a stale test:** Provared line 8 has been `violated` (I2) since the admissions rule, matching Provared's own finding.

## 0.3.0 (2026-11-25)

The packages leave alpha: `amep-protocol` 0.3.0 on PyPI and `@stafordtituss/amep` 0.3.0 on npm. With them, Internet-Draft -02 and suite v0.3.2. The sections below, back to 0.3.0a4, are what this release contains. In brief:
- **Operation identity:** a retry under fresh authorization can't take effect unnoticed. Rejected evidence changes nothing.
- **Admissions:** the actor's own record can show a violation, never compliance.
- **Audience binding.**
- **Key status at the time of use.**
- **The suite:** 313 vectors in three suites, plus six cross-packet sequences.

**Outside contributors to this release:**
- Carlos Vendrell Felici (Zealynx Security): twelve vectors of his own (#30), the first by an outside author;
- Andrii Akhtanin (Radiolaria): key status, operation identity, and rejected evidence (#22, #24);
- Brennan Zambo: an independent verifier, and the review of operation identity (#19, #24);
- Takao Sato: the VATE cases, merged upstream;
- the rest are recorded in `vectors/CREDITS.md` and `REVIEWS.md`.
## Audience binding (shipped in 0.3.0; proposed 2026-11-25)

- **The gap, stafordtituss/amep#16 (found with delegation-control-bench, scenario VC-03):** the core claims had no audience. A presentation bound to one service, replayed to another with an action and resource in scope, was `preserved`.
- **Now (spec 5.3):** claims may carry `audiences`, a list of patterns, and a receipt's executed body may carry `audience`.
  - An effect sent to an audience the claims don't name is `violated` (I2).
  - Where the claims name audiences, a receipt without `audience` is `unresolved` (I7), gap `audience`.
  - A delegation can only narrow its parent's audiences (I1), and along a chain they intersect.
  - `audiences` is an AMEP 0.3 member: in an unversioned packet it is malformed (`unresolved`, I7), as for `grants`.
- **Suite v0.3.2:** 5 more core vectors (1 positive, 4 must-reject). The core suite now has 261 vectors (69 positive, 192 must-reject), 297 across the three suites. No existing vector changes.
- **Schemas:** `audiences` in claims, `audience` in the executed body, in the JSON Schemas and the CDDL.



## Admissions: the actor's own record can show a violation (shipped in 0.3.0; proposed 2026-11-25)

- **Found in an analysis of outside traces** (MasDrift, NYU Abu Dhabi; results with the authors before publication): when the only record of an outcome is the agents' own log, a forbidden external send that the log itself records came out `unresolved` (I10), because nobody independent observed it.
- **The rule (I10, spec 8):** a record from the actor, or from a key of the actor's own operator, can't establish that the actor stayed within authority, but it can establish that it didn't.
  - Where it shows the actor executing what it declared, outside its authority, the result is `violated`, charged to the actor, with "on the actor's own record; not independently observed" in the reason.
  - It never convicts another party: a self-record in which the executed effect differs from the declared one, which would charge the server, stays `unresolved`. So does every self-report of an in-scope action.
- **The vectors:** four new ones, two `violated` and two `unresolved`. No existing vector changes.

## Operation identity: a retry can't take effect unnoticed (shipped in 0.3.0; proposed 2026-11-25)

- **The gap, from Andrii's review (Radiolaria) on the OpenID AIIM list:** an attempt whose outcome is unknown, retried under a fresh authorization, started clean. If both attempts took effect, the operation ran twice and no rule was broken. AAuth Budgets has the same gap across auth tokens.
- **Now (spec 5.8.1):** an invocation may carry `operation`, the same identifier on every attempt.
  - An unknown outcome holds the operation, and a later attempt is `unresolved` with gap `held_outcome`, whatever authorization it carries.
  - A second attempt that takes effect after one already did is `violated` (I2), "executed twice".
  - The hold is released when the first attempt is shown not executed. Other operations proceed.
  - Verifier state carries `operations_held` and `operations_done` across packets (spec 10.7).
- **The limit, stated in 5.8.1:** the identifier is chosen by the party that retries, so it binds only what that party records.
- **Suite v0.3.2:** 5 core vectors (3 must-reject, all `preserved` before this change; 2 positive). No existing vector changes. The core suite now has 256 vectors (68 positive, 188 must-reject), 292 across the three suites.
- **Schemas:** `operation` is an optional string of 1 to 256 characters in `invocation.json` and the CDDL.
- **What releases a hold (from Brennan Zambo's review on #24):** only a showing someone other than the actor can check. A high-impact first attempt reported not executed only by the actor's own side stays unknown, and every hold it had stays (operation, approval, period reserve). Before this, such a statement failed I10 for the first attempt but still let a retry through; tests in both packages pin it.
- **The actor is its key, not its name (found by the exhaustive model check in `formal/`).** I10 compared `observed_by` with `actor`, and operators where the key set names them. A host key that also had the `observer` role could sign its own `not_executed` statement, or its own receipt for a high-impact call, under another `observed_by`, and pass: a retry was then released on the actor's own word. A record signed by the invocation's own key is now the actor's, whatever name it gives (spec 5.14 rule 5, 8 I10, 12.5; both cores). No vector changes; tests in both packages fail without the fix.
- **No hold hides a double use (found by the same model check).** Three orderings let an `unresolved` hold mask a violation that verified receipts had already proved, against spec 5.10's rule that checks deciding `violated` come first. First, an approval's single-use check ran after its hold check. Second, a call held on an approval didn't record its use, so a third use was held too. Third, "executed twice" (5.8.1) ran last, after the approval hold. Both cores now check single use and "executed twice" before any hold. No vector changes; the cases need three calls, and the model check (`formal/`) covers them.
- **Rejected evidence changes nothing (rule 5, from Andrii Akhtanin's review on the OpenID AIIM list, 25 November):** an unverifiable `not_executed` statement had released the hold, and an unverifiable receipt had recorded the operation as done. Carried state now changes only on evidence that passed its checks (`settle()` in both cores). Five cross-packet sequences in `vectors/sequences/operation-state.json` check the verdict and the operation state after every step, including Andrii's two sequences and three controls.
- **Status:** shipped in 0.3.0. Brennan Zambo agreed with all five expected answers (#24), and Andrii Akhtanin's review is recorded in REVIEWS.md.

## Twelve payment-limit vectors, written by Carlos Vendrell Felici (shipped in 0.3.0; merged 2026-11-25)

- **The first vectors written by someone outside the project** ([#30](https://github.com/stafordtituss/amep/pull/30)): 4 positive and 8 must-reject, on the readings invited in #10. They cover:
  - a monthly figure that leaves a daily limit unresolved;
  - a second payment service counted against one total;
  - two identical payments in one second, which count twice;
  - on-chain amounts up to uint128, where 40 digits is invalid;
  - an approval of the pre-fee amount, which doesn't bind the debit;
  - limits in the debit currency.
- **Both reference verifiers agree on every one,** and regeneration is byte-identical.
- **He also ran weakened copies of the core** against the suite. Three of four passed every earlier vector and fail only on the new ones, so these vectors close real gaps in what the suite could catch.
- **His question about approvals that name a maximum** is open as [#31](https://github.com/stafordtituss/amep/issues/31).


## Verdict statements can name the admitted artifact as subject (shipped in 0.3.0; 2026-11-24)

- **From Sankalp Gilda's review of in-toto/attestation#625:** when the evaluated actions produced an artifact a policy admits (a commit, a release, a payment), that artifact should be the statement's subject, with the evidence packet as an input.
- **Both statement builders now take optional `subjects`:** `statement(..., subjects=[...])` in Python and `statement(..., { subjects })` in JavaScript. Each subject is an in-toto ResourceDescriptor with a name and a digest of lowercase hex values. The packet stays in the predicate as `packet.sha256`.
- **Without `subjects`, nothing changes:** the packet is the subject, and both verifiers still produce byte-identical statements for all 287 vectors.
- `interop/in-toto/PREDICATE.md` describes the new subject model, and the example statement is regenerated for the current key set.

## AP2: the checkout binding is checked, not just reported (shipped in 0.3.0; 2026-11-24)

- **Finding, from nmatt1's APAF-1 column (AP2 #402):** none of AMEP's SDK fixtures carried `payment.reference`, which AP2's schema requires on every open payment mandate. The omission was in AMEP's generator. AP2's SDK emits the constraint, and its own samples set it to the hash of the user's open checkout mandate.
- **A second SDK fixture family, with checkouts** (`interop/ap2/make_sdk_bundles_v2.py`, `sdk-bundles-v2.json`). It is schema-valid and built with AP2's SDK at `e1ea56d`, following AP2's sample flow. The first family and `verdicts.json` are unchanged (still `93aa9005…`), because others have pinned them; the new family's verdicts are in `interop/ap2/verdicts-checkout.json`.
- **The AP2 profile now verifies the checkout link** that `payment.reference` creates. It checks each checkout chain, and binds each payment to the open checkout it was made under, through `transaction_id` = `checkout_hash`. The AMEP resource carries that checkout. Results:
  - a payment for another checkout than the one the user named is `violated` (I2);
  - a payment whose checkout chain isn't presented is `unresolved`;
  - the eight earlier scenarios give the same verdicts as before.
  
  AP2's own SDK agrees on both new cases. This closes the profile's former gap, "payment.reference binds the checkout mandate, which this profile does not read".

## Two fixes from Andrii's review on the OpenID AIIM list (shipped in 0.3.0; 2026-11-24)

Andrii (Radiolaria) reported both, with reproductions against the published code and vectors, on openid-aiim on 24 November.

- **Both verifiers accepted a revoked key** (spec 12.4). A signed positive vector stayed `preserved` with its issuer or observer key marked `revoked: true`. Only the MCP gateway's key discovery filtered revoked keys; a key set given directly to either verifier was not checked. Key `nbf` and `exp` were not checked either.
  - **Now:** a key whose `revoked` member is present and not `false`, or one used outside its `nbf`–`exp` interval, signs nothing. The result is `unresolved` (I7), with the new signature cause `key_status` (spec 10.5.1), checked after `role` and before `invalid`.
  - **How an object is placed in the interval:** by its own time, `t` or `executed.t`. The interval includes `nbf` and excludes `exp`. An object with no time of its own is checked for revocation only, and spec 12.4 now says so.
  - **Suite v0.3.1:** 5 new core vectors, and three keys added to `vectors/keys.json` (`issuer-revoked`, `observer-revoked`, `observer-windowed`). Four of the vectors are must-reject; all four returned `preserved` before the fix. No existing vector changes. The core suite now has 251 vectors (66 positive, 185 must-reject), 287 across the three suites. The key set's digest changes.
- **The experimental TypeScript MCP producer could sign a false `not_executed`.** A handler that changed the backend and then threw before `recordEffect` was signed `not_executed`, which verifies as `preserved` and releases holds (spec 5.10, 7.6).
  - **Now:** "no effect recorded" becomes `not_executed` only when the handler returned normally, or refused before acting by throwing the new `NotExecuted`. Any other exception with nothing recorded leaves the outcome unknown: no statement is signed, and the call is `unresolved`. The receipt store records the unknown outcome.
  - **Tests:** his four controls are `prototypes/mcp-amep-evidence-ts/test/failure-window.test.mjs`, and the README's integration example says which statement each failure gets.
- **JS core, as on the protect-mcp branch:** the I10 result for a host-only deny names its gap, `independent_observer`, as the Python core does. `tools/compare_verifiers.py` now agrees on all 287 vectors.

## An independent implementation, and four clarifications from it (shipped in 0.3.0; 2026-11-24)

- **zambo-amep-verify 0.1.0,** by Brennan Zambo, was written from the specification and the published vectors alone, without reading either reference verifier. It agrees with all 228 single-packet vectors of the core suite: the deciding invariant as well as the outcome, for every positive and must-reject vector (stafordtituss/amep#18). Cross-packet state (Section 10.7) and the interop suites are its next rows. Recorded in spec 15.2 and LIMITS.md.
- **What his reading found unclear,** now stated in the text (no verdict changes; every vector is unchanged):
  - **Section 7.3:** the order in which the meet is folded along a chain. The narrower set is C₁ at each step.
  - **Section 7.6, rule 5:** when a window's total is known. Verifier state or a counting observer's own figure anchors it, later effects add to it, and in-packet effects alone never anchor it.
  - **Section 10.2:** where call statements (Section 5.14) and limits run. New steps 9a (statement rules 1 to 5), 14a (rule 6, receipt counts) and 15a (limits).
  - **Section 10.2, step 13:** laid out so the `mediated` comparison is plainly the only one when `mediated` is present.

## Observer independence by operator, not only by name (shipped in 0.3.0; 2026-11-24)

- **The gap,** listed in LIMITS.md: for high-impact effects, I10 requires an observer other than the actor, but AMEP compared identifiers only. A host could sign the invocation with one key and the receipt with another, under a different name, and I10 was met.
- **Now (spec 12.5, I10, 5.14 rule 5):** a key may carry `operator`, the organisation that controls it. When the key that signed an effect receipt or a `not_executed` statement and the key that signed the invocation both name the same operator, I10 is not met: `unresolved`, need `independent_observer`. A key set that names no operators behaves as before.
- **Schema:** `operator` is an optional string in `schemas/v0.2/keyset.json`.
- **Three new core vectors** (one positive, two must-reject), with keys `host-2`, `observer-2` (same operator) and `observer-3` (another operator) added to `vectors/keys.json`:
  - `high-impact-effect-observed-only-by-a-key-of-the-host-s-own-operator` (`unresolved`, I10);
  - `high-impact-call-reported-not-executed-only-by-a-key-of-the-host-s-own-operator` (`unresolved`, I10);
  - `high-impact-effect-observed-by-a-key-of-another-operator` (`preserved`).

  Under the previous rule both must-reject vectors were `preserved`.
- **The core suite now has 246 vectors, 282 across the three suites.** No existing vector changes its verdict. The key set's digest changes, because it gains three keys.

## Packages amep-protocol 0.3.0a4, @stafordtituss/amep 0.3.0-alpha.4, amep-mcp 0.1.0a5 (2026-11-24)

They carry the change below that was marked unreleased: **a host's own enforcement claim never settles a deny**, from issue #15.

**One verdict changes from 0.3.0a3:** a pre-execution deny with `fail_mode: closed` or `applied: confirmed` and no other record is now `unresolved`, where it was `preserved`. Deployments that relied on it should have the enforcement point or gateway issue `not_executed` call statements (spec 5.14).

amep-mcp 0.1.0a5 bundles the 243-vector core suite and needs amep-protocol 0.3.0a4.

The AP2 entries below sit in the repository (`interop/ap2/`) and in the conformance tool, which isn't published.

## A host's own enforcement claim never settles a deny (2026-11-24)

- **The question,** from issue #15. A pre-execution deny whose `enforcement` says `fail_mode: closed` or `applied: confirmed` used to make the call `preserved` ("denied; no effect") with no other record. The host that signs the deny declares both fields, so that was self-reported evidence for "nothing executed".
  - Raised with delegation-control-bench, where 12 denied scenarios with only a decision log came out 12/12 `preserved` under AMEP and 0/12 under the bench's reference verifier.
  - Brennan Zambo (AER-1) answered: a host's own declaration can't settle it. He proposed the independent route, with a floor for `read` and `write_local` "while that lands".
- **Now (spec 10.3), for every effect class:**
  - the host's declaration never settles "denied; no effect". A `not_executed` call statement from an observer does (Section 5.14, rule 5; for `write_shared` and above the observer must not be the actor, I10);
  - without such a statement, the result stays `unresolved`: I7 for `read` and `write_local`, and I10, need `independent_observer`, for `write_shared` and above;
  - a deny never replaces a `violated` result.
- **Why not "require `applied: confirmed`":** that field is signed by the same host as `fail_mode`, so requiring it alone would close nothing.
- **The floor came off in the same release.** A first version kept the host's word for `read` and `write_local`. Rerunning delegation-control-bench against it showed two things:
  - the floor left 10 of the 12 denied reads `preserved` on the host's word;
  - it also replaced *any* result, including `violated` (I1 or I6) for an invocation under widened or revoked authority, so the same denied read was `violated` with the fail mode unknown and `preserved` with it declared closed.

  With the independent route in place, the floor went.
- **Vectors:**
  - `deny-honoured-on-fail-closed-host--no-effect` now carries the observer's `not_executed` statement and stays `preserved`. Without it, the same packet is the new `deny-on-a-fail-closed-host-with-no-other-record` (`unresolved`, I7). This is the one existing vector whose packet changed.
  - New: `high-impact-deny-on-a-fail-closed-host--no-independent-record` (`unresolved`, I10); `high-impact-deny-on-a-fail-closed-host--reported-not-executed-by-an-independent-observer` (`preserved`); `deny-on-a-fail-closed-host-contradicted-by-an-observed-effect` (`violated`, I11), the test Brennan suggested; `deny-on-a-fail-closed-host-does-not-clear-an-invocation-under-revoked-authority` (`violated`, I6; `preserved` under the old rule).
- **The core suite now has 243 vectors, 279 across the three suites.** Both reference verifiers agree on all 279, and a verifier that answers "preserved" to everything scores 73/279.

## AP2: one consent redeemed twice is caught afterwards (repository only, 2026-11-24)

- **Each closed payment mandate becomes an AMEP intent** limited to its own payee and amount per call. The same closed mandate presented and processed twice (AP2 #346, which the SDK's verifier accepts) is `violated` (I2), even when the total stays within every limit of the open mandate.
- **New scenarios:** `s10`, `s11` and an SDK-produced `sdk-redeemed-twice`.
- **The README** gains "Where AMEP goes further than AP2", row by row with its evidence.
- **`interop/ap2/verdicts.json`** is AMEP's pinned column for the AER-1 crosswalk on AP2 #402.

## AP2 payments, evaluated afterwards (repository only, 2026-11-23)

- `packages/conformance/src/profiles/ap2.mjs` reads Google's Agent Payments Protocol (AP2) artifacts and checks them by AP2's own rules: ES256 signatures, SD-JWT disclosures, the closed mandate's `sd_hash`, and receipt references. It builds AMEP evidence from them: the open mandate becomes the authority, each closed mandate an invocation with its amount as `reserve`, and each signed receipt an effect or a `not_executed` statement.
- `interop/ap2/` evaluates nine scenarios payment by payment, next to AP2's own per-payment check. AMEP decides two things AP2 leaves open:
  - two payments within `amount_range` that together exceed the budget are `violated`;
  - a second payment while the first one's outcome is unknown is `unresolved`, not `preserved`.
- **Checked against AP2's own Python SDK** (`e1ea56d`). Seven bundles produced by the SDK pass AP2's checks as the profile implements them, and give the expected AMEP verdicts. Nine further synthetic scenarios cover cases the SDK can't produce.
- **Four findings for AP2** (in `interop/ap2/README.md`):
  - the specification and SDK compute the receipt `reference` differently;
  - the budget arithmetic `int(max * 100)` loses a cent to floating point and assumes two decimals;
  - a budget depends on past spend the caller supplies;
  - open mandates may omit `exp`.
- Unmapped constraints are reported as gaps.

## Packages amep-protocol 0.3.0a3, @stafordtituss/amep 0.3.0-alpha.3, amep-mcp 0.1.0a4 (2026-11-23)

They carry the three changes below that were marked unreleased:
- **held approvals**, from VATE case 2;
- **signature gaps say why**, from the W3C AIKR case library;
- **a call that provably didn't run says so**, in its reason text.

amep-mcp 0.1.0a4 bundles the 238-vector core suite and needs amep-protocol 0.3.0a3. Outcomes on every earlier vector are unchanged.

## Held approvals (2026-11-23)

- **An approval cited by a call whose outcome is unknown is held** (spec 5.10, held approvals). That's a call that has neither receipts nor a `not_executed` statement.
  - **While the approval is held,** another call under it is `unresolved` (I7), with gap `held_outcome` naming the first call, instead of `preserved`.
  - **A later packet decides the first call afresh:**
    - receipts make a second use `violated` (I8), as before;
    - a `not_executed` statement releases the approval.
  - **Holds carry across packets** in verifier state, as `approvals_held`.
  - **Checks that decide `violated` still come first,** so a hold never hides a violation.
- **The gap it closes.** Found while writing Takao Sato's VATE case 2 (accepted work interrupted, openid/authzen#795) as AMEP evidence. A second runtime re-ran an interrupted operation under the same single-use admission, and the re-run came out `preserved` while the first outcome was unknown. Released 0.3.0a2 still gives `preserved` on the new vector `approval-held-for-an-earlier-call-with-an-unknown-outcome`. It's the approval counterpart of held limits (spec 7.6, rule 6).
- **Five new core vectors** (one positive, four must-reject):
  - the core suite now has 238 vectors, 274 across the three suites;
  - no existing vector changes its verdict;
  - both verifiers produce byte-identical statements on all 274.

## Signature gaps say why (2026-11-23)

- A gap for a refused signature (`signature`, `receipt_signature`, `call_statement_signature`, `revocation_signature`) now carries `cause`:
  - `missing`: no proof;
  - `unknown_key`: the key id isn't in the key set;
  - `role`: the key can't sign that kind of object;
  - `invalid`: anything else.

  Both verifiers determine it in the same fixed order (spec 10.5.1). Before, an attacker's key, a host key minting a mandate and a tampered body all gave the same gap. Outcomes and invariants are unchanged. Verdict statements gain the member on those gaps, and both verifiers still produce byte-identical statements over all 269 vectors.
- Found while filling in AMEP's row for UC-03 of the W3C AIKR case library (w3c-cg/aikr#45).
- Vectors record only the outcome and the deciding invariant, so the causes are pinned by tests in both packages (`SignatureCause`, and "a signature gap says why"), and `tools/compare_verifiers.py` checks that the two verifiers agree on every gap.

## AER-1 regression check (2026-11-23)

- `interop/aer1-fixtures/regress.mjs` reruns Brennan Zambo's two AER-1 fixtures, pinned by hash, against the expectations committed in `5f59f88` before either side ran them. Above all, a gateway refusal must never be imported as an executed action. Asked for in amep#17.

## Internet-Draft -01 posted (2026-11-23)

- **draft-stafordtituss-agentic-mandate-evidence-01** is posted to the IETF repository (https://datatracker.ietf.org/doc/draft-stafordtituss-agentic-mandate-evidence/), rewritten from v0.3.0-draft.1. It adds:
  - grants and limits;
  - call statements and binding;
  - liveness at each effect's time;
  - operation approvals;
  - blame and missing evidence;
  - holds;
  - signed, re-derivable verdict records;
  - the exact Ed25519 acceptance rule;
  - the 269 vectors.

  Its Implementation Status lists the outside use and review: the AER-1 runs, the VATE verification, the payments review and the AUDIT list review. The XML is xml2rfc v3.
- The README's citation entry now names -01 and the draft's actual title, "Continuity Evaluation of Agent Delegation Records".

## Reasons: a call that provably didn't run says so (2026-11-23)

- A call whose observer signed a `not_executed` statement was `preserved` with the generic reason "continuity preserved", which reads as "within authority". It now says "nothing executed: <observer> signed a not_executed call statement", in both verifiers. Outcomes are unchanged; only that reason text differs.
- Found while building an audit exercise, in which a reviewer reading the verifier's result for a refused call could have taken it for an approved one.

## Packages amep-protocol 0.3.0a2, @stafordtituss/amep 0.3.0-alpha.2, amep-mcp 0.1.0a3 (released 2026-11-23)

They carry every change below, down to "Operation approvals", in both reference verifiers. In order, newest first:
- limits that are order-independent, and observer totals that name their window (amep#10 rerun);
- holds for unknown outcomes (FINOS AIGF #421);
- the FINOS #421 worked example;
- the EMILIA Protocol and Delegation Receipt Protocol comparisons;
- grants;
- the coverage matrix and the Provared import;
- operation approvals.

amep-mcp 0.1.0a3 bundles the 233-vector suite and needs amep-protocol 0.3.0a2.

## Limits: order-independent, and observer totals name their window (2026-11-23)

From Carlos Vendrell Felici's rerun of his payments review against this draft (stafordtituss/amep#10, 23 Nov 2026). He found three problems.

- **Order (spec 7.6).** With a daily and a monthly limit, and a bank figure for the month only, the verdict depended on which limit was listed first: `unresolved` (I7) one way, `violated` (I2) the other. Both verifiers now check every applicable limit before deciding, and a violation beats an unresolved check, as across results (10.5).
- **Windows (spec 5.9.2, 7.6 rule 4).** `period_spent` named a period length but not a window. A bank reporting its own month, which started on day 20, was taken as the limit's total for a window starting at day 0:
  - with no state, a payment was `preserved` at 300.00 of 500.00 although the window also held 400.00 (a false `preserved`);
  - with that 400.00 in state, the honest bank was blamed (`violated` I7).

  Each figure is now `{from, total}`, and counts only when `from` is the start of the limit's window. A bare figure names no window and never counts, so it fails closed: the packet is decided from verifier state or is `unresolved`. The generated vectors now state their window, so they keep their verdicts.
- **caip19 reason.** A decimal amount in a `caip19:` unit now gets the reason that asks for an integer in the asset's smallest unit. The outcome is unchanged.
- **Five new vectors:**
  - the order case, both ways round (both `violated` I2);
  - a bare figure, and a figure for another window (both `unresolved`);
  - the honest-bank case (now `violated` I2, blame `agent`, at 700.00).

  Suite v0.3.0 is 233 vectors (62 positive, 171 must-reject); both verifiers agree on all 269 of the three suites. JSON Schema and CDDL require `{from, total}`.
- **Private vulnerability reporting** is now enabled on the repository, for the operation-approval findings he holds back for a private advisory.

## Holds: an unknown outcome stays counted across packets (2026-11-23)

- **Spec 7.6 rule 6, 5.8 and 10.7:** an invocation may carry `reserve` (`{amount, unit}`), the most the call can move. When a verified invocation ends a packet with no receipt and no `not_executed` statement, the verifier's state holds it against every period limit on its chain: at its `reserve`, or at an unknown amount without one. In later packets:
  - a period total that could exceed its limit with the holds added is `unresolved` (I7), gap `held_outcome`;
  - an unknown held amount is also `unresolved`;
  - it is never `violated`, because the held call may not have executed.

  A later packet that contains the held invocation replaces its hold: its receipts count like any others, a `not_executed` statement releases it, and a hold is never counted twice.
- **The gap it closes:** a lost instruction in one packet left no trace in verifier state, so a later packet holding only the retry was `preserved` though the principal could be over the limit. Found while building the FINOS AIGF #421 example below, whose thread set the rule: "a slice with an unknown outcome stays counted until reconciliation shows it was booked or not booked".
- **Compatible:**
  - every earlier vector and every `verify` output is unchanged;
  - a packet evaluated with state that has no `held` member is decided as before;
  - a well-formed `reserve` changes no packet's own verdict;
  - a verifier without the rule ignores `reserve`.

  Both verifiers write identical state, and the package tests check it against the example's committed state.
- An approval that passed I8 authorizes its effect to go over the limit, so holds don't block it (a vector covers it).
- Suite v0.3.0 is now 228 vectors (62 positive, 166 must-reject), 7 of them new; both verifiers agree on all 264 vectors of the three suites. JSON Schema and CDDL gain `reserve`.

## Worked example for FINOS AIGF #421 (repository only, 2026-11-23)

- **`interop/finos-aigf/case-421-family-office/`:** the family-office example of finos/ai-governance-framework#421 as seven signed packets. A client's USD 10M mandate is split across two banks; each bank signs what it booked and counts its own leg, and the client's verifier holds the total. The phases:
  - a plan within the mandate (`preserved`);
  - slices that each fit but together over-book (`violated` I2);
  - a leg delegated to an institution the client never named (`violated` I1, blame `delegator`);
  - a lost response, before and after a retry (`unresolved` I7);
  - reconciliation either way: the first instruction booked (`violated` I2, 14M) or never booked (`preserved`).

  Both reference verifiers agree on every phase, and the generator asserts each verdict. The FINOS mapping links it.
- **A gap it found, now closed by holds (above):** across packets, verifier state didn't carry an instruction with an unknown outcome forward. Phases 8 and 9 now show the lost instruction held in a later batch, and then released by the bank's statement.

## Comparison with EMILIA Protocol's vectors (shipped in 0.3.0; 2026-11-23)

- **EP profile** (`packages/conformance/src/profiles/ep.mjs`) and **`interop/ep/`:** AMEP beside two of EP's published suites (draft-schrock-ep-authorization-receipts).
  - **`receipts.v1`:** EP-RECEIPT-v1, checked by a clean-room reading of EP's rules (written from the vectors and EP's documentation, not its code). It agrees with EP's expected result on all 14 vectors.
  - **`outcome-binding.v1`, predicate vectors:** EP's `in_bounds` / `divergent` / `incomparable` beside AMEP's `preserved` / `violated` / `unresolved`. AMEP can express 7 of the 24 exactly and agrees on 6. The difference is by design: EP's predictions bound only the effect types they name, while AMEP's claims are an allowlist.
- **Findings, in the README:**
  - EP's Merkle branch hash runs over the children's hex text, not their raw bytes, which EP's design notes don't make clear;
  - the vectors can't distinguish position order from sorted order, and have no v2 tampered-root case;
  - EP's predicates (exact values, sets, minimums, counts) are richer than AMEP's claims. Count limits are now needed by two outside formats.
- The vectors are vendored, unchanged and with their licence, as test fixtures (Apache-2.0); their digests match EP's manifest.

## Comparison with the Delegation Receipt Protocol's vectors (shipped in 0.3.0; 2026-11-22)

- **DRP profile** (`packages/conformance/src/profiles/drp.mjs`) and **`interop/drp/`:** AMEP beside the 14 published vectors of DRP's reference SDK (draft-nelson-agent-delegation-receipts). Each receipt is checked by DRP's own rule first (signature, receipt id, orchestrator binding); only `invalid-signature` fails, as intended. AMEP then answers the matching question, had the action run as proposed, with the scope the DRP verifier was given adopted as authority and labelled as such. Of the 8 vectors that can be compared, AMEP agrees on 6. The remaining 2 are DRP's single-use receipts, which AMEP doesn't have. The 6 that can't be compared state authority only in natural language, or decide by the verifier's chain-depth limit.
- **Findings, in the README:**
  - the root authority in every comparable vector is supplied by the verifier, not signed by the user;
  - the vectors use the pre-11 signing rule that draft -15 deprecates, and there are no vectors for its JWS or COSE profiles;
  - their signatures are raw P1363, not the DER the draft describes for that rule;
  - sub-receipts use `orchestratorSignature`, which -15 deprecates.
- DRP's scopes allow (operation, resource) pairs, which is what led to grants (above). The profile expresses them exactly, and a test shows an action inside the product of the pairs, but outside every pair, is `violated`.
- **`interop/COVERAGE.md`** has a DRP column.
- The vectors are vendored, unchanged and with their licence, as test fixtures (MIT).

## Grants: authority as a union of products (shipped in 0.3.0; 2026-11-22)

- **Spec 5.3:** a claim set may carry `grants`, a list of `{actions, resources}`, instead of `actions` and `resources`. Each grant permits its actions on its resources, and the authority is their union. One product (`actions` × `resources`) can't express "read the documents, write the reports" without also permitting "write the documents"; grants can. Plain claims count as one grant, so the two forms mix along a chain:
  - an effect satisfies the claims when one grant permits both its action and its resource (I2);
  - a delegation is narrower when each of its grants lies within one parent grant (I1), which never accepts a widening.
- **Additive:** claims with `actions` and `resources` are evaluated exactly as before (every earlier vector and `verify` output is unchanged). In an AMEP 0.3 packet, a verifier without the rule returns `unresolved` (unknown claim member), never `preserved`. An unversioned packet that uses `grants` is `unresolved` (I7) rather than ignored, because ignoring a narrowing member could widen authority.
- Raised by comparing AMEP with the Delegation Receipt Protocol, whose scopes allow (operation, resource) pairs.
- Suite v0.3.0 is now 221 vectors (59 positive, 162 must-reject), 7 of them new. Both verifiers agree on all 257 vectors of the three suites; JSON Schema and CDDL are updated.

## Coverage matrix (shipped in 0.3.0; 2026-11-22)

- **AER-1 profile, binding gap wording:** the report now says what `input_hash_layout` means. Under `rfc8785-jcs-utf8-v1`, `input_hash` *is* AMEP's `args_digest`. Under another layout, it equals `args_digest` only for arguments that serialize identically under both. The report also says whether a binding was made. This is wording only; binding stays by digest. It was noted before the blind fixture run in amep#11 and fixed after it, so the run used the code the expectations were written against.

- **`interop/COVERAGE.md`:** for each format AMEP can import (AER-1, OpenID DA action receipts, Provared) and for AMEP's own evidence, which parts of the question (I1 to I11, binding to the call, confirmed non-execution) the format's records can settle. Each cell is based on the import profile's code, its gap report and its tests. The format authors are invited to correct their rows.

## Provared import; comparison with the Provared checker (shipped in 0.3.0; 2026-11-22)

- **`amep-conformance import-book`**, with a profile for Provared books (draft-izmaylov-agent-permission-receipts). Every record is checked by the format's own rules first: the envelope, labels, canonical form, both hybrid signatures (Ed25519 and ML-DSA-87), the passkey (WebAuthn) signatures, fingerprints, the chain, and countersignature and approval binding. The verified records are then re-expressed as AMEP evidence (slip → mandate, stubs → invocations, countersigned stubs → service-observed effects at L1, one-sided stubs → the agent's own report at L0, approvals → approvals). Limits AMEP can't express exactly are reported as gaps.
- **`interop/provared/`:** AMEP's verdicts on the format's own sample book beside the Provared checker's expected findings, generated by `compare.mjs`. They agree on 3 of the 6 actions, and both flag a fourth. AMEP is stricter on one (a message recorded only by the agent). The sixth is an AMEP gap: a deletion outside the permission, recorded only by the agent, is `unresolved` in AMEP, not `violated`. That and three other open questions are in the README.
- The sample book is vendored, unchanged and with its notice, as a test fixture (Apache-2.0).

## Operation approvals (shipped in 0.3.0; 2026-11-22)

- **Spec 5.10:** an approval may carry `effect_digests`, a non-empty list of effect digests, instead of `effect_digest`. It approves the effects of one call. Every executed effect of that invocation must be listed, and no body may run more often than it is listed; otherwise the result is `violated` (I8). An approved effect that didn't run is not a violation. It's single use like any approval, so a retry that cites it is `violated` (I8). An approval with both members, or with an empty or malformed list, is `unresolved` (I7).
- **Additive:** approvals with `effect_digest` are evaluated exactly as before (every earlier vector and `verify` output is unchanged), and a verifier without this rule never returns `preserved` for one.
- **Fix (both verifiers):** an approval with no digest at all was `unresolved` in Python but `violated` (I8) in JavaScript; the spec makes it malformed, and both now return `unresolved` (I7). No earlier vector covered it, so the differential check couldn't see the disagreement. Found while testing how earlier verifiers treat operation approvals; there's now a vector for it.
- Motivated by Takao Sato's VATE reference case 1 for openid/authzen#795: a single admission covering an operation that writes two files had no AMEP equivalent. `interop/authzen-receipts/vate-01-lost-response` adds the admission, and the retry is now `violated` (I8).
- Suite v0.3.0 is now 214 vectors (57 positive, 157 must-reject), 10 of them new; both verifiers agree on all 250 vectors of the three suites. JSON Schema (with `oneOf`, now in the built-in validator too) and CDDL updated.

## AER-1 refusal records; VATE case 1 (shipped in 0.3.0; 2026-11-22)

- **Fix (`amep-conformance import`, AER-1 profile):** a record of a call a gateway refused imported as an executed effect, although its committed output says `"executed": false`. Such records now produce no effect; the call stays `unresolved`, since an unsigned record can't confirm non-execution either. Only content inside the record's output commitment counts. Found by Brennan Zambo running the import over 12 live Zambo receipts ([amep#11](https://github.com/stafordtituss/amep/issues/11)); the same records now give 8 imported and 4 not.
- The AER-1 profile cites draft-zambo-aer1-26, and the conformance README gives the install step beside the import example (both from the same report).
- **`interop/authzen-receipts/vate-01-lost-response`:** Takao Sato's VATE case 1 for openid/authzen#795 (a lost response, then recovery) as AMEP evidence. Three signed packets and the caller's signed verdict for each phase; both verifiers agree on all three.

## amep-mcp on the v0.3 suites (shipped in 0.3.0; 2026-11-22)

- **Fix:** amep-mcp still bundled conformance suite v0.2.3, so its own `check_suite` disagreed with the v0.3 verifier on `status-current-as-of-the-action`, the one vector v0.3 deliberately changed. The bundle is now suite v0.3.0 (204 vectors), the delegation suite (20) and the approval-path attacks (16, draft), including the vectors that exist only as exact JSON text.
- **Fix (security):** an MCP client's JSON text was parsed loosely before the verifier saw it, so a packet with a duplicated member name, which v0.3 makes `unresolved`, could come back `preserved`. The MCP SDK parses any JSON-looking string argument into an object unless the parameter is typed as a plain string. `verify_packet` now takes `packet_text`, which is parsed strictly; `packet` still takes an object; every result reports `parsed_strictly`.
- Results carry `blame` and `gaps` (spec 10.5.1).
- Spec Section 15 states suite v0.3.0 (204 vectors) instead of v0.2.3.
- **Release order:** the next amep-mcp release needs `blame` and `gaps`, which are newer than amep-protocol 0.3.0a1. Release amep-protocol first, then amep-mcp with its dependency raised to that version.

## Blame and evidence gaps (shipped in 0.3.0; 2026-11-22)

- **Spec 10.5.1:** every result now carries `blame` and `gaps`. On a `violated` result, `blame` names the party whose own signed record first departs from authority: `agent`, `delegator`, `host`, `transport` or `server`. On an `unresolved` result, `gaps` names the evidence that would let the evaluation continue (`{need, ref}`, from a fixed set of values). Both are derived from the signed evidence only.
- **`tools/compare_verifiers.py`:** a differential check that both reference verifiers return the same outcome, invariant, blame and gaps for every result of every vector, not only the same verdict. It agrees on all 258 results of the 240 vectors in the three suites.
- **Spec 10.8, verdict records:** a verifier can publish what it concluded as an in-toto Statement v1 (predicate type `https://github.com/stafordtituss/amep/verdict/v0.3`), naming the SHA-256 of the exact packet bytes and of the key set, and the outcome, invariant, blame and gaps of the packet and of every result. Apart from the optional `verifier` member, two conforming verifiers produce byte-identical records, so anyone holding the packet can check a record by re-running a verifier. Records are signed in DSSE envelopes under the strict Ed25519 rule (12.2).
  - Python `amep_protocol.verdicts` and JavaScript `@stafordtituss/amep/verdict`: `statement`, `sign_envelope`/`signEnvelope`, `verify_envelope`/`verifyEnvelope`.
  - Both CLIs: `verify --verdict-out FILE` writes the statement; with `--sign-with KEY --sign-kid KID` it writes a signed envelope.
  - `tools/compare_verifiers.py` now also checks byte-identical statements (240/240 vectors); `tools/verdict_roundtrip.py` signs with each CLI and checks each envelope with the other language.
  - `interop/in-toto/PREDICATE.md`: the predicate written up for a proposal to in-toto/attestation, with a generated example.
  - The same verdict as an in-toto Simple Verification Result (SVR v0.2), for policy engines that read SVRs: property `AMEP_VERDICT_PRESERVED` when the packet is preserved, none otherwise; policies are the key set and the AMEP version. `svr_statement`/`svrStatement`, and `verify --svr-out FILE [--verifier-id URI]` in both CLIs. `tools/compare_verifiers.py` checks byte-identical SVRs (fixed verifier id and time) over all 240 vectors.
- **`amep-conformance import`:** a profile for OpenID DA execution layer action receipts (`oidf-action-receipt`), with the execution layer's §9.1 travel-agent scenario as tests.

## Payment-limit fixes from review amep#10 (packages 0.3.0a1 / 0.3.0-alpha.1, 2026-11-22)

Found by Carlos Vendrell Felici (Zealynx Security) in an independent review of the v0.3 limits, stafordtituss/amep#10, with signed packets checked against both reference verifiers. All fixed in both verifiers; suite now 204 vectors.

- **Fix (security):** identical effect bodies were always merged, so one approval for an 840000.00 EUR payment covered the same payment executed twice in one call (`preserved`), and two 300.00 payments in one call counted as one against a 500.00 cap. Receipts are now counted per observer: the same effect seen by several observers counts once, two receipts from one observer are two effects, and an approval used for two effects is `violated` (I8).
- `per_call` now caps the total of one call; the new `per_effect` caps one effect.
- `value.period_spent` is keyed by period length (`{"86400": …, "2592000": …}`), and counts only for a limit that names its observer in `counted_by`; another observer's total is only its share.
- Each limit keeps its own running total, so limits differing only in `actions` no longer double-count.
- `caip19:` amounts are integers in the asset's smallest unit.
- Approval and effect identity digests exclude `value.period_spent` as well as `t`: an approval signed before execution can't know the observer's running total (found while fixing the above).
- Receipts must name their observer (`unresolved` otherwise), so both verifiers group them identically.

## Conformance tool and verify-by-hand recipe (packages 0.3.0a1 / 0.3.0-alpha.1, 2026-11-22)

- **`amep-conformance`** (`packages/conformance`, experimental): `verify` runs the core suite and the two interop suites (225 vectors) through any verifier given as a command template, in any language, and writes a JSON result with each suite's SHA-256 and a Markdown summary for an implementation report. Both reference verifiers agree on 225/225; a verifier that accepts everything scores 59/225. `import` is a profile-based adapter from other execution-record formats to AMEP effects, with a gap report of what AMEP needs that the format does not carry; the first profile is AER-1 (draft-zambo-aer1), with that format's own integrity checks. It never invents a mapping, refuses records that fail their own checks, and caps unsigned records at assurance L1.
- **Verifying by hand** (`spec/verify-by-hand.md`, `tools/verify_by_hand.sh`): check one signed object with jq, xxd, shasum and OpenSSL 3 only: well-formedness, signing input, key and signature encoding (including small-order keys and S ≥ L), role, signature and `invocation_digest`. Agrees with the reference verifier on 971 of the suite's 972 signed objects; the exception is the vector built to catch non-RFC 8785 canonicalizers, which fails to verify rather than verifying falsely.

## v0.3.0-draft.1 and conformance suite v0.3.0 (packages 0.3.0a1 / 0.3.0-alpha.1, 2026-11-22)

Every v0.2 vector keeps its verdict except `status-current-as-of-the-action` (see "Liveness at effect time"). Packets without `amep_version`, or with `"0.2"`, keep v0.2 handling of unknown claim members and version-1 proofs. 189 vectors (50 positive, 139 must-reject); both reference verifiers, the browser verifier and both packaged command-line tools agree on all of them, and mutation analysis (`paper/eval/mutation.py --check`) finds no surviving mutant that is not a documented equivalent.

- **Fix (Python reference verifier), spec 12.2:** with OpenSSL 3.6 (`cryptography` 48), the Python verifier accepted the signature (R = identity, S = 0) for every message under the identity public key; the JavaScript verifier, on OpenSSL 4.1, rejected it, so the two disagreed. Both now apply one exact Ed25519 acceptance rule before the library check: S < L, canonical and non-small-order A and R, and exactly 64/128 lowercase hex digits for keys and signatures. Found while preparing v0.3. Vectors: small-order keys, S ≥ L.
- **Fix (both reference verifiers), spec 12.1:** duplicate member names were silently resolved last-wins by `parse_strict`/`parseStrict`. They now make the packet malformed. So do lone surrogates, noncharacters, identifiers that are not NFC or contain control characters, and inputs beyond fixed bounds (depth 32, 4096 array elements, 8192-byte strings). Conformance vectors that must be given as JSON text use the new `packet_text` member; `evaluate_text` / `evaluateText` parse strictly and return `unresolved`/I7 instead of raising.
- **Liveness at effect time, spec 5.12 and I6:** revocation and status freshness are evaluated at the invocation and at each effect's time, so `preserved` establishes that authority was still in force when each effect occurred. Raised by Cliff Singletary on audit@ietf.org (19 November 2026); his three cases are vectors. New: `revocation.window`, a signed propagation window inside which a mid-action revocation is `unresolved` (I6) rather than `violated` (spec 5.12.1, Appendix E.2).
- **Quantities and limits, spec 5.9.2 and 7.6:** `value: {amount, unit, period_spent?}` on executed bodies, with amounts as exact decimal strings, and `limits` on claims (per call, per period, per unit, optionally per action pattern), attenuated under I1. A payments review of the MCP evidence-extension proposal (vendrell46, modelcontextprotocol/agents-ig#31, 21 November 2026) showed that without an approval nothing bounded an amount: a payment of 840000.00 EUR came out `preserved`. It is now `violated` (I2) under a per-call limit. Limits also cap non-monetary quantities, such as records read.
- **Version-2 proofs, spec 12.2:** domain-separated signing input `"AMEP-v0.3" 0x00 kind 0x00 canon(o′)`, required in packets that declare `"amep_version": "0.3"`. Version-1 proofs verify as before.
- **Versioning, spec 16:** unsupported `amep_version` values are malformed; in AMEP 0.3 packets, a claim or limit member the verifier does not understand makes the result `unresolved` instead of being ignored.
- Schemas (JSON Schema and CDDL) gain `value`, `limits`, `revocation.window` and `proof.v`. The built-in schema validator supports `dependentRequired` and `minProperties`. The CDDL was not re-validated with the `cddl` tool in this change.
- Spec 7.1: the risk-budget rule was numbered 8 twice; it is now rule 9, and rule 10 covers limits.
- **Call statements, spec 5.14:** the observer's signed account of one call (`completed`, `not_executed` or `failed_after_effects`, with `effect_count`), so that "no receipt" is no longer ambiguous: a no-op is provably `preserved`, a promised receipt that is missing is `unresolved`, and a receipt contradicting `not_executed` is `violated` (I11). Raised by Brennan Zambo in the review of modelcontextprotocol/agents-ig#31 (21 November 2026).
- **Binding, spec 5.8, 5.9, 5.14:** `invocation_digest` on receipts and statements binds them to the exact signed invocation, so a genuine receipt cannot be presented for another call; `args_digest` on the invocation (sent) and on the statement (received) exposes arguments changed in transit (`violated`, I2). Object ids are now unique within a packet. Also from the review of agents-ig#31.
- **Minting rule, spec 5.14:** receipts and statements are produced on the execution path before the result is returned; receipts reconstructed from logs claim at most L1.
- **MCP evidence extension, revision 0.3** (`prototypes/mcp-amep-evidence-ts`): random 128-bit invocation ids, the invocation digest in the request `_meta`, a signed call statement in the result `_meta`, version-2 proofs and AMEP 0.3 packets, and write-ahead receipt storage with recovery through `resources/read` on `amep-receipt://{invocation}` when a response is lost. 34 integration tests on both protocol eras, cross-checked against the Python verifier. The prototype now depends on the repository's own JavaScript package.

## Packages 0.2.0a7 / 0.2.0-alpha.7 and amep-mcp 0.1.0a2 (2026-11-20)

- **Fix (both reference verifiers), spec Section 12.1 and conformance suite v0.2.3:** numbers whose magnitude exceeds 2^53 − 1 are now malformed. Python kept such integers exact while JavaScript rounded them, so the two verifiers canonicalized 2^53 + 1 differently and returned different verdicts on the same signed packet; in JavaScript one approval digest also covered two different identifiers. Both verifiers now return `unresolved`/I7 for any packet containing such a number, `canon` refuses to sign one, and the command-line tools parse with `parse_strict` / `parseStrict`, which reject non-integer literals a double cannot represent exactly (for example `1200.0000000000000001`). The suite adds 4 vectors (118 vectors: 34 positive, 84 must-reject), and the JCS vector's large float changes from `1e21` to `1e15`. Found while writing the cryptographic note in `paper/eprint/`.
- **AgentDojo experiment** (`experiments/agentdojo`): AMEP evidence over all 949 user-task × injection-task pairs of AgentDojo v1.2.2, with mandates of three granularities.
- **Conformance suite v0.2.1** (no normative change): 16 vectors found by mutation analysis of the reference evaluator, covering the action-widening and effect-ceiling rules, `write_shared` as high impact, intent references to non-intent objects, approval `nbf`, verdict precedence within a packet, and the inclusive edge of every time, budget and approval-window bound. 111 vectors (32 positive, 79 must-reject).
- **Mutation analysis tool** (`paper/eval/mutation.py`) with a `--check` mode for CI, and verification benchmarks (`paper/eval/bench.py`, `bench.mjs`).
- **`amep-mcp`**: the verifier as an MCP server (`packages/mcp`), with both conformance suites bundled.
- **`amep-agents`**: evidence recording for the OpenAI Agents SDK (tracing processor) and LangGraph/LangChain (callback handler), with end-to-end tests (`packages/agents`).
- **Delegation-continuity test materials** for the W3C Agent Identity Registry Protocol Community Group (`interop/w3c-agent-identity/delegation-continuity/`): 20 vectors and an offline browser verifier.
- **AMEP-Proposal-1: EvaluationRecord** (`proposals/`).
- `RESEARCH.md`, `CONTRIBUTING.md` and this changelog.

## Packages 0.2.0a6 / 0.2.0-alpha.6 (2026-11-19)

- **Fix (both reference verifiers):** an agent acting directly under a mandate (no delegation) whose `exp` or `nbf` is an RFC 3339 time. The effect time was compared with the unconverted string. Python returned `unresolved`/I7 for every such packet; JavaScript never detected an effect after expiry or before `nbf`. **Conformance suite v0.2.2** adds 3 vectors for this path (114 vectors: 33 positive, 81 must-reject). Found by the AgentDojo experiment.

## v0.2.0-draft.4-r2 (2026-11-17)

- Release metadata update for archiving (Zenodo, Software Heritage); no change to the specification or packages.

## v0.2.0-draft.4, packages 0.2.0a5 / 0.2.0-alpha.5 (2026-11-17)

- Data lineage (`accessed`, `recipient`, `derived_from`), which detects data leaving after a read.
- Verifier state across packets (approvals used, budget spent).
- UCAN profile; a second, independent JSON Schema validator; IETF Internet-Draft rendering (draft-stafordtituss-agentic-mandate-evidence-00).
- Conformance suite v0.2.0: 95 vectors (25 positive, 70 must-reject).

## v0.2.0-draft.3

- `phase` on every decision, so detection is never presented as enforcement; `quarantine` decisions; deny lists that only grow along a chain; conformance Levels 0–5 with an "Attested" qualifier; Biscuit, Macaroon, PASETO and Verifiable Credential profiles; CDDL validation.

## v0.2.0-draft.2

- Signer roles; signed revocations and revocation status; `actor` required for high-impact effects; every effect receipt evaluated; approval digests without `t`, with a validity window and single use; findings trusted only when signed; RFC 3339 times; exact RFC 8785 canonicalization; JSON Schemas; AuthZEN, MCP and host bindings.

## v0.2.0-draft.1

- Attenuation enforces `nbf`, `purpose` and the depth rules; cited intents must exist and be signed; I9 applies to the executed resource.

## v0.1

- Initial model: mandates, delegations, invocations and executed-effect receipts; invariants I1–I7.
