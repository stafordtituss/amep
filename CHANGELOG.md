# Changelog

Specification drafts, conformance-suite versions and package versions are listed together. Package versions follow PEP 440 (Python) and SemVer (npm).

## Held approvals (unreleased, 2026-11-23)

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

## Signature gaps say why (unreleased, 2026-11-23)

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

## Reasons: a call that provably didn't run says so (unreleased, 2026-11-23)

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

## Limits: order-independent, and observer totals name their window (unreleased, 2026-11-23)

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

## Holds: an unknown outcome stays counted across packets (unreleased, 2026-11-23)

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

## Worked example for FINOS AIGF #421 (unreleased, 2026-11-23)

- **`interop/finos-aigf/case-421-family-office/`:** the family-office example of finos/ai-governance-framework#421 as seven signed packets. A client's USD 10M mandate is split across two banks; each bank signs what it booked and counts its own leg, and the client's verifier holds the total. The phases:
  - a plan within the mandate (`preserved`);
  - slices that each fit but together over-book (`violated` I2);
  - a leg delegated to an institution the client never named (`violated` I1, blame `delegator`);
  - a lost response, before and after a retry (`unresolved` I7);
  - reconciliation either way: the first instruction booked (`violated` I2, 14M) or never booked (`preserved`).

  Both reference verifiers agree on every phase, and the generator asserts each verdict. The FINOS mapping links it.
- **A gap it found, now closed by holds (above):** across packets, verifier state didn't carry an instruction with an unknown outcome forward. Phases 8 and 9 now show the lost instruction held in a later batch, and then released by the bank's statement.

## Comparison with EMILIA Protocol's vectors (unreleased, 2026-11-23)

- **EP profile** (`packages/conformance/src/profiles/ep.mjs`) and **`interop/ep/`:** AMEP beside two of EP's published suites (draft-schrock-ep-authorization-receipts).
  - **`receipts.v1`:** EP-RECEIPT-v1, checked by a clean-room reading of EP's rules (written from the vectors and EP's documentation, not its code). It agrees with EP's expected result on all 14 vectors.
  - **`outcome-binding.v1`, predicate vectors:** EP's `in_bounds` / `divergent` / `incomparable` beside AMEP's `preserved` / `violated` / `unresolved`. AMEP can express 7 of the 24 exactly and agrees on 6. The difference is by design: EP's predictions bound only the effect types they name, while AMEP's claims are an allowlist.
- **Findings, in the README:**
  - EP's Merkle branch hash runs over the children's hex text, not their raw bytes, which EP's design notes don't make clear;
  - the vectors can't distinguish position order from sorted order, and have no v2 tampered-root case;
  - EP's predicates (exact values, sets, minimums, counts) are richer than AMEP's claims. Count limits are now needed by two outside formats.
- The vectors are vendored, unchanged and with their licence, as test fixtures (Apache-2.0); their digests match EP's manifest.

## Comparison with the Delegation Receipt Protocol's vectors (unreleased, 2026-11-22)

- **DRP profile** (`packages/conformance/src/profiles/drp.mjs`) and **`interop/drp/`:** AMEP beside the 14 published vectors of DRP's reference SDK (draft-nelson-agent-delegation-receipts). Each receipt is checked by DRP's own rule first (signature, receipt id, orchestrator binding); only `invalid-signature` fails, as intended. AMEP then answers the matching question, had the action run as proposed, with the scope the DRP verifier was given adopted as authority and labelled as such. Of the 8 vectors that can be compared, AMEP agrees on 6. The remaining 2 are DRP's single-use receipts, which AMEP doesn't have. The 6 that can't be compared state authority only in natural language, or decide by the verifier's chain-depth limit.
- **Findings, in the README:**
  - the root authority in every comparable vector is supplied by the verifier, not signed by the user;
  - the vectors use the pre-11 signing rule that draft -15 deprecates, and there are no vectors for its JWS or COSE profiles;
  - their signatures are raw P1363, not the DER the draft describes for that rule;
  - sub-receipts use `orchestratorSignature`, which -15 deprecates.
- DRP's scopes allow (operation, resource) pairs, which is what led to grants (above). The profile expresses them exactly, and a test shows an action inside the product of the pairs, but outside every pair, is `violated`.
- **`interop/COVERAGE.md`** has a DRP column.
- The vectors are vendored, unchanged and with their licence, as test fixtures (MIT).

## Grants: authority as a union of products (unreleased, 2026-11-22)

- **Spec 5.3:** a claim set may carry `grants`, a list of `{actions, resources}`, instead of `actions` and `resources`. Each grant permits its actions on its resources, and the authority is their union. One product (`actions` × `resources`) can't express "read the documents, write the reports" without also permitting "write the documents"; grants can. Plain claims count as one grant, so the two forms mix along a chain:
  - an effect satisfies the claims when one grant permits both its action and its resource (I2);
  - a delegation is narrower when each of its grants lies within one parent grant (I1), which never accepts a widening.
- **Additive:** claims with `actions` and `resources` are evaluated exactly as before (every earlier vector and `verify` output is unchanged). In an AMEP 0.3 packet, a verifier without the rule returns `unresolved` (unknown claim member), never `preserved`. An unversioned packet that uses `grants` is `unresolved` (I7) rather than ignored, because ignoring a narrowing member could widen authority.
- Raised by comparing AMEP with the Delegation Receipt Protocol, whose scopes allow (operation, resource) pairs.
- Suite v0.3.0 is now 221 vectors (59 positive, 162 must-reject), 7 of them new. Both verifiers agree on all 257 vectors of the three suites; JSON Schema and CDDL are updated.

## Coverage matrix (unreleased, 2026-11-22)

- **AER-1 profile, binding gap wording:** the report now says what `input_hash_layout` means. Under `rfc8785-jcs-utf8-v1`, `input_hash` *is* AMEP's `args_digest`. Under another layout, it equals `args_digest` only for arguments that serialize identically under both. The report also says whether a binding was made. This is wording only; binding stays by digest. It was noted before the blind fixture run in amep#11 and fixed after it, so the run used the code the expectations were written against.

- **`interop/COVERAGE.md`:** for each format AMEP can import (AER-1, OpenID DA action receipts, Provared) and for AMEP's own evidence, which parts of the question (I1 to I11, binding to the call, confirmed non-execution) the format's records can settle. Each cell is based on the import profile's code, its gap report and its tests. The format authors are invited to correct their rows.

## Provared import; comparison with the Provared checker (unreleased, 2026-11-22)

- **`amep-conformance import-book`**, with a profile for Provared books (draft-izmaylov-agent-permission-receipts). Every record is checked by the format's own rules first: the envelope, labels, canonical form, both hybrid signatures (Ed25519 and ML-DSA-87), the passkey (WebAuthn) signatures, fingerprints, the chain, and countersignature and approval binding. The verified records are then re-expressed as AMEP evidence (slip → mandate, stubs → invocations, countersigned stubs → service-observed effects at L1, one-sided stubs → the agent's own report at L0, approvals → approvals). Limits AMEP can't express exactly are reported as gaps.
- **`interop/provared/`:** AMEP's verdicts on the format's own sample book beside the Provared checker's expected findings, generated by `compare.mjs`. They agree on 3 of the 6 actions, and both flag a fourth. AMEP is stricter on one (a message recorded only by the agent). The sixth is an AMEP gap: a deletion outside the permission, recorded only by the agent, is `unresolved` in AMEP, not `violated`. That and three other open questions are in the README.
- The sample book is vendored, unchanged and with its notice, as a test fixture (Apache-2.0).

## Operation approvals (unreleased, 2026-11-22)

- **Spec 5.10:** an approval may carry `effect_digests`, a non-empty list of effect digests, instead of `effect_digest`. It approves the effects of one call. Every executed effect of that invocation must be listed, and no body may run more often than it is listed; otherwise the result is `violated` (I8). An approved effect that didn't run is not a violation. It's single use like any approval, so a retry that cites it is `violated` (I8). An approval with both members, or with an empty or malformed list, is `unresolved` (I7).
- **Additive:** approvals with `effect_digest` are evaluated exactly as before (every earlier vector and `verify` output is unchanged), and a verifier without this rule never returns `preserved` for one.
- **Fix (both verifiers):** an approval with no digest at all was `unresolved` in Python but `violated` (I8) in JavaScript; the spec makes it malformed, and both now return `unresolved` (I7). No earlier vector covered it, so the differential check couldn't see the disagreement. Found while testing how earlier verifiers treat operation approvals; there's now a vector for it.
- Motivated by Takao Sato's VATE reference case 1 for openid/authzen#795: a single admission covering an operation that writes two files had no AMEP equivalent. `interop/authzen-receipts/vate-01-lost-response` adds the admission, and the retry is now `violated` (I8).
- Suite v0.3.0 is now 214 vectors (57 positive, 157 must-reject), 10 of them new; both verifiers agree on all 250 vectors of the three suites. JSON Schema (with `oneOf`, now in the built-in validator too) and CDDL updated.

## AER-1 refusal records; VATE case 1 (unreleased, 2026-11-22)

- **Fix (`amep-conformance import`, AER-1 profile):** a record of a call a gateway refused imported as an executed effect, although its committed output says `"executed": false`. Such records now produce no effect; the call stays `unresolved`, since an unsigned record can't confirm non-execution either. Only content inside the record's output commitment counts. Found by Brennan Zambo running the import over 12 live Zambo receipts ([amep#11](https://github.com/stafordtituss/amep/issues/11)); the same records now give 8 imported and 4 not.
- The AER-1 profile cites draft-zambo-aer1-26, and the conformance README gives the install step beside the import example (both from the same report).
- **`interop/authzen-receipts/vate-01-lost-response`:** Takao Sato's VATE case 1 for openid/authzen#795 (a lost response, then recovery) as AMEP evidence. Three signed packets and the caller's signed verdict for each phase; both verifiers agree on all three.

## amep-mcp on the v0.3 suites (unreleased, 2026-11-22)

- **Fix:** amep-mcp still bundled conformance suite v0.2.3, so its own `check_suite` disagreed with the v0.3 verifier on `status-current-as-of-the-action`, the one vector v0.3 deliberately changed. The bundle is now suite v0.3.0 (204 vectors), the delegation suite (20) and the approval-path attacks (16, draft), including the vectors that exist only as exact JSON text.
- **Fix (security):** an MCP client's JSON text was parsed loosely before the verifier saw it, so a packet with a duplicated member name, which v0.3 makes `unresolved`, could come back `preserved`. The MCP SDK parses any JSON-looking string argument into an object unless the parameter is typed as a plain string. `verify_packet` now takes `packet_text`, which is parsed strictly; `packet` still takes an object; every result reports `parsed_strictly`.
- Results carry `blame` and `gaps` (spec 10.5.1).
- Spec Section 15 states suite v0.3.0 (204 vectors) instead of v0.2.3.
- **Release order:** the next amep-mcp release needs `blame` and `gaps`, which are newer than amep-protocol 0.3.0a1. Release amep-protocol first, then amep-mcp with its dependency raised to that version.

## Blame and evidence gaps (unreleased, 2026-11-22)

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
