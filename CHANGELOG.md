# Changelog

Specification drafts, conformance-suite versions and package versions are listed together. Package versions follow PEP 440 (Python) and SemVer (npm).

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
