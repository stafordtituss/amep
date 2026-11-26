# What has been checked, by whom, against what

This page answers a narrow question for each outside party: **what did they check, against which version, and what did they find?** It is not an endorsement list. It separates:
- independent implementations;
- reproductions of AMEP's own outputs;
- reviews that changed AMEP's rules;
- reviews of AMEP's reading of another format.

AMEP's own checks are listed last, because they show consistency, not independence.

Every row links to the public record. The full entries, in the reviewers' own words where they asked for that, are in [REVIEWS.md](REVIEWS.md) and [vectors/CREDITS.md](vectors/CREDITS.md).

## The baseline

**Release 0.3.1** (`amep-protocol` 0.3.1 on PyPI, `@stafordtituss/amep` 0.3.1 on npm), conformance suite v0.3.3. Suite digests are as printed by `amep-conformance verify`, SHA-256 over the key set and every vector file:

| Suite | Vectors | Digest |
|---|---|---|
| core (`vectors/`) | 291 (76 positive, 215 must-reject) | `53fab55dfa89fecbd4476c53dc497a330e39926b849d2471dd762f6b3418a3e9` |
| approval-path attacks (`interop/approval-path-attacks/`) | 16 | `371db5321167b1f29f72262399d29b0a2f4fd7c2bdd4a3df96dfa314298a3eb9` |
| delegation continuity (`interop/w3c-agent-identity/delegation-continuity/`) | 20 | `018ebe703a21f321bdfb1942e4617717074aeb05f19d93b632b2671b2ce1785c` |
| cross-packet sequences (`vectors/sequences/operation-state.json`) | 7 sequences, 20 steps | file SHA-256 `8e6f4616d763bb80e9ab448c78bda950432d6669f24a642f27a7e96493e90bb4` |

Earlier results below were against earlier suites. Each row says which, and none of them is a claim about 0.3.1 unless it says so.

## 1. Independent implementations

Written by someone other than the author, without reading the reference verifiers.

| Who | What | Against | Result | Not covered |
|---|---|---|---|---|
| Brennan Zambo, [zambo-amep-verify](https://github.com/zambodotdev/zambo-amep-verify) 0.1.0 | A verifier written from the specification text and the published vectors only (Python, standard library; RFC 8032, RFC 8785) | Core suite at `5f1700c`, rerun at `59d0daf` (24 November, before 0.3.0) | 228 of 228 single-packet vectors on outcome and invariant; 246 of 246 with the cross-packet state supplied. Four unclear passages found and clarified | It does not build cross-packet state itself; the two interop suites; everything added in 0.3.0 and 0.3.1. [#18](https://github.com/stafordtituss/amep/issues/18), [#19](https://github.com/stafordtituss/amep/issues/19) |
| nmatt1 (paymnts), APAF-1 | An independent verifier column over AMEP's AP2 payment fixtures. Their own engine and dictionary; AMEP's fixtures and generator | The pinned AP2 fixture sets (22 rows), then the second family with checkouts (33 rows, 24 November) | Matches AMEP's column row by row, including the `held_outcome` gap and the signature gap. Found that the fixtures lacked `payment.reference`; fixed | AMEP's core suite: only the AP2 profile's fixtures. [AP2 #402](https://github.com/google-agentic-commerce/AP2/issues/402) |

## 2. Reproductions of AMEP's own outputs

These re-run AMEP's published results with AMEP's code, or check them by hand. They confirm the results reproduce; they are not independent implementations.

| Who | What | Against | Result |
|---|---|---|---|
| Andrii Akhtanin (Radiolaria) | Reran the six carried-state sequences in both reference verifiers | Release 0.3.0 (`87c0dfb`), 26 November | All 17 steps passed their verdict and carried-state assertions. Asked for the restoration transition, now the seventh sequence ([#40](https://github.com/stafordtituss/amep/pull/40)). [His message on the OpenID AIIM list](https://lists.openid.net/pipermail/openid-aiim/Week-of-Mon-20261123/000275.html) |
| Andrii Akhtanin (Radiolaria) | Reproduced the operation-identity cases of #24 and the producer controls of #22 | The #22 and #24 branches, 25 November | Reproduced, then found that rejected evidence still changed carried state; fixed as spec 5.8.1 rule 5 |
| Takao Sato (VATE) | Reproduced AMEP's verdicts on three reference cases and checked their signatures, then merged them into the Verifiable Agent Trust Envelope comparison | AMEP reference cases 1 to 3 | Merged upstream: [#138](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/pull/138) (case 1), [#139](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/pull/139) (case 2) and [#142](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/pull/142) (case 3) in Poke-nushi/Verifiable-Agent-Trust-Envelope |

## 3. Reviews that changed AMEP's rules

Each led to a specification change, vectors that pin it, and a release.

| Who | Findings | Fixed in | Reviewer's check of the fix |
|---|---|---|---|
| tclancy (Tom Clancy) | A host-signed `principal_confirmed` cleared an injection finding; `unresolved` inside a propagation window with nothing missing; a missing invocation read as proof of a bypass ([#34](https://github.com/stafordtituss/amep/issues/34), [#35](https://github.com/stafordtituss/amep/issues/35), [#36](https://github.com/stafordtituss/amep/issues/36)) | 0.3.1 | Reviewed the fixes ("LGTM", [#39](https://github.com/stafordtituss/amep/pull/39)). One follow-up is in 0.3.1; two are tracked in [#41](https://github.com/stafordtituss/amep/issues/41) |
| Carlos Vendrell Felici (Zealynx Security) | Five quantity-limit errors, found with 17 signed packets ([#10](https://github.com/stafordtituss/amep/issues/10)); then 12 vectors of his own ([#30](https://github.com/stafordtituss/amep/pull/30)). He also ran weakened copies of the core: three of four passed every earlier vector and fail only on his new ones | 0.3.0 | His rerun of 23 November: [reviews/amep-10-payments-review.md](reviews/amep-10-payments-review.md) |
| Andrii Akhtanin (Radiolaria) | Key status ([#22](https://github.com/stafordtituss/amep/pull/22)); retries under fresh authorization ([#24](https://github.com/stafordtituss/amep/pull/24)); rejected evidence changing carried state | 0.3.0 | The sequence rerun above |
| Brennan Zambo | Call statements and binding; a host's own `fail_mode` never settling "nothing executed" ([#15](https://github.com/stafordtituss/amep/issues/15)); what may release a hold (review of #24) | 0.3.0 | Agreed the expected answers on #24 |
| Cliff Singletary (Cerydora) | Revocation between an invocation and its effect, and between two effects of one call | 0.3.0 | IETF audit list, 19 November |

## 4. Reviews of AMEP's reading of another format

These check whether an AMEP import profile reads the other project's records correctly. They are not reviews of AMEP itself.

| Who | What | Status |
|---|---|---|
| Agent Receipts maintainers | Reviewed the Agent Receipts profile and report at `1700014` against their spec; three wording changes made | Done. [agent-receipts/obsigna#1204](https://github.com/agent-receipts/obsigna/issues/1204), [#37](https://github.com/stafordtituss/amep/pull/37) |
| Tom Farley (ScopeBlind) | Checked the protect-mcp fixtures against the published issuer key; requested binding and phase changes | Changes made; re-review pending. [#20](https://github.com/stafordtituss/amep/pull/20) |
| yuzhou (Teleport) | Checked two readings of the Teleport mapping against pinned Teleport source | Mapping corrected. [gravitational/teleport#70011](https://github.com/gravitational/teleport/discussions/70011) |

## 5. AMEP's own checks (not independent)

| What | Result at 0.3.1 |
|---|---|
| Python and JavaScript reference verifiers. Same author, so agreement shows consistency, not independence | Both agree with every expected outcome: 291 core, 16 approval-path, 20 delegation, and all 7 sequences |
| The offline browser page (the JavaScript core with WebCrypto) | 291 of 291 |
| The vector index, JSON Schemas and CDDL | Every vector as expected (23 deliberately invalid) |

## What has not been checked yet

- **The current suite:** no independent implementation has run suite v0.3.3. Brennan Zambo's results are against the core suite as of 24 November.
- **The interop suites** (approval-path attacks, delegation continuity) have no outside run.
- **The 0.3.1 rule changes,** apart from tclancy's review of his own findings.
- **Production use:** nothing here shows AMEP in a production deployment.

To add a row, run the suites against your implementation (`amep-conformance verify`) and open an [implementation report](https://github.com/stafordtituss/amep/issues/new?template=implementation-report.yml).
