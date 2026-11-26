# Reviewing AMEP

AMEP asks one question: **after an agent acts, can a third party verify from portable evidence whether the action stayed within the authority it was delegated?** It answers preserved, violated or unresolved, and publishes conformance vectors (positive and must-reject) so that anyone can check a verifier.

Outside scrutiny is the most useful thing AMEP can get, and critical findings are as welcome as positive ones. Every review, implementation and citation by others is logged below, as written and with the reviewer's stated relationship to the author.

## Three ways to take part

### 1. Run AMEP against your own system, and publish the result in your repository

The strongest contribution: a conformance run, an integration, or a verifier written without the reference code.

1. Run the vectors in `vectors/` against your system or implementation (see "Check everything" in the README).
2. Publish the results, including any disagreements with the expected outcome or invariant, in **your own** repository or site.
3. Open an [implementation report](https://github.com/stafordtituss/amep/issues/new?template=implementation-report.yml) linking to it.

Pull requests that add AMEP evidence export or verification to another project are welcome too; please link them in a report.

### 2. Cite or reference AMEP in your own work

If AMEP is relevant to your Internet-Draft, paper or specification, an informative reference is welcome, and so is a note explaining where the two approaches differ. AMEP cites related work in its Related Work section and in the README; if your work is missing or described inaccurately, please open an issue.

Citation: see `CITATION.cff`, or cite the Internet-Draft, [draft-stafordtituss-agentic-mandate-evidence](https://datatracker.ietf.org/doc/draft-stafordtituss-agentic-mandate-evidence/).

### 3. Review it in public

- Open an [independent technical review](https://github.com/stafordtituss/amep/issues/new?template=independent-review.yml) issue.
- Or comment on the Internet-Draft on an IETF mailing list, or on a W3C, DIF or OpenID Foundation list, and link the archived message in an issue.
- If you sent feedback privately, the maintainer may ask whether you would be willing to post it publicly. It is never posted without your agreement.

## Log

Entries are added only with the person's agreement and link to the public record. Reviews are listed as written, including critical ones. Implementations by the author are not listed here.

### Implementations and conformance runs by others

| Date | Who | Relationship to author | What | Link |
|---|---|---|---|---|
| 2026-11-22 | Brennan Zambo, Zambo (zambo.dev); author of AER-1, the receipt format the run imports | None (no prior collaboration, employment or financial relationship), as stated in the report | Conformance run of `amep-conformance import` (commit `97183f5`) over 12 live AER-1 receipts from the Zambo MCP server, with Zambo's own tool map. All 12 passed the six AER-1 format checks, and 9 imported as AMEP effects. Of the 3 not imported, 2 lacked a field the resource template needs, and the tool map deliberately has no entry for the third. The report states what an unsigned receipt cannot establish: who issued it, and which call authorized it. **Findings:** a gateway refusal record imported as an effect although the call was not executed. That's fixed: such records are no longer imported, so the same 12 records now give 8 imported and 4 not. Also a stale draft citation in the profile, and a missing install step beside the import example (both fixed). | [stafordtituss/amep#11](https://github.com/stafordtituss/amep/issues/11), [results and tool map](https://gist.github.com/zambodotdev/a70a6df54e8ba89ed780abde108aa5fd) |
| 2026-11-24 | Brennan Zambo, Zambo (zambo.dev); author of AER-1, a neighbouring specification (an interest he disclosed) | No employment or financial relationship. Public technical exchanges since 22 Nov (#11, #15, #17; AP2 #402 and #405) | **An independent implementation of the AMEP verifier:** zambo-amep-verify 0.1.0, written from the specification text and the published vectors only, without reading either reference verifier. Python, standard library only: Ed25519 from RFC 8032, canonicalization from RFC 8785. It agrees with all 228 single-packet vectors of the core suite at `5f1700c`, on the outcome and the deciding invariant. Given the earlier state the 18 cross-packet vectors supply, all 246 agree; it doesn't build that state itself yet (Section 10.7 and the interop suites are open on its side). Re-run at `59d0daf`: 246 of 246. **Findings:** four places where the specification text was unclear: the meet's fold order (7.3), when a period total is known (7.6 rule 5), and where call statements and limits run in the evaluation (10.2, steps 9a, 14a and 15a, and step 13's layout). All clarified in `59d0daf`; no vector changed. | [stafordtituss/amep#19](https://github.com/stafordtituss/amep/issues/19), [#18](https://github.com/stafordtituss/amep/issues/18), [implementation and results](https://github.com/zambodotdev/zambo-amep-verify) |
| 2026-11-24 | nmatt1 (paymnts) | As they state it: "APAF-1 is an independent verifier column run by the paymnts production decision layer over AMEP's published fixture set; the fixtures and generator are AMEP's, the verdict engine and dictionary are ours." | **An independent verifier column over AMEP's AP2 fixtures:** APAF-1 judged all 22 payment rows of the pinned fixture sets (`sdk-bundles.json` `7e1dd6d9…`, `bundles.json` `bd530228…`, both hashes recomputed before judging). It's generated by their own implementation: SD-JWT disclosures resolved, and every ES256 signature and digest binding recomputed. It judges the decision on the presented artifacts, including state across payments: spend, use count and closed-mandate replay. AMEP's column was checked against it row by row and matches, including the `held_outcome` gap on s9 txn-2 and the signature gap on s8. **Finding:** none of the open mandates carried `payment.reference`, which AP2's schema requires, so the `spec_schema` check couldn't pass. **Fixed** in AMEP's second SDK family with checkouts, and the profile now checks the checkout binding (#21). APAF-1 re-ran over that family (33 rows, pin `70626262…`): both new cases agree (another checkout: declined, AMEP violated; checkout chain absent: escalated, AMEP unresolved), and `spec_schema` is conformant across it. | [AP2 #402: column](https://github.com/google-agentic-commerce/AP2/issues/402#issuecomment-7131341440), [consent and relationship](https://github.com/google-agentic-commerce/AP2/issues/402#issuecomment-7137351556), [column artifact](https://github.com/nmatt1/paymnts-trail-head-conformance/blob/e4564ad/interop/ap2/apaf1-column.json), [re-run over the v2 family](https://github.com/google-agentic-commerce/AP2/issues/402#issuecomment-7142475421), [updated column](https://github.com/nmatt1/paymnts-trail-head-conformance/blob/7b7388e/interop/ap2/apaf1-column.json) |

### References to AMEP in others' work

| Date | Work | Authors | Relationship to author | Link |
|---|---|---|---|---|
| | *None yet* | | | |

### Public reviews and discussion

| Date | Reviewer | Relationship to author | Where | Summary | Link |
|---|---|---|---|---|---|
| 2026-11-25 | yuzhou (ZYZ666-RGB) — Teleport mapping | None known | GitHub discussion in gravitational/teleport | Checked only two readings of AMEP's Teleport mapping against the pinned Teleport 18.11.10 source (`a2409e7`), and did not run a deployment: a pre-forward access denial as "not executed through this proxy", and a forwarded call as "dispatched, outcome unknown". Corrected the mapping: `success: false` after forwarding is not evidence of non-execution, and HTTP `success: true` covers statuses in [200, 400). Did not review or endorse the rest of the mapping, or AMEP. Listed with the reviewer's agreement and in the wording they asked for. | [gravitational/teleport#70011](https://github.com/gravitational/teleport/discussions/70011) |
| 2026-11-22 | Carlos Vendrell Felici, Zealynx Security | None (no prior collaboration, employment or financial relationship), as stated in the review | Independent review issue | Payments review of the v0.3 quantity limits, with 17 signed packets checked against both reference verifiers. Found that identical payments in one call counted as one (so one approval covered a payment executed twice), that one `period_spent` stood for several periods, that one observer's share was taken as the principal's total, that `caip19:` amounts were ambiguous, and that limits differing only in `actions` shared one total. All fixed in both verifiers (see CHANGELOG). The reviewer disclosed that the review was written with an AI tool. Finding-by-finding dispositions, including his rerun of 23 November: [reviews/amep-10-payments-review.md](reviews/amep-10-payments-review.md). | [stafordtituss/amep#10](https://github.com/stafordtituss/amep/issues/10) |
| 2026-11-25 | Andrii Akhtanin (Radiolaria), author of the Radiolaria reference kernel; external reviewer of the key-status, failure-window and operation-state changes in PRs #22 and #24 | None | Reproduced the five operation-identity cases of #24 and the five producer controls of #22, then found a cross-packet failure: rejected outcome evidence still changed the operation's recorded state (an unverifiable `not_executed` statement released the hold; an unverifiable receipt recorded the operation as done). Fixed as spec 5.8.1 rule 5, with five cross-packet sequences (`317930b`). | [OpenID AIIM list, 25 Nov 2026](https://lists.openid.net/pipermail/openid-aiim/); [#22](https://github.com/stafordtituss/amep/pull/22), [#24](https://github.com/stafordtituss/amep/pull/24) |
| 2026-11-26 | tclancy ([Tom Clancy](https://tomclancy.info/pages/about.html)) | None known. Found AMEP through the OpenSSF agenda request, ossf/ai-ml-security#61 | Three issues on this repository, then a review of the fixes | Three findings, each a verdict that said more than its evidence: a host-signed `principal_confirmed` cleared an injection finding (#34); `unresolved` inside a propagation window when nothing was missing (#35); a missing invocation read as proof of a bypass and charged to the host (#36). All three fixed, with vectors. He reviewed the fixes ("LGTM" on #39) and added three follow-ups: one is in 0.3.1 (a confirmation must be made with the principal present and name the principal), and two are tracked in #41 | [#34](https://github.com/stafordtituss/amep/issues/34), [#35](https://github.com/stafordtituss/amep/issues/35), [#36](https://github.com/stafordtituss/amep/issues/36), [#39](https://github.com/stafordtituss/amep/pull/39#issuecomment-7198819985) |
| 2026-11-26 | Andrii Akhtanin (Radiolaria) | None | OpenID AIIM mailing list | Reran the six carried-state sequences of release 0.3.0 (87c0dfb) in both reference verifiers: all 17 steps passed their verdict and carried-state assertions. Asked for the spec 5.10 restoration transition, which none covered; it is now the seventh sequence (#40) | openid-aiim list, 26 November 2026; [#40](https://github.com/stafordtituss/amep/pull/40) |
