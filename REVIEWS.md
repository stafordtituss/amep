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
| | *None yet* | | | |

### References to AMEP in others' work

| Date | Work | Authors | Relationship to author | Link |
|---|---|---|---|---|
| | *None yet* | | | |

### Public reviews and discussion

| Date | Reviewer | Relationship to author | Where | Summary | Link |
|---|---|---|---|---|---|
| 2026-11-22 | Carlos Vendrell Felici, Zealynx Security | None (no prior collaboration, employment or financial relationship), as stated in the review | Independent review issue | Payments review of the v0.3 quantity limits, with 17 signed packets checked against both reference verifiers. Found that identical payments in one call counted as one (so one approval covered a payment executed twice), that one `period_spent` stood for several periods, that one observer's share was taken as the principal's total, that `caip19:` amounts were ambiguous, and that limits differing only in `actions` shared one total. All fixed in both verifiers (see CHANGELOG). The reviewer disclosed that the review was written with an AI tool. | [stafordtituss/amep#10](https://github.com/stafordtituss/amep/issues/10) |
