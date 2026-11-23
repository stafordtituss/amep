# Dispositions: payments review by Carlos Vendrell Felici (amep#10)

This is the maintainer's record of what happened to each finding in [stafordtituss/amep#10](https://github.com/stafordtituss/amep/issues/10). For each one it gives:
- the reviewer's case or observation;
- the reading AMEP adopted;
- the commit and release that carry the change;
- the reviewer's own follow-up, where he has posted one.

His words are in the issue; this page only links and summarizes them.

- **Reviewer:** Carlos Vendrell Felici, Zealynx Security.
- **Relationship:** none, as stated in the review.
- **AI use:** disclosed in his review and his rerun ("Claude Code ran both parts and wrote this reply on my behalf").

## Round 1: review of v0.3.0-draft.1 (22 November 2026, at `88120a2`)

[Review](https://github.com/stafordtituss/amep/issues/10) (17 signed packets, both reference verifiers) · [maintainer's response](https://github.com/stafordtituss/amep/issues/10#issuecomment-7072695354)

| # | Finding (reviewer's cases) | Reading adopted | Change | Released in | Reviewer's rerun (23 Nov) |
|---|---|---|---|---|---|
| 1 | Two identical payments in one call counted as one, so one approval covered a payment executed twice (A3, A4, A4s) and two payments counted once toward a period limit (A5) | Receipts are grouped per observer. One effect seen by several observers counts once, but two receipts from one observer are two effects (spec 10.2) | `409d520` | amep-protocol 0.3.0a1, @stafordtituss/amep 0.3.0-alpha.1 | Confirmed: A3, A4 and A4s are `violated` I8, A5 is `violated` I2, and the control A4p is `preserved` |
| 2 | `per_call` capped one effect, so 60.00 + 60.00 passed `per_call: 100.00` (B1) | `per_call` caps the whole call; a new `per_effect` caps one effect (spec 7.6) | `409d520` | 0.3.0a1 | Confirmed: B1 and B2 are `violated` I2, and the control B1p is `preserved` |
| 3 | One `period_spent` figure stood for both a daily and a monthly total (C1, C2) | `period_spent` is keyed by period length (spec 5.9.2) | `409d520` | 0.3.0a1 | Confirmed for C1 (`violated` I2). His rerun then found that C2's result depended on limit order: see round 2, finding 6 |
| 4 | One observer's share was taken as the principal's total when one mandate paid through two services (D1 to D4) | A limit names the observer that counts all of the node's spending (`counted_by`); no other observer's figure counts (spec 7.6) | `409d520` | 0.3.0a1 | Confirmed: D1 `preserved`, D2 `unresolved` I7, D3 and D4 `violated` I2 |
| 5 | `caip19:` amounts could be read as whole tokens or as base units (E1, E2) | Integers in the asset's smallest unit (spec 5.9.2) | `409d520` | 0.3.0a1 | Confirmed: E1 `preserved` and E1b `violated` at the cap; E3 (1 yoctoNEAR) `preserved` |
| 5a | Two limits differing only in `actions` shared one running total (F1) | Each limit keeps its own total (spec 7.6) | `409d520` | 0.3.0a1 | Confirmed: F1 `preserved`, F1b `violated` I2 |
| 5b | *Found by the maintainer while fixing 1 to 5:* approval digests included `period_spent`, which an approval signed before execution can't know | Approval and effect-identity digests leave out `period_spent`, as they leave out `t` (spec 5.10) | `409d520` | 0.3.0a1 | Not separately tested |

## Round 2: rerun at `9dbf1c2` (23 November 2026)

[Rerun](https://github.com/stafordtituss/amep/issues/10#issuecomment-7089336784) (the original 17 packets, plus the cases rebuilt in the 0.3.0a1 format with controls, at three commits) · [maintainer's response](https://github.com/stafordtituss/amep/issues/10#issuecomment-7089902771)

| # | Finding | Reading adopted | Change | Released in | Status |
|---|---|---|---|---|---|
| 6 | The verdict depended on the order of the limits: daily first, `unresolved` I7; monthly first, `violated` I2 (C2, C2r) | Every applicable limit is checked before deciding; a violation beats an unresolved check (spec 7.6) | `33c7d94` | Not yet released | Fixed; vectors `limit-order--*`. Awaiting the reviewer's rerun |
| 7 | `period_spent` didn't say which window it covered. A bank's own month was read as the limit's window, giving a false `preserved` (W1) and blaming an honest bank (W2) | Each figure is `{from, total}` and counts only for the window that starts at `from`; a bare figure never counts (spec 5.9.2, 7.6 rule 4) | `33c7d94` | Not yet released | Fixed; vectors `observer-figure-*` and `observer-s-own-month-is-not-held-against-it`. Awaiting the reviewer's rerun |
| 8 | A decimal amount in a `caip19:` unit got a reason asking for a decimal string (E3b) | The reason asks for an integer in the asset's smallest unit; the outcome is unchanged | `33c7d94` | Not yet released | Fixed |
| 9 | One body listed once in an operation approval, with receipts from the bank and the PSP, is `preserved`: spec 10.2 counts it as one effect | No change: it follows from 10.2. The reviewer notes that for a batch payment this rule decides between one approved transfer and two | — | — | Open as a design question; the reviewer may raise it in a private advisory |
| 10 | Four operation-approval results that go against spec 5.10 | Reported privately; private vulnerability reporting was enabled for it on 23 November | — | — | Awaiting the reviewer's private advisory |

Also from the rerun: in the original 17 packets, E1 and E2 now read their cap of "100" as 100 base units, so they no longer test the decimals question. The rebuilt E1 and E1b cover it.

## What the review changed

- **Spec sections changed:** 5.9.2, 5.10, 7.6 (rules 1 to 5, the order rule, and rule 4's window) and 10.2.
- **Vectors added from the reviewer's cases:** 15 in round 1 and 5 in round 2.
- **Credit:** in spec 7.6 and the changelog.
- **Released:** findings 1 to 5b in 0.3.0a1. Findings 6 to 8 go into the next alpha release.
