# Approval-path attacks: AMEP test vectors (draft for review)

**Status:** draft, under review by the authors of the attack catalogue. Not yet part of the core conformance suite.

The attacks are from S. V. Kodathala, P. Pollishetty and J. Cargill, *Approve What, Exactly? Effect Binding and Trusted Rendering for Agent Step-Up Authorization*, [arXiv:2610.21063](https://arxiv.org/abs/2610.21063), 2026. That paper defines twelve attacks on the approval path of AI agents (AB1–AB12), plus substitution, replay and grant stretching. It also proposes ASU, a gateway that blocks them *at approval time*.

These vectors ask the complementary question: **after the fact, using only the evidence left behind, can a third party show that the attack happened?** The evidence is a signed approval, a signed invocation and a receipt signed by the payment system. Where the answer is no, the attack is listed under [Not detectable from evidence](#not-detectable-from-evidence) rather than forced into a vector.

## Scenario

Alice (`did:web:bank.example:customers:alice`) lets a payments assistant pay her landlord and her utility company. Her passkey key issues the mandate and signs approvals. The bank's payment system signs a receipt of every payment it executes. Payment arguments (amount, currency, memo) travel in the `x-args` extension of the executed-effect body, so the approval digest covers them.

## Vectors

16 vectors: 4 positive and 12 must-reject. Both reference verifiers (Python and JavaScript) agree with every expected outcome, and every packet validates against the AMEP JSON Schemas.

| Attack | Vector | Expected |
|---|---|---|
| Baseline: binding (P2) | `approved-payment-executed-as-approved` | preserved |
| Baseline: single use (P3) | `two-payments-two-approvals` | preserved |
| Baseline for AB12 | `small-payment-within-budget-needs-no-approval` | preserved |
| AB1 (boundary) | `signed-body-with-both-amounts-is-preserved` | preserved |
| AB10, substitution | `post-approval-substitution` | violated, I8 |
| AB1 | `amount-cancellation` | violated, I8 |
| AB2 | `decoy-field-recipient` | violated, I8 |
| AB2, substitution | `decoy-recipient-executed` | violated, I2 |
| AB4 | `hidden-text-in-executed-argument` | violated, I8 |
| AB3, grant stretching | `standing-grant-to-new-payee` | violated, I2 |
| AB3, grant stretching | `approval-reused-for-larger-amount` | violated, I8 |
| Replay (P3) | `approval-replayed-in-same-run` | violated, I8 |
| Replay (P3) | `approval-marked-consumed` | violated, I8 |
| Replay (P3) | `approval-used-after-expiry` | violated, I8 |
| AB7 | `approval-signed-by-enrolled-attacker-key` | unresolved, I7 |
| AB12 | `payment-split-under-threshold` | violated, I2 |

Each vector file carries an `attack` field and a `note` field explaining where the boundary lies.

## Not detectable from evidence

| Attack | Why after-the-fact evidence cannot show it |
|---|---|
| AB4, when the hidden text was signed | If Alice's key signed bytes that contain the hidden text, the approval is genuine. Whether she *saw* it depends on trusted rendering (the paper's H3). The vectors cover only text added after approval. |
| AB5, label spoofing | A property of the card shown to the user, not of the signed effect. |
| AB6, non-injective rendering | The approval binds a digest of the effect, so two effects never share an approval. But if the card for E2 looked like E1 and Alice signed E2, the evidence shows a genuine approval of E2. |
| AB8, challenge ambiguity | AMEP signs RFC 8785 canonical JSON of the whole object, so distinct objects give distinct signed bytes. There's no vector, because the encoding admits no ambiguous pair to construct. Review of this claim is welcome. |
| AB9, ceremony control | The device signs a digest; the evidence proves what was signed, not what was displayed (the paper's P5 and H3). |
| AB11, flooding | Every approval in a flood is genuinely signed. The evidence records how many approvals a run requested, but no invariant makes "too many" a violation. A rate profile could. |

## Open questions for reviewers

1. **AB1 and AB2:** do the vectors model the attacks as the paper defines them? In particular, is a second amount or beneficiary appearing in the executed body (rather than the approved one) the right reading?
2. **AB7:** AMEP reports `unresolved`, not `violated`, because evidence can show that no authorised approver signed but not who controls the unknown key. Is that the right outcome for an evidence verifier?
3. **AB12:** AMEP's risk budget counts effect-cost units (60 per irreversible payment here), not currency. Should a monetary threshold be an AMEP profile?
4. **Extensions in the digest:** payment arguments are carried in `x-args`, and the reference verifiers include extension members in the approval digest (spec 5.10 binds the executed-effect body). Spec 7 says extensions must not change outcomes. These vectors depend on the digest covering them, so the spec should say so explicitly.

## Regenerate and check

From the repository root:

```
python3 -I interop/approval-path-attacks/generate.py
node verifier/typescript/amep_verifier.mjs interop/approval-path-attacks
```

Keys are deterministic test keys. Never use them for anything else.

## Credit

The attack catalogue and the ASU design are the work of Kodathala, Pollishetty and Cargill. Review of these vectors by the paper's authors will be credited here and in `REVIEWS.md`.
