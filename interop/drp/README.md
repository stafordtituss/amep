# AMEP beside the Delegation Receipt Protocol

The [Delegation Receipt Protocol](https://datatracker.ietf.org/doc/draft-nelson-agent-delegation-receipts/) (DRP; reference SDK [Commonguy25/authproof-sdk](https://github.com/Commonguy25/authproof-sdk)) is a **pre-execution** check. A user signs a receipt, and before an agent acts a verifier answers PERMIT or DENY for the proposed action. AMEP judges **what executed**, afterwards. The two meet at one question: is this action within the authority the user delegated?

The AMEP profile (`packages/conformance/src/profiles/drp.mjs`) takes each of the SDK's 14 published vectors and:
1. **Checks the receipt by DRP's own rule first:** the signature, the receipt id, and for sub-receipts the orchestrator binding.
2. **Separates what the user signed from what the verifier was given at check time,** because AMEP decides authority only from signed, machine-readable evidence.
3. **Asks AMEP the matching question:** had the action run as proposed, would AMEP find it within authority? To answer it, the scope the DRP verifier was given is adopted as authority, re-expressed and signed by the importer. That re-expression is labelled wherever it's used.

[COMPARISON.md](COMPARISON.md) has the results, vector by vector. Regenerate it with `node interop/drp/compare.mjs`; add `--check` to test that it's current.

## Results

| | Vectors |
|---|---|
| **Agree** (6) | 4 PERMITs are `preserved`. `action-not-in-scope` is `violated` I2 (blame `agent`). `parent-scope-violation` is `violated` I1 (blame `delegator`) |
| **DRP denies on a check AMEP doesn't make** (2) | `one-time-use-already-consumed` and `one-time-use-no-store`: DRP makes a receipt single use. AMEP makes *approvals* single use, not mandates |
| **Not comparable** (6) | 5 vectors state authority only in natural language (`scope`, free-text action). In `chain-exceeds-max-depth`, the deciding rule is the verifier's own maximum depth |

Every receipt passes DRP's own checks except `invalid-signature`, which fails them as intended. The profile's tests also show that changing a signed field breaks both the signature and the receipt id.

## What the comparison found

**1. In every comparable vector, the root authority is supplied by the verifier, not signed by the user.**
- In 5 of the 8, the only machine-readable scope is `verifierOptions.scopeSchema`, which the verifier is given at check time. The signed receipt states its scope in natural language.
- In the other 3, the parent-child vectors, the child's scope is signed. The parent's is supplied (`parentScopeSchema`), and the parent receipt itself carries only natural-language scope.

DRP's verifier is given its policy, and the vectors test that decision. AMEP's verdict, by contrast, rests on what the evidence shows the user signed. So the AMEP column is labelled as a re-expression, and it would say something different if the importer didn't sign the supplied scope.

**2. The published vectors use the signing rule that draft -15 deprecates.**
- Draft -15 (Section 5) signs the RFC 8785 (JCS) form of the body as a JWS or COSE_Sign1. It notes that the pre-11 rule, `JSON.stringify` in insertion order, isn't canonical across languages.
- All 14 vectors use the pre-11 rule. There are no published vectors for the JWS or COSE profiles, so nothing here tests them.
- The receipt id is the SHA-256 of `JSON.stringify(body + signature)`, also the pre-11 definition. It matches the bytes as given, not a canonical form.

**3. The vectors' signatures aren't in the legacy form the draft describes.**
- The draft (Section 4.4) describes the pre-11 `signature` as lowercase hex of the **DER-encoded** ECDSA signature.
- In all 14 vectors, it's 64 bytes of raw `r‖s` (IEEE P1363). The profile checks it that way, and it verifies.

This is worth raising with the author: a verifier written from the draft's text alone would reject every vector.

**4. Sub-receipts use the binding that draft -15 deprecates.**
- The parent-child link in the vectors is `orchestratorSignature` over `orchestrator-delegation:<parent id>:<child id>`.
- Draft -15 deprecates that field. It says verifiers "MUST NOT treat its presence as satisfying holder binding". It binds the chain instead by the parent's `delegateeKey` matching the child's `signerPublicKey`.
- No vector carries `delegateeKey`, so the current holder-binding rule isn't exercised by any published vector.

**5. DRP scopes are (operation, resource) pairs. AMEP now expresses them exactly.**
- The scope in `narrowed-sub-receipt` allows read documents, read reports and write reports. AMEP's claims were one product, actions × resources, and the smallest product holding those three pairs also allows *write documents*. Expressing DRP's scope would have widened it.
- AMEP 0.3 now has **grants** (spec 5.3): a union of products, one grant per pair, so nothing is widened. The profile's tests include the case: *write documents* under that scope is `violated` I2.
- DRP's scopes are where the gap showed. It wasn't specific to DRP: any pair-based policy has it.

## Where DRP is ahead

- **A decision before the action.** DRP is built to stop an action, and AMEP to judge one afterwards. They're complementary: a DRP PERMIT, with its receipt, is evidence an AMEP packet could carry.
- **One-time use of the delegation itself**, with a required consumption store. AMEP makes approvals single use, but has no single-use mandate.
- **Authority-state drift.** A receipt can commit to the authority state, so a verifier can detect that the authority has changed since signing. AMEP's nearest check is revocation at the effect's own time (I6).
- **A COSE profile** alongside JWS.

## Gaps on AMEP's side

These are DRP checks with no AMEP verdict:
- one-time-use receipts;
- maximum chain depth as a delegation rule;
- authority-state drift;
- the instruction hash (`instructionsHash`), which binds the operator's instructions to the receipt. AMEP binds evidence to the call (`args_digest`), not to the instructions.

The first two are candidates for an AMEP extension.

## Corrections

This is the AMEP author's reading of DRP's vectors through the profile's code. Corrections from DRP's author are welcome, by issue or pull request, especially where a vector's intent is misread.
