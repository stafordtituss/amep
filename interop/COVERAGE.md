# Which questions each agent-receipt format can settle

AMEP asks one question with many parts: **did what an agent actually executed stay within the authority it was delegated?** This matrix shows, for each format AMEP can import or compare with, which parts that format's own evidence can settle. Where it can't, AMEP's verdict for that part is `unresolved`, with the missing evidence named.

It covers only formats with an import or comparison profile, where every cell can be checked against the profile's code, its gap report and its tests (`packages/conformance`). Formats without a profile are listed at the end, with no cells, until their profiles exist.

**Legend**
- ● **The format carries it.** Its records hold the evidence, and the profile uses it.
- ◐ **Partly.** The evidence is partial, needs a published map from the deployment, or is in the format but not yet used by the profile (the note says which).
- ○ **Not carried.** AMEP cannot settle this part from the format's records; it needs AMEP evidence from elsewhere, such as the gateway's signed invocation, or it stays `unresolved`.

| Question (AMEP invariant) | AMEP native | AER-1 (Zambo) | OpenID DA action receipt | Provared (Izmaylov) | Delegation Receipt Protocol (Nelson) |
|---|---|---|---|---|---|
| **Each delegation only narrows its parent** (I1) | ● | ○ no delegation | ◐ references the Task and chain by `jti` and hash; the verifier supplies their content | ◐ helper agents (passes, section 25) are in the format; not yet used by the profile | ◐ the child's scope is signed in the receipt; in the published vectors the parent's machine-readable scope is supplied by the verifier |
| **What executed was within the claims**: action, resource, effect class (I2) | ● | ◐ through the deployment's tool map | ◐ through a published map of `verb` and `resource_type` | ◐ action names, and effect class from the shared list's kinds; the resource is only the service named | ◐ (operation, resource) pairs, exactly, as AMEP grants, when the scope is machine-readable; effect class from a fixed map of operations |
| **What executed matches what was declared** (I2) | ● | ○ one record per call; the declared side comes from the gateway | ○ the declared side comes from the gateway | ○ a stub is the agent's record of what it did; there is no separate declared effect | ○ a pre-execution decision; nothing records what executed |
| **Amounts within limits** (I2, section 7.6) | ● | ○ no quantities | ○ no amount on the action (raised in openid/authzen#795) | ◐ amounts and limits. Lifetime totals and approval thresholds map exactly; caps an approval can't lift, counts and sliding windows are gaps | ○ none in the published vectors |
| **An approved adapter interpreted the call** (I3) | ● | ◐ the tool name and version are committed; not yet used as an interpretation pin | ○ | ○ | ○ |
| **No unconfirmed untrusted influence** (I4) | ● | ○ | ○ | ○ | ○ |
| **Data released was permitted** (I5) | ● | ○ no data-flow labels; the importer refuses `external_send` and above without a declared release | ○ | ○ documents are named by hash, not by data class | ○ |
| **Not revoked at the effect's own time** (I6) | ● | ○ | ◐ revocation receipts (section 6.5) are in the format; not yet used by the profile (its revocation test uses AMEP revocations) | ◐ cancellations (section 22) are in the format; not yet used by the profile | ◐ a revocation registry (draft section 9) and an authority-state commitment (in one vector); the profile maps neither |
| **The evidence is authentic** (I7) | ● signed by keys holding the right role | ○ unsigned; hashes show the served bytes are intact, not who served them | ◐ the PEP's signature is not checked by the profile | ● hybrid Ed25519 + ML-DSA-87 signatures and passkey signatures, all checked by the profile | ◐ the user's P-256 signature, checked by the profile under the legacy rule; the -15 JWS and COSE profiles have no published vectors |
| **Approvals bound to exactly what executed, used once** (I8) | ● including operation approvals | ○ | ○ not carried by the receipt | ● a passkey-signed approval of one action; AMEP checks single use | ○ one-time use applies to the whole receipt, not to an approval of an effect |
| **No action against guardrails, keys or the evidence store** (I9) | ● | ◐ through the tool map's resource | ◐ through the map | ○ no resource beyond the service | ◐ denied actions, when the scope is machine-readable |
| **Observed by someone other than the actor** (I10) | ● with assurance levels | ◐ the provenance class: executed or observed by the service (L1), or logged by the agent (L0) | ◐ the execution layer's receipt; its signer isn't checked by the profile | ● a countersignature by the service (L1); without one, the stub is the agent's own word (L0) | ○ nothing is observed; it's a decision before execution |
| **No effect without an authorized call, or despite a deny** (I11) | ● | ○ | ● an executed action under a non-`permit` decision is reported, never imported as authorized | ◐ a service's refusal is signed; it is not bound to an AMEP invocation | ○ a DENY is a decision, with no record of whether anything ran |
| **Bound to the exact call that was authorized** (args digest) | ● `invocation_digest`, `args_digest` | ● when `input_hash` equals the invocation's `args_digest`; the `rfc8785-jcs-utf8-v1` layout makes that hold for any argument shape | ● when `decision_attestation.request_hash` hashes the same request | ◐ a reserved document name (`provared.http-request`) can bind a receipt to the call; not yet used by the profile | ◐ `instructionsHash` binds the operator's instructions to the receipt; not used by the profile |
| **A confirmed "nothing ran"** (call statements, section 5.14) | ● the server's signed `not_executed` statement and `effect_count` | ◐ a refusal in the committed output is not imported, but an unsigned record can't confirm non-execution | ◐ `failure` and `network-error` outcomes are not imported; a confirmed non-execution is not a defined outcome | ◐ the service's signed refusal; no count of the effects of a call | ○ |

## What the matrix shows

- **No other format carries evidence for untrusted influence (I4), data release (I5) or adapter interpretation (I3).** Those parts are decided only from AMEP's own evidence: a gateway or host that signs invocations, findings and interpretations.
- **Each format is strong somewhere AMEP's native evidence is not specialized:**
  - Provared: authentication (hybrid post-quantum signatures, passkeys), approvals and observer independence through countersignatures;
  - the OpenID receipts: refusing to treat an action executed under a non-`permit` decision as authorized;
  - AER-1: committed output bytes, and now binding to the call.
  
  The verdict can use all of them.
- **The weakest cell in every format is the "declared" side and the binding to the call.** That's why the AMEP MCP extension (modelcontextprotocol/agents-ig#31) has the gateway sign each invocation and the server bind its receipt to it. AER-1's new `rfc8785-jcs-utf8-v1` layout closes the binding cell for AER-1 from the format's own side.

- **The Delegation Receipt Protocol decides before execution**, so most of its column is ○ by design. Its strength is the decision itself, and its receipt is evidence an AMEP packet could carry. The comparison with its vectors is in `interop/drp/`.

## Corrections

Each row is the AMEP author's reading of a format, through the code that imports it. The authors of these formats are invited to correct their row, by an issue or a pull request, especially where a ◐ or ○ undersells what their records carry.

## Formats without a profile yet

No cells until a profile exists and has been run on the format's own published examples:
- Authorization Receipts for High-Risk Agent Actions (EMILIA, draft-schrock-ep-authorization-receipts). A partial profile covers two of its 21 suites, its receipts and its outcome predicates (`interop/ep/`); a column waits for the rest;
- Notarized Agents (arXiv 2606.04193).
