# protect-mcp decision receipts in AMEP

This profile reads protect-mcp's signed decision receipts (ScopeBlind gateway) as AMEP evidence. It was requested and is open for review in [ScopeBlind/scopeblind-gateway#31](https://github.com/ScopeBlind/scopeblind-gateway/issues/31). protect-mcp and its receipt format are Tom Farley's (ScopeBlind). The profile and this run are AMEP's (Staford Titus Selvaraj), with no endorsement implied.

## What a decision receipt is, in AMEP terms

A protect-mcp receipt is an ACTA envelope (draft-farley-acta-signed-receipts). Its payload type is `protectmcp:decision` for both allow and deny. It carries:
- `decision`;
- `reason`, from the gateway log's `reason_code`;
- `policy_digest`;
- `payload_digest.input_hash`;
- a signature: Ed25519 over the RFC 8785 bytes of the payload.

It's the gateway's record of its own decision, made before the tool ran. So the profile:

1. **Authenticates the receipt.** It checks the signature against an issuer key the verifier obtained separately (`--issuer-key`). The `public_key` inside the payload is never used as the trust anchor, and with no key the receipt is rejected.
2. **Binds the receipt to an AMEP invocation by digest.** `payload_digest.input_hash` is SHA-256 over the RFC 8785 bytes of the tool input, the same construction as AMEP's `args_digest`, so a receipt binds to the invocation when the two values are equal. It never binds by guessing.
3. **Yields no AMEP effect.** An allow doesn't show that the tool ran. A deny doesn't show that it didn't: under spec 10.3, only a `not_executed` statement from an observer settles non-execution.
4. **Re-expresses the decision.** It becomes an AMEP pre-execution decision for the bound invocation (allow, or deny with `fail_mode: closed` in enforce mode), so the evaluation applies 10.3 to it. That AMEP decision is signed by the importer, after the ACTA signature has been checked.

## Versions tested

| | Version |
|---|---|
| Quickstart | scopeblind-gateway README at [`95ecaa3`](https://github.com/ScopeBlind/scopeblind-gateway/blob/95ecaa3504d95f43eda61f56ed31e43fbe02a03f/README.md#L57-L98), run verbatim ([`fixtures/quickstart.sh`](fixtures/quickstart.sh)) |
| Packages | `protect-mcp@0.32.5`, `@veritasacta/verify@0.11.0` (installed exactly, `npm install --save-exact --ignore-scripts`) |
| Node.js | v26.13.1 (the quickstart asks for 22) |
| AMEP | this repository at the commit that adds this directory: `amep-conformance import --profile protect-mcp`, with the in-repo `@stafordtituss/amep` core |

**Issuer key:** `deb516bdd67886e150fea0da92946ec1caa9f19d168e349879f02e9695bae78c`. It was taken from `protect-mcp init`'s output when the key was generated, not from a receipt. The private key was not copied here.

The quickstart's own verifier agreed before AMEP ran:
- both original receipts are valid, and so is their chain link;
- the altered copy gives `invalid_signature`.

See [`fixtures/quickstart-verify-output.log`](fixtures/quickstart-verify-output.log), with local paths removed.

## Results

AMEP packet: [`packet.json`](packet.json), with deterministic test keys from [`make-packet.mjs`](make-packet.mjs).
- **Mandate:** the principal allows `repo.read` on `repo:file/*` and `repo.push` on `repo:git/origin/*`. That's deliberately wider than the gateway's starter policy, so both calls are within authority, and the result turns only on what the evidence shows about execution.
- **`i-1`:** the quickstart's `Read {"path":"README.md"}`, effect class `read`.
- **`i-2`:** its `Bash {"command":"git push --force origin main"}`, mapped to `repo.push`, effect class `external_send`.

| Fixture | Signature (expected key) | Binding | AMEP decision | AMEP verdict for the call |
|---|---|---|---|---|
| [`1-allow.json`](fixtures/1-allow.json): `Read`, `cedar_allow` | valid | digest, to `i-1` | allow, pre-execution | **`unresolved`**, I7, gap `receipt`: nothing shows the read ran |
| [`2-deny.json`](fixtures/2-deny.json): `Bash`, `cedar_deny: starter.force-push-main` | valid | digest, to `i-2` | deny, pre-execution, `fail_mode: closed` | **`unresolved`**, I10, gap `independent_observer`: only the gateway says the push didn't run |
| [`3-deny-altered-to-allow.json`](fixtures/3-deny-altered-to-allow.json): fixture 2 with `decision` set to `allow` | **`invalid_signature`** | not used | none | none computed: the record fails its own checks and isn't imported |

These are the results Tom Farley predicted in #31: the first two decisions authenticate, downstream execution stays unresolved for both, and the altered copy fails signature verification.

### Binding and phase (revised after Tom Farley's review of #20)

The digest establishes the **arguments**, not the invocation. So the profile now binds a receipt only under three conditions:
- **The signed marker `payload_digest.canonical` is `"jcs"`.** The pinned `protect-mcp@0.32.5` `sign --input` path signs it; other gateway paths can omit the digest or use another serialization.
- **The receipt's tool maps to the invocation's declared action.**
- **Exactly one candidate matches.** When two calls have the same arguments, only a trusted identifier tells them apart: the invocation's signed `correlation.tool_use_ref` equal to the receipt's signed `request_id`. Otherwise the receipt stays authenticated but unbound.

A pre-execution decision is derived only where the **phase is established**. The payload type `protectmcp:decision` also carries receipts signed after execution (`reason: "post_execution_receipt"`), so the type alone can't establish phase:
- the `cedar_allow` and `cedar_deny` reasons of the `sign --cedar` path count as pre-execution;
- `post_execution_receipt` counts as post-execution;
- any other reason leaves the phase not established.

The constructed fixtures below are **not ScopeBlind output**. Each is a copy of fixture 1 with one field changed, re-signed in the same wire format with a deterministic test key ([`make-constructed.mjs`](make-constructed.mjs)), so that only the rule under test differs.

| Fixture | Against | Binding | AMEP decision |
|---|---|---|---|
| [`4-missing-canonical-marker.json`](fixtures/constructed/4-missing-canonical-marker.json) | `packet.json` | missing: no `canonical: "jcs"` | none |
| [`5-post-execution-receipt.json`](fixtures/constructed/5-post-execution-receipt.json) | `packet.json` | digest, to `i-1` | none: phase is post-execution |
| [`6-allow-resigned.json`](fixtures/constructed/6-allow-resigned.json) (control) | `packet.json` | digest, to `i-1` | allow, pre-execution, as fixture 1 |
| `1-allow.json` | [`packet-repeated.json`](fixtures/constructed/packet-repeated.json): two reads of `README.md` | **ambiguous**, `i-1` or `i-1b` | none: authenticated, unbound |
| `1-allow.json` | [`packet-repeated-correlated.json`](fixtures/constructed/packet-repeated-correlated.json): the same, with `correlation.tool_use_ref` | digest and `request_id`, to `i-1` | allow, pre-execution |

All of these, with fixtures 1 to 3: `sh interop/protect-mcp/run-all.sh`.

To reproduce:

```bash
(cd packages/conformance && npm install)
node interop/protect-mcp/make-packet.mjs
for f in 1-allow 2-deny 3-deny-altered-to-allow; do
  node packages/conformance/bin/amep-conformance.mjs import interop/protect-mcp/fixtures/$f.json --profile protect-mcp \
    --map interop/protect-mcp/toolmap.json --issuer-key deb516bdd67886e150fea0da92946ec1caa9f19d168e349879f02e9695bae78c \
    --packet interop/protect-mcp/packet.json --keys interop/protect-mcp/keys.json
done
```

## Gap report: what AMEP needs that a decision receipt doesn't carry

| Need | Status | Detail |
|---|---|---|
| Origin authentication | checked | Ed25519 over the RFC 8785 payload, against a key obtained separately. |
| What was executed | missing | The receipt precedes execution and carries no result. An effect needs a receipt from the tool side (for example an MCP server's signed receipt bound to the same `args_digest`). |
| Confirmation that a denied call didn't run | missing | Needs a `not_executed` statement from the party that would have executed the call (spec 10.3, 5.14). For a high-impact call it must come from an operator other than the gateway's (spec 12.5, I10). |
| Binding to the authorizing call | digest | `payload_digest.input_hash` equals AMEP's `args_digest` for the same input. |
| The policy the decision followed from | digest only | `policy_digest` names the policy the gateway says it evaluated. Re-deriving the decision would also need the policy text and the evaluation inputs. |
| Canonical action, resource and effect class | from the tool map | `tool_name` and the input are protect-mcp's; their AMEP meaning comes from the deployment's [`toolmap.json`](toolmap.json). |
| Completeness of the receipt log | not established | `previousReceiptHash` detects a removed or reordered link in the supplied chain, not receipts that were never supplied. |

## Found along the way

The JS reference core gave the I10 result for a host-only deny with no gap and a non-null `blame`. The Python core named the gap `independent_observer` correctly. Outcome and invariant were right in both, which is all the vectors compare. Fixed in the same change; see CHANGELOG.
