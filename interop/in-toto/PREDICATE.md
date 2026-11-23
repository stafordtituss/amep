# Predicate type: AMEP verdict

Type URI: `https://github.com/stafordtituss/amep/verdict/v0.3`

Version: 0.3 (tracks AMEP v0.3.0-draft.1, Section 10.8)

This is the predicate as AMEP defines it, laid out like an in-toto predicate specification so it can be proposed to `in-toto/attestation` under the ITE-9 guidelines.

## Purpose

An AMEP verdict records what a verifier concluded when it checked an AI agent's actions against the authority the agent was given. AMEP (Agentic Mandate Evidence Protocol) is a draft format for the signed evidence of one agent session:
- the mandate a principal granted;
- any delegations and approvals;
- each tool invocation;
- the receipts the tool servers signed for what they executed.

A verifier evaluates that evidence and returns, for every invocation, one of three outcomes:
- **preserved:** the action stayed within its authority;
- **violated:** the evidence shows it went outside;
- **unresolved:** the evidence is not enough to decide either way.

Each result also names the deciding invariant, the party at fault when something was violated (`blame`), and the missing evidence when nothing could be decided (`gaps`).

The predicate carries that conclusion as an attestation about the evidence packet. Anyone who holds the packet and the key set can re-run any conforming verifier and check the record. Anyone who doesn't can rely on its signer, as with any other attestation.

## Use cases

1. **An agent changed a repository.** A coding agent pushes a commit or opens a pull request using tools over MCP. Its session evidence is an AMEP packet. The CI system, or an independent auditor, evaluates the packet and attaches a signed verdict to the commit: "this change was made by actions that stayed within the agent's mandate" (preserved), or "it wrote outside `repo:app/*`; blame: agent" (violated). A policy engine admits the change only with a preserved verdict from a trusted verifier. This is the supply-chain question "was this change made within authority?", asked of an agent instead of a build.
2. **Payments and other irreversible actions.** An agent pays an invoice. The verdict states whether the payment was within the mandate's per-call limit and, if it needed an approval, whether one was present and bound to this exact payment. A finance team archives the signed verdict with the payment record.
3. **Disputes and audits.** Months later, a party asks whether an incident was the agent's fault, the delegating principal's, the host's or the tool server's. The archived verdict gives the answer that was reached at the time and names the evidence it was reached from. Re-running a verifier on the archived packet reproduces it.
4. **Detection.** A security team runs verification over agent sessions after the fact. An `unresolved` verdict with its `gaps` (for example, a missing receipt for invocation `i-7`) tells them what to collect, rather than just "failed".

## Why existing predicates don't cover this

- **SLSA Provenance** describes how an artifact was built. Here the subject is a record of what an agent did, and the claim is a judgement about authority, not a build description.
- **SLSA Verification Summary Attestation (VSA)** is the closest. It says a verifier checked an artifact against a policy and gives PASSED or FAILED. AMEP needs four things VSA doesn't express:
  - a third outcome, `unresolved`. "Not enough evidence" must not read as either a pass or a failure. A missing receipt is a gap, not a violation.
  - per-invocation results, since one session holds many actions with different outcomes;
  - the party at fault (`blame`) and the missing evidence (`gaps`), each from a fixed vocabulary;
  - a digest of the key set the evidence was verified against, without which the outcome isn't reproducible.
- **Test Result** records pass, warn or fail for a test run. It has the same limits as VSA, and the subject would be a test configuration rather than evidence.

- **Simple Verification Result (SVR)** records the properties that passed, and by design doesn't carry what's needed to reproduce the result. It has the same limits as VSA.

The predicates compose. Both reference verifiers also publish the verdict as an SVR (`verify --svr-out`), with the property `AMEP_VERDICT_PRESERVED` when the packet is preserved and none otherwise, for policy engines that only read SVRs. The AMEP verdict carries the detail when the outcome is anything else.

## Prerequisites

- The in-toto Attestation Framework, Statement v1, with DSSE envelopes.
- AMEP v0.3.0-draft.1: [spec/amep-v0.2.md](../../spec/amep-v0.2.md), Sections 10.5, 10.5.1 and 10.8.

## Model

- **Subject:** the evidence packet, identified by the SHA-256 of the exact bytes the verifier evaluated. The name is conventionally `amep-packet`. Hashing bytes rather than a parsed form means a record also covers a packet that doesn't parse, which comes out `unresolved`.
- **Producer:** an AMEP verifier, such as a CI job, an auditor or a gateway, signing with its own key.
- **Consumer:** a policy engine, an archive, or a party re-checking the verdict.

## Schema

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "amep-packet", "digest": { "sha256": "<hex>" } }],
  "predicateType": "https://github.com/stafordtituss/amep/verdict/v0.3",
  "predicate": {
    "packet":   { "sha256": "<hex>" },                       // required; equals the subject digest
    "keyset":   { "sha256": "<hex>" },                       // required
    "verdict":  { "outcome": "<outcome>", "invariant": "<id>", "blame": "<party>" | null, "gaps": [<gap>] },  // required
    "results":  [{ "id": "<invocation id>", "outcome": "...", "invariant": "...", "blame": ..., "gaps": [...] }],  // required
    "verifier": { "name": "<string>", "version": "<string>" } // optional
  }
}
// <outcome>: "preserved" | "violated" | "unresolved"
// <party>:   "agent" | "delegator" | "host" | "transport" | "server"
// <gap>:     { "need": "<need>", "ref": "<id>" }   (needs listed in AMEP Section 10.5.1)
//              signature gaps add "cause": "missing" | "unknown_key" | "role" | "invalid"
```

## Parsing rules

- The payload is the JCS (RFC 8785) form of the statement. Consumers MUST parse it as I-JSON and reject duplicate member names (AMEP Section 12.1).
- Signatures are Ed25519 over the DSSE pre-authentication encoding, under AMEP's strict acceptance rule (Section 12.2). That rule rejects small-order and non-canonical keys and S ≥ L.
- `blame` is non-null only when `outcome` is `violated`, and `gaps` is non-empty only when it is `unresolved`.
- Consumers MUST ignore unknown members of `predicate` and `verifier`. A new outcome, party or need requires a new predicate version.
- **Determinism:** with `verifier` removed, two conforming verifiers given the same packet bytes and key set produce byte-identical predicates.

## Fields

| Field | Type | Required | Meaning |
|---|---|---|---|
| `packet.sha256` | hex string | yes | SHA-256 of the exact packet bytes evaluated. |
| `keyset.sha256` | hex string | yes | SHA-256 of the JCS form of the key set (each key id's public key and roles) the packet was verified against. |
| `verdict.outcome` | string | yes | Packet verdict (AMEP Section 10.5): the first `violated` result, else the first `unresolved` one, else `preserved`. An empty packet is `unresolved`. |
| `verdict.invariant` | string | yes | The deciding invariant, `I1`–`I11`, or `-` when all results are preserved. |
| `verdict.blame` | string or null | yes | The party whose own signed record first departs from authority. |
| `verdict.gaps` | array | yes | Evidence that would let evaluation continue: `{need, ref}`. A gap for a refused signature also carries `cause`: `missing`, `unknown_key`, `role` or `invalid` (AMEP Section 10.5.1). |
| `results[]` | array | yes | One entry per result, in evaluation order. `id` is the invocation id, or `-` for a packet-level result. |
| `verifier` | object | no | The implementation. It's the only member that may differ between conforming verifiers. |

Free-text reasons aren't part of the record, because they differ between implementations.

## Example

[example.statement.json](example.statement.json) is the statement both reference verifiers produce for the conformance vector `must-reject/payment-over-the-per-call-limit-without-approval`. An agent made a payment above the mandate's per-call limit without the approval the mandate requires, so the outcome is violated, the deciding invariant is I2 and the blame falls on the agent. To regenerate it:

```bash
python3 interop/in-toto/make_example.py
```

To sign and check a verdict yourself, with either reference CLI (released in `amep-protocol` 0.3.0a2 and `@stafordtituss/amep` 0.3.0-alpha.2):

```bash
amep-protocol verify packet.json --keys keys.json --verdict-out verdict.dsse.json --sign-with verifier.key --sign-kid verifier-1
```

`tools/verify_verdict.py` and `tools/verify_verdict.mjs` check an envelope. `tools/verdict_roundtrip.py` signs with each CLI and checks each envelope with the other language.

## Implementations

- Python: `amep-protocol` (PyPI), `amep_protocol.verdicts`.
- JavaScript: `@stafordtituss/amep` (npm), `@stafordtituss/amep/verdict`.

`tools/compare_verifiers.py` checks that the two produce byte-identical statements over all 269 AMEP conformance vectors (all three suites). Both implementations are by the same author.

Outside use: in the Verifiable Agent Trust Envelope project, signed verdict envelopes for a lost-response and recovery case are kept under `reference/amep/case-01-lost-response/`. Its maintainer re-ran the pinned Python verifier on them and reported that all five verdicts matched ([VATE PR #138](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/pull/138)).

## Changelog

- 0.3: first version.
