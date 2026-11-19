# Delegation continuity: test materials

| | |
|---|---|
| **Title** | Delegation continuity across agent hops |
| **Authors** | Staford Titus Selvaraj (independent) |
| **Date / version** | 2026-11-17 / 0.1 |
| **Status** | For discussion |
| **Licence** | Apache 2.0 (code and vectors), as in the source repository |

## What it tests

When a human authorizes an agent, and that agent delegates part of the work to a second agent, can a receiver or an auditor show that what the second agent did stayed within what the human authorized?

```
H  did:web:acme.example:people:hr-lead        authorizes
A  did:aria:acme.example:hiring-agent         delegates a narrower scope to
B  did:aria:acme.example:scheduling-agent     which calls
T  service:calendar.acme.example              and T signs what it actually did
```

The scenario extends the group's hiring use case by one delegation hop. Each vector is a signed evidence packet and an expected outcome: `preserved`, `violated` or `unresolved` (the evidence cannot show it either way). The vectors cover the five questions raised on this list in September:

| Question | Vectors |
|---|---|
| Can B prove whose authority it is exercising? | `within-bounds`, `identity-only`, `self-issued-delegation` |
| Which constraints from H's authorization survived? | `delegation-drops-a-deny`, `deny-added-by-delegate`, `delegation-outlives-parent` |
| Did A have authority to re-delegate? | `redelegation-without-right`, `depth-not-decreasing` |
| Did the effective scope expand along the chain? | `delegation-widens-scope`, `delegation-raises-effect-class`, `effect-outside-delegated-scope`, `executed-differs-from-declared` |
| Has any upstream authorization been revoked? | `root-revoked-before-action`, `status-shows-revoked`, `stale-status`, `fresh-status`, `revoked-after-the-action` |

Three further vectors cover required human approval: `approval-bound-to-effect`, `approval-for-a-different-effect` and `approval-replayed`.

There are 20 vectors: 5 in `positive/` and 15 in `must-reject/`. Each file has `name`, `question`, `aria` (the ARIA section or rule it exercises), `expect` and `packet`. `keys.json` holds the public test keys.

## Relation to ARIA

ARIA identifies agents and their principals. These materials test the authority that passes **between** those identities. ARIA §6 plans this but doesn't yet specify it in detail: every hop signed, scope only narrows, the original principal stays traceable, maximum depth 4. ARIA AP 1.0 refuses delegated credentials, so nothing here is an ARIA conformance test today. The materials are offered as input for when sub-agent credentials are specified. See [`USE-CASE.md`](USE-CASE.md) for the mapping and the open questions.

## Run the vectors

The evidence format is AMEP (Agentic Mandate Evidence Protocol), an open specification with an IETF Internet-Draft ([draft-stafordtituss-agentic-mandate-evidence](https://datatracker.ietf.org/doc/draft-stafordtituss-agentic-mandate-evidence/)) and two reference verifiers by the same author, `amep-protocol` on PyPI and `@stafordtituss/amep` on npm. From this folder:

```
npx --package @stafordtituss/amep@0.2.0-alpha.5 amep-protocol check-suite .
```

Or, with no install and no network, open [`verify.html`](verify.html) in a current browser and click "Run all vectors". It embeds the 20 vectors and the JavaScript verifier, and checks signatures with the browser's WebCrypto.

Both verifiers agree with the expected outcome on all 20 vectors. `generate.py` regenerates them from a checkout of https://github.com/stafordtituss/amep.

The keys are deterministic **test** keys derived from public labels. They protect nothing and must not be reused. The folder contains no personal data: every identifier is fictitious.
