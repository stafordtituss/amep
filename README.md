# AMEP: Agentic Mandate Evidence Protocol

**Status:** draft v0.2.0-draft.3 · **Author and editor:** Staford Titus Selvaraj

AI agents act for people through chains of delegation, tools and adapters. Identity tells you *who* acted, and authorization tells you what a token *allowed*. Neither proves that **what actually happened stayed within what a person authorized**.

AMEP defines portable, signed evidence for that chain, from a person's mandate through delegations, interpretations and invocations to an **independently observed effect**. It also defines a deterministic outcome:

- `preserved`: the effect stayed within authority;
- `violated`: it went beyond, and the result names the broken invariant;
- `unresolved`: evidence is missing, which is never treated as permission.

## What's here

| Path | Contents |
|---|---|
| `spec/amep-v0.2.md` | The core specification |
| `spec/bindings/` | AuthZEN, MCP and agent-host bindings |
| `spec/profiles/` | Biscuit, Macaroon, PASETO and Verifiable Credential profiles |
| `schemas/` | JSON Schemas (one per object) and CDDL |
| `vectors/` | The conformance suite: positive and must-reject packets |
| `verifier/python/` | Reference verifier and vector generator (Python) |
| `verifier/typescript/` | Independent reference verifier (JavaScript, Node.js CLI) |
| `verifier/browser/` | The same JavaScript verifier as an offline web page |
| `tools/` | Schema builder and validator, Appendix B generator |

## Check everything

```
python3 -I verifier/python/amep_verifier.py
python3 -I verifier/python/amep_verifier.py --check vectors
node verifier/typescript/amep_verifier.mjs vectors
node verifier/browser/build.mjs && node verifier/browser/test_page.mjs
python3 -I tools/validate_schemas.py
python3 -I tools/validate_cddl.py          # needs the cddl tool: gem install cddl
python3 -I tools/vector_index.py --check
```

## What AMEP is not

Not an identity provider, a policy engine or a prompt-injection detector. AMEP binds to OAuth and OpenID AuthZEN for decisions, SCITT for transparency, MCP and A2A for carriage, and OpenTelemetry for tracing.

## Licenses, attribution and trademarks

- Specification text: Community Specification License 1.0 (`LICENSE-SPEC.md`), with `Scope.md` and `Notices.md`. Derivative works must credit the AMEP Working Group, founded and chaired by Staford Titus Selvaraj.
- Code, schemas and vectors: Apache License 2.0 (`LICENSE-CODE`). Redistributions must keep `NOTICE`.
- "AMEP" and "AMEP Conformant" are trademarks of Staford Titus Selvaraj; see `TRADEMARKS.md`. Forks are welcome under a different name.
- To cite AMEP, see `CITATION.cff`.

## Contributing

Open an issue, then an `AMEP-Proposal-N` document. Every normative change needs at least one positive and one must-reject vector.
