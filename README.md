# AMEP™: Agentic Mandate Evidence Protocol

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24317758.svg)](https://doi.org/10.5281/zenodo.24317758) [![PyPI](https://img.shields.io/pypi/v/amep-protocol)](https://pypi.org/project/amep-protocol/) [![npm](https://img.shields.io/npm/v/@stafordtituss/amep)](https://www.npmjs.com/package/@stafordtituss/amep)

**Status:** draft v0.2.0-draft.4 · **Author and editor:** Staford Titus Selvaraj ([ORCID 0009-0004-8227-7595](https://orcid.org/0009-0004-8227-7595)) · **IETF:** [draft-stafordtituss-agentic-mandate-evidence](https://datatracker.ietf.org/doc/draft-stafordtituss-agentic-mandate-evidence/) · **Paper:** [Preprints.org, doi:10.20944/preprints202611.1865.v1](https://doi.org/10.20944/preprints202611.1865.v1)

AI agents act for people through chains of delegation, tools and adapters. Identity tells you *who* acted, and authorization tells you what a token *allowed*. Neither proves that **what actually happened stayed within what a person authorized**.

AMEP defines portable, signed evidence for that chain, from a person's mandate through delegations, interpretations and invocations to an **independently observed effect**. It also defines a deterministic outcome:

- `preserved`: the effect stayed within authority;
- `violated`: it went beyond, and the result names the broken invariant;
- `unresolved`: evidence is missing, which is never treated as permission.

## Install

| Language | Package | Install |
|---|---|---|
| Python 3.10+ | `amep-protocol` | `pip install --pre amep-protocol` |
| Node.js 20+ | `@stafordtituss/amep` | `npm install @stafordtituss/amep` |
| Any MCP client | `amep-mcp` (MCP server) | `uvx amep-mcp` |

Both include a verifier, a producer SDK (keys, signing, and builders for every AMEP object) and the `amep-protocol` command-line tool:

```
amep-protocol verify packet.json --keys keys.json      # exit 0 preserved, 1 violated, 2 unresolved
amep-protocol keygen --kid issuer-1 --roles issuer,approver --out issuer-1
amep-protocol check-suite vectors/
```

The MCP server exposes the verifier as tools (`verify_packet`, `explain_invariant`, `list_vectors`, `get_vector`, `check_suite`) so that agents and MCP clients can check evidence themselves; see `packages/mcp/README.md`.

See `packages/python/README.md` and `packages/js/README.md`. Published at [amep-protocol on PyPI](https://pypi.org/project/amep-protocol/) and [@stafordtituss/amep on npm](https://www.npmjs.com/package/@stafordtituss/amep); releases are described in `PUBLISHING.md`.

## What's here

| Path | Contents |
|---|---|
| `spec/amep-v0.2.md` | The core specification |
| `spec/bindings/` | AuthZEN, MCP and agent-host bindings |
| `spec/profiles/` | Biscuit, Macaroon, PASETO, UCAN and Verifiable Credential profiles |
| `schemas/` | JSON Schemas (one per object) and CDDL |
| `vectors/` | The conformance suite: positive and must-reject packets (also on Hugging Face: [stafordtituss/amep-conformance](https://huggingface.co/datasets/stafordtituss/amep-conformance)) |
| `packages/python/` | The `amep-protocol` Python package: verifier, SDK, CLI |
| `packages/js/` | The `@stafordtituss/amep` npm package: the same, in JavaScript (independent implementation) |
| `packages/mcp/` | The `amep-mcp` MCP server: the verifier and both conformance suites as MCP tools |
| `verifier/python/` | Conformance-vector generator (uses the Python package) |
| `verifier/typescript/` | Repository CLI for the JavaScript verifier |
| `verifier/browser/` | The JavaScript verifier as an offline web page |
| `tools/` | Schema builder and validators, Appendix B generator, attribution check |

## Check everything

```
python3 -I verifier/python/amep_verifier.py
python3 -I verifier/python/amep_verifier.py --check vectors
node verifier/typescript/amep_verifier.mjs vectors
node verifier/browser/build.mjs && node verifier/browser/test_page.mjs
python3 tools/validate_schemas.py           # uses the jsonschema library too, if installed
python3 -I tools/validate_cddl.py          # needs the cddl tool: gem install cddl
python3 -I tools/vector_index.py --check
python3 -I tools/attribution_check.py
```

GitHub Actions runs all of these on every push and pull request (`.github/workflows/conformance.yml`), and also fails if the committed vectors, schemas or browser page differ from what the generators produce.

The IETF Internet-Draft is in `ietf/`: Markdown source, with XML, text and HTML rendered by kramdown-rfc and xml2rfc.

## What AMEP is not

Not an identity provider, a policy engine or a prompt-injection detector. AMEP binds to OAuth and OpenID AuthZEN for decisions, SCITT for transparency, MCP and A2A for carriage, and OpenTelemetry for tracing.

## Licenses, attribution and trademarks

- Specification text: Community Specification License 1.0 (`LICENSE-SPEC.md`), with `Scope.md` and `Notices.md`. Derivative works must credit the AMEP Working Group, founded and chaired by Staford Titus Selvaraj.
- Code, schemas and vectors: Apache License 2.0 (`LICENSE-CODE`). Redistributions must keep `NOTICE`.
- "AMEP" and "AMEP Conformant" are trademarks of Staford Titus Selvaraj; see `TRADEMARKS.md`. Forks are welcome under a different name.
- To cite AMEP, see `CITATION.cff`.

## Contributing

Questions, vectors, implementations in other languages and research results are all welcome; see [`CONTRIBUTING.md`](CONTRIBUTING.md). Open problems suitable for papers and theses are in [`RESEARCH.md`](RESEARCH.md), and changes are listed in [`CHANGELOG.md`](CHANGELOG.md).

Open an issue, then an `AMEP-Proposal-N` document. Every normative change needs at least one positive and one must-reject vector.

**Implementations.** Python (`amep-protocol`), JavaScript (`@stafordtituss/amep`) and the browser verifier, all by the specification's author. Implementations by others are especially welcome; open an issue and yours will be listed here.
