# AMEP™: Agentic Mandate Evidence Protocol

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24317758.svg)](https://doi.org/10.5281/zenodo.24317758) [![PyPI](https://img.shields.io/pypi/v/amep-protocol)](https://pypi.org/project/amep-protocol/) [![npm](https://img.shields.io/npm/v/@stafordtituss/amep)](https://www.npmjs.com/package/@stafordtituss/amep)

**Status:** draft v0.3.0-draft.1 (packages 0.3.0a4) · **Independent implementation:** [zambo-amep-verify](https://github.com/zambodotdev/zambo-amep-verify), 228/228 single-packet core vectors · **Author and editor:** Staford Titus Selvaraj ([ORCID 0009-0004-8227-7595](https://orcid.org/0009-0004-8227-7595)) · **IETF:** [draft-stafordtituss-agentic-mandate-evidence](https://datatracker.ietf.org/doc/draft-stafordtituss-agentic-mandate-evidence/) · **Paper:** [Preprints.org, doi:10.20944/preprints202611.1865.v1](https://doi.org/10.20944/preprints202611.1865.v1)

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
| OpenAI Agents SDK, LangGraph | `amep-agents` | `pip install --pre "amep-agents[openai-agents]"` or `[langgraph]` |

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
| `packages/js/` | The `@stafordtituss/amep` npm package: the same, in JavaScript (written separately from the Python package, by the same author) |
| `packages/mcp/` | The `amep-mcp` MCP server: the verifier and both conformance suites as MCP tools |
| `packages/agents/` | The `amep-agents` package: evidence for every tool call in OpenAI Agents SDK and LangGraph/LangChain agents |
| `verifier/python/` | Conformance-vector generator (uses the Python package) |
| `verifier/typescript/` | Repository CLI for the JavaScript verifier |
| `verifier/browser/` | The JavaScript verifier as an offline web page |
| `packages/conformance/` | `amep-conformance`: runs the suites against any verifier, and imports other receipt formats (AER-1, OpenID action receipts, Provared books) with a gap report |
| `interop/` | Mappings and runs against other work. [`interop/COVERAGE.md`](interop/COVERAGE.md) shows which parts of AMEP's question each receipt format can settle |
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

What AMEP can't show, each limit pinned by a vector or test: [LIMITS.md](LIMITS.md).

## Related work

AMEP evaluates evidence *after* authority has been granted and exercised. Related work, mostly on granting and checking authority *before* an action:

- **Delegation Receipt Protocol** ([draft-nelson-agent-delegation-receipts](https://datatracker.ietf.org/doc/draft-nelson-agent-delegation-receipts/), R. Nelson). A user-signed Authorization Object, anchored before the agent runs and checked before execution. A DRP receipt is a natural mandate input for AMEP.
- **Authenticated Delegation and Authorized AI Agents** ([arXiv:2501.09674](https://arxiv.org/abs/2501.09674), South et al., 2025). Scoped, verifiable delegation credentials for agents, extending OpenID Connect and OAuth 2.0.
- **Infrastructure for AI Agents** ([arXiv:2501.10114](https://arxiv.org/abs/2501.10114), Chan et al., TMLR 2025) and **IDs for AI Systems** ([arXiv:2406.12137](https://arxiv.org/abs/2406.12137), Chan et al., 2024). Attribution and response infrastructure; AMEP's evidence is one form of it.
- **DIF Threat Model for Delegated Authority in AI-Mediated Systems** ([identity.foundation](https://identity.foundation/delegated-authority-threat-model/)) and **DIF Delegated Authority Evaluations** ([identity.foundation](https://identity.foundation/delegated-authority-evaluations/)), Trusted AI Agents Working Group. The threat model argues that delegated authority fails at the moment of action; the evaluations compare OAuth, UCAN, zCaps, KYA-OS, AuthZEN and others.
- **NIST NCCoE, Accelerating the Adoption of Software and AI Agent Identity and Authorization** ([concept paper, 2026](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization)). Identification, authorization, auditing and non-repudiation for agents using existing standards.
- **GNAP** ([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635)). Delegated authorization negotiation across multiple parties.
- **AgentDojo** ([arXiv:2406.13352](https://arxiv.org/abs/2406.13352)) and **CaMeL** ([arXiv:2503.18813](https://arxiv.org/abs/2503.18813)), Debenedetti, Tramèr et al. Prompt-injection evaluation and data-flow-based defenses for agents. A successful injection is an effect outside the user's mandate, which AMEP reports as `violated`.

## Licenses, attribution and trademarks

- Specification text: Community Specification License 1.0 (`LICENSE-SPEC.md`), with `Scope.md` and `Notices.md`. Derivative works must credit the AMEP project and its original author, Staford Titus Selvaraj. (The license calls the project its "Working Group"; AMEP is an open-source project, not a standards-body working group.)
- Code, schemas and vectors: Apache License 2.0 (`LICENSE-CODE`). Redistributions must keep `NOTICE`.
- "AMEP" and "AMEP Conformant" are trademarks of Staford Titus Selvaraj; see `TRADEMARKS.md`. Forks are welcome under a different name.
- To cite AMEP, see `CITATION.cff`.

## Review AMEP

AMEP needs outside scrutiny more than anything else. Three ways to help, all public:

1. **Run it against your own system.** Run the vectors against your implementation or system, publish the results (failures included) in your own repository, and open an [implementation report](https://github.com/stafordtituss/amep/issues/new?template=implementation-report.yml).
2. **Cite it where relevant.** If your Internet-Draft, paper or specification overlaps with AMEP, an informative reference, or a note on where the approaches differ, is welcome.
3. **Review it in public.** Open an [independent technical review](https://github.com/stafordtituss/amep/issues/new?template=independent-review.yml), or comment on an IETF, W3C, DIF or OpenID Foundation list and link the message.

Every review, implementation and citation by others is logged, as written and including critical ones, in [`REVIEWS.md`](REVIEWS.md).

**Independent implementations:** [zambo-amep-verify](https://github.com/zambodotdev/zambo-amep-verify) by Brennan Zambo, written from the specification and vectors alone, agrees with all 228 single-packet core vectors ([#19](https://github.com/stafordtituss/amep/issues/19)). More are welcome: see [#18](https://github.com/stafordtituss/amep/issues/18).

## Contributing

Questions, vectors, implementations in other languages and research results are all welcome; see [`CONTRIBUTING.md`](CONTRIBUTING.md). Open problems suitable for papers and theses are in [`RESEARCH.md`](RESEARCH.md), and changes are listed in [`CHANGELOG.md`](CHANGELOG.md).

Open an issue, then an `AMEP-Proposal-N` document. Every normative change needs at least one positive and one must-reject vector.

**Implementations.** Python (`amep-protocol`), JavaScript (`@stafordtituss/amep`) and the browser verifier, all by the specification's author. **Run by others:** Brennan Zambo ran the conformance import over 12 live AER-1 receipts from the Zambo MCP server, and published the results ([amep#11](https://github.com/stafordtituss/amep/issues/11)). Implementations by others are especially welcome; open an [implementation report](https://github.com/stafordtituss/amep/issues/new?template=implementation-report.yml) and yours will be listed here and in [`REVIEWS.md`](REVIEWS.md).

## Citation

If you use AMEP, its conformance suite or its results in your work, please cite it. GitHub's **Cite this repository** button (from [`CITATION.cff`](CITATION.cff)) gives the same entries.

The specification, conformance suite and verifiers (Zenodo; this DOI always resolves to the latest version):

```bibtex
@software{selvaraj2026amep,
  author    = {Selvaraj, Staford Titus},
  title     = {{AMEP}: Agentic Mandate Evidence Protocol},
  year      = {2026},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.24317758},
  url       = {https://github.com/stafordtituss/amep}
}
```

The IETF Internet-Draft:

```bibtex
@techreport{selvaraj2026amepdraft,
  author      = {Selvaraj, Staford Titus},
  title       = {Continuity Evaluation of Agent Delegation Records},
  type        = {Internet-Draft},
  number      = {draft-stafordtituss-agentic-mandate-evidence-01},
  institution = {Internet Engineering Task Force},
  year        = {2026},
  month       = nov,
  url         = {https://datatracker.ietf.org/doc/draft-stafordtituss-agentic-mandate-evidence/}
}
```

The paper (preprint):

```bibtex
@misc{selvaraj2026ameppaper,
  author = {Selvaraj, Staford Titus},
  title  = {{AMEP}: Verifiable Evidence That Agent Actions Stayed Within Delegated Authority},
  year   = {2026},
  note   = {Preprint},
  doi    = {10.20944/preprints202611.1865.v1}
}
```

## Contact

- **Questions, bugs and proposals:** [open an issue](https://github.com/stafordtituss/amep/issues/new/choose). Public discussion helps everyone who reads the repository later.
- **Reviews and implementation reports:** use the [review](https://github.com/stafordtituss/amep/issues/new?template=independent-review.yml) and [implementation report](https://github.com/stafordtituss/amep/issues/new?template=implementation-report.yml) forms.
- **Standards discussion:** the IETF agent2agent and audit lists, and the W3C Agent Identity Community Group.
- **Security issues in the verifiers:** open a [private security advisory](https://github.com/stafordtituss/amep/security/advisories/new) rather than a public issue.
- **Collaboration:** Staford Titus Selvaraj, Charlemagne Labs · [ORCID 0009-0004-8227-7595](https://orcid.org/0009-0004-8227-7595)
