"""Builds the Hugging Face dataset of AMEP conformance vectors in dist/hf-dataset/.

Run from the repository root:  python3 -I tools/build_hf_dataset.py
Upload (needs a Hugging Face account):  hf upload stafordtituss/amep-conformance dist/hf-dataset --repo-type dataset
"""
import json
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "dist", "hf-dataset")
SUITES = {
    "core": ("vectors", "0.2.3"),
    "delegation": ("interop/w3c-agent-identity/delegation-continuity", "0.1"),
}

CARD = """---
license: apache-2.0
pretty_name: AMEP conformance vectors
tags:
  - ai-agents
  - agent-security
  - authorization
  - delegation
  - audit
  - conformance-testing
  - model-context-protocol
task_categories:
  - other
size_categories:
  - n<1K
configs:
  - config_name: core
    data_files: core.jsonl
    default: true
  - config_name: delegation
    data_files: delegation.jsonl
---

# AMEP conformance vectors

Signed evidence packets, each with the verdict a conforming verifier must return, for the **Agentic Mandate Evidence Protocol (AMEP)**: an open specification for proving that actions taken by AI agents stayed within the authority a person delegated.

Each packet holds signed objects for one chain of agent activity:
- a person's mandate;
- delegations to sub-agents;
- the invocation an agent declared;
- an independently observed receipt of what was actually executed;
- optionally, approvals and revocations.

A verifier evaluates the packet and returns one of three outcomes:
- `preserved`;
- `violated`, naming one of eleven invariants (I1 to I11);
- `unresolved`, meaning evidence is missing, which is never treated as permission.

## Configurations

| Config | Rows | Contents |
|---|---|---|
| `core` | {core_n} | The AMEP conformance suite v{core_v}: {core_pos} positive and {core_neg} must-reject vectors, covering attenuation, declared-vs-executed drift, revocation, signer roles, approval replay, data release, guardrail tampering, self-reported effects, orphan effects and numbers outside the I-JSON safe range |
| `delegation` | {del_n} | Delegation continuity across agent hops, built for the W3C Agent Identity Registry Protocol Community Group's hiring scenario (DID-identified agents) |

## Fields

| Field | Meaning |
|---|---|
| `name` | Stable vector identifier |
| `description` | What the vector tests |
| `expected_outcome` | `preserved`, `violated` or `unresolved` |
| `expected_invariant` | Deciding invariant (`I1`–`I11`), or `-` when preserved |
| `packet` | The evidence packet (JSON string) |
| `keys` | The public test key set the packet is signed with (JSON string) |
| `state` | Verifier state carried in from earlier packets, when the vector needs it (JSON string or null) |

## Use

```python
import json
from datasets import load_dataset
from amep_protocol.core import evaluate, verdict   # pip install --pre amep-protocol

for row in load_dataset("stafordtituss/amep-conformance", "core", split="train"):
    state = json.loads(row["state"]) if row["state"] else None
    v = verdict(evaluate(json.loads(row["packet"]), json.loads(row["keys"]), state=state))
    assert (v.outcome, v.invariant) == (row["expected_outcome"], row["expected_invariant"]), row["name"]
```

Two reference verifiers (Python and JavaScript, written separately by the same author) agree on every row. Mutation analysis of the reference evaluator kills every non-equivalent mutant with this suite.

## Intended uses

- Testing a new AMEP verifier or producer, in any language.
- Benchmarking tools that claim to audit agent actions: does your tool reach the same verdict?
- Research on agent authorization, delegation and audit evidence.

## Notes

- The keys are deterministic **test** keys derived from public labels. They protect nothing and must not be reused.
- All identifiers (users, agents, resources) are fictitious. The dataset contains no personal data.
- One vector (`malformed-timestamp`) is deliberately malformed.

## Source and citation

- Specification, verifiers and generator: https://github.com/stafordtituss/amep
- IETF Internet-Draft: draft-stafordtituss-agentic-mandate-evidence
- Archive: doi:10.5281/zenodo.24317758

```bibtex
@misc{{selvaraj2026amep,
  author = {{Selvaraj, Staford Titus}},
  title = {{AMEP: Agentic Mandate Evidence Protocol}},
  year = {{2026}},
  doi = {{10.5281/zenodo.24317758}}
}}
```
"""


def rows(d):
    keys = json.load(open(os.path.join(ROOT, d, "keys.json"), encoding="utf-8"))
    for sub in ("positive", "must-reject"):
        for f in sorted(os.listdir(os.path.join(ROOT, d, sub))):
            if f.endswith(".json"):
                v = json.load(open(os.path.join(ROOT, d, sub, f), encoding="utf-8"))
                yield {"name": f[:-5], "description": v.get("name", ""),
                       "expected_outcome": v["expect"]["outcome"], "expected_invariant": v["expect"]["invariant"],
                       "packet": json.dumps(v["packet"], ensure_ascii=False, separators=(",", ":")),
                       "keys": json.dumps(keys, separators=(",", ":")),
                       "state": json.dumps(v["state"], separators=(",", ":")) if "state" in v else None}


def main():
    os.makedirs(OUT, exist_ok=True)
    counts = {}
    for name, (d, version) in SUITES.items():
        data = list(rows(d))
        with open(os.path.join(OUT, f"{name}.jsonl"), "w", encoding="utf-8") as fh:
            for r in data:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        pos = sum(r["expected_outcome"] == "preserved" for r in data)
        counts[name] = (len(data), version, pos, len(data) - pos)
    card = CARD.format(core_n=counts["core"][0], core_v=counts["core"][1], core_pos=counts["core"][2],
                       core_neg=counts["core"][3], del_n=counts["delegation"][0])
    open(os.path.join(OUT, "README.md"), "w", encoding="utf-8").write(card)
    print(f"wrote {OUT}: " + ", ".join(f"{k} {v[0]} rows" for k, v in counts.items()))
    # Check the rows the way the dataset card tells users to: decode the JSON strings and evaluate.
    import sys
    sys.path.insert(0, os.path.join(ROOT, "packages/python/src"))
    from amep_protocol.core import evaluate, verdict
    for name in SUITES:
        for line in open(os.path.join(OUT, f"{name}.jsonl"), encoding="utf-8"):
            row = json.loads(line)
            state = json.loads(row["state"]) if row["state"] else None
            v = verdict(evaluate(json.loads(row["packet"]), json.loads(row["keys"]), state=state))
            assert (v.outcome, v.invariant) == (row["expected_outcome"], row["expected_invariant"]), row["name"]
    print("every row evaluates to its expected verdict")


if __name__ == "__main__":
    main()
