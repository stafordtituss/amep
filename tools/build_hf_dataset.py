"""Builds the Hugging Face dataset of AMEP conformance vectors in dist/hf-dataset/.

Run from the repository root:  python3 -I tools/build_hf_dataset.py
Upload (needs a Hugging Face account):  hf upload stafordtituss/amep-conformance dist/hf-dataset --repo-type dataset
"""
import json
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "dist", "hf-dataset")
RELEASE = "0.3.2"   # the amep-protocol / @stafordtituss/amep release these rows are pinned to
SUITES = {
    "core": ("vectors", "0.3.4"),
    "approval_path": ("interop/approval-path-attacks", "draft"),
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
  - config_name: approval_path
    data_files: approval_path.jsonl
  - config_name: delegation
    data_files: delegation.jsonl
  - config_name: sequences
    data_files: sequences.jsonl
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
| `core` | {core_n} | The AMEP conformance suite v{core_v}: {core_pos} positive and {core_neg} must-reject vectors. They cover attenuation across delegation, declared versus executed effects, revocation at each effect's own time and propagation windows, clocks of different operators, signer roles and key status, observer independence, operation identity and retries, approvals, quantity limits, audiences, principal confirmation, call statements, orphan effects, and malformed input |
| `approval_path` | {ap_n} | Attacks on agent step-up approval from Kodathala, Pollishetty and Cargill, *Approve What, Exactly?* (arXiv:2610.21063), each as the evidence it leaves behind: post-approval substitution, replay, decoy recipients, amount splitting and others. A draft suite, under review by the paper's authors |
| `delegation` | {del_n} | Delegation continuity across agent hops, built for the W3C Agent Identity Registry Protocol Community Group's hiring scenario (DID-identified agents) |
| `sequences` | {seq_n} | Cross-packet sequences: verifier state carried from one packet to the next, with the expected verdict and carried state after every step |

These rows are pinned to release **{release}** (`pip install amep-protocol=={release}`, `npm i @stafordtituss/amep@{release}`). The core suite's digest, as printed by `amep-conformance verify`, is `{core_digest}`. [EVALUATION.md](https://github.com/stafordtituss/amep/blob/v{release}/EVALUATION.md) records which outside parties have checked what, against which version.

## Fields

| Field | Meaning |
|---|---|
| `name` | Stable vector identifier |
| `description` | What the vector tests |
| `expected_outcome` | `preserved`, `violated` or `unresolved` |
| `expected_invariant` | Deciding invariant (`I1`–`I11`), or `-` when preserved |
| `packet` | The evidence packet, as JSON text. Evaluate it as text: some rows test malformed text (duplicate member names, lone surrogates) |
| `keys` | The public test key set the packet is signed with (JSON string) |
| `state` | Verifier state carried in from earlier packets, when the vector needs it (JSON string or null) |

The `sequences` config has one row per sequence: `name`, `keys`, and `steps` (a JSON string listing each step's `packet`, `expect` and `state_after`). Replay the steps in order, carrying state.

## Use

```python
import json
from datasets import load_dataset
from amep_protocol.core import evaluate_text, verdict   # pip install amep-protocol

for row in load_dataset("stafordtituss/amep-conformance", "core", split="train"):
    state = json.loads(row["state"]) if row["state"] else None
    # evaluate_text parses strictly: some rows test malformed JSON text, which json.loads would accept or alter
    v = verdict(evaluate_text(row["packet"], json.loads(row["keys"]), state=state))
    assert (v.outcome, v.invariant) == (row["expected_outcome"], row["expected_invariant"]), row["name"]
```

Two reference verifiers (Python and JavaScript, written separately by the same author) agree on every row. Because they share an author, that shows consistency, not independence. An independent verifier, zambo-amep-verify, agrees with an earlier version of the core suite; see EVALUATION.md for its exact scope.

## Intended uses

- Testing a new AMEP verifier or producer, in any language.
- Benchmarking tools that claim to audit agent actions: does your tool reach the same verdict?
- Research on agent authorization, delegation and audit evidence.

## Notes

- The keys are deterministic **test** keys derived from public labels. They protect nothing and must not be reused.
- All identifiers (users, agents, resources) are fictitious. The dataset contains no personal data.
- Some vectors are deliberately malformed (for example `malformed-timestamp`, and several `must-reject` vectors with invalid members) and are expected to return `unresolved`.

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
                       # the packet as JSON text: verbatim for the vectors whose defect is in the text itself
                       # (duplicate member names, lone surrogates), which parsing would erase
                       "packet": v["packet_text"] if "packet_text" in v else json.dumps(v["packet"], ensure_ascii=False, separators=(",", ":")),
                       "keys": json.dumps(keys, separators=(",", ":")),
                       "state": json.dumps(v["state"], separators=(",", ":")) if "state" in v else None}


def sequence_rows():
    doc = json.load(open(os.path.join(ROOT, "vectors", "sequences", "operation-state.json"), encoding="utf-8"))
    for seq in doc["sequences"]:
        yield {"name": seq["name"], "keys": json.dumps(doc["keys"], separators=(",", ":")),
               "steps": json.dumps(seq["steps"], ensure_ascii=False, separators=(",", ":"))}


def suite_digest(d):
    import subprocess
    out = subprocess.run(["node", "-e", f"import('./packages/conformance/src/verify.mjs').then(m => console.log(m.loadSuite({json.dumps(d)}).sha256))"],
                         cwd=ROOT, capture_output=True, text=True, check=True)
    return out.stdout.strip()


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
    seqs = list(sequence_rows())
    with open(os.path.join(OUT, "sequences.jsonl"), "w", encoding="utf-8") as fh:
        for r in seqs:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    card = CARD.format(core_n=counts["core"][0], core_v=counts["core"][1], core_pos=counts["core"][2],
                       core_neg=counts["core"][3], ap_n=counts["approval_path"][0], del_n=counts["delegation"][0],
                       seq_n=len(seqs), release=RELEASE, core_digest=suite_digest("vectors"))
    open(os.path.join(OUT, "README.md"), "w", encoding="utf-8").write(card)
    print(f"wrote {OUT}: " + ", ".join(f"{k} {v[0]} rows" for k, v in counts.items()))
    # Check the rows the way the dataset card tells users to: decode the JSON strings and evaluate.
    import sys
    sys.path.insert(0, os.path.join(ROOT, "packages/python/src"))
    from amep_protocol.core import evaluate, evaluate_text, verdict
    for name in SUITES:
        for line in open(os.path.join(OUT, f"{name}.jsonl"), encoding="utf-8"):
            row = json.loads(line)
            state = json.loads(row["state"]) if row["state"] else None
            v = verdict(evaluate_text(row["packet"], json.loads(row["keys"]), state=state))
            assert (v.outcome, v.invariant) == (row["expected_outcome"], row["expected_invariant"]), row["name"]
    for line in open(os.path.join(OUT, "sequences.jsonl"), encoding="utf-8"):
        row = json.loads(line)
        keys, state = json.loads(row["keys"]), {}
        for step in json.loads(row["steps"]):
            v = verdict(evaluate(step["packet"], keys, state=state))
            assert (v.outcome, v.invariant) == (step["expect"]["outcome"], step["expect"]["invariant"]), row["name"]
    print("every row evaluates to its expected verdict, and every sequence step too")


if __name__ == "__main__":
    main()
