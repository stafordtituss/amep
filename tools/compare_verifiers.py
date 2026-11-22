"""Differential check: both reference verifiers must return the same result for every invocation of every vector,
including the deciding invariant, the blamed party and the evidence gaps (spec 10.5), not only the same verdict.

Run from the repo root: python3 tools/compare_verifiers.py
"""
import json
import os
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "packages", "python", "src"))
from amep_protocol.core import evaluate, evaluate_text  # noqa: E402

SUITES = ["vectors", "interop/approval-path-attacks", "interop/w3c-agent-identity/delegation-continuity"]


def python_results():
    out = {}
    for d in SUITES:
        keys = json.load(open(os.path.join(ROOT, d, "keys.json")))
        for sub in ("positive", "must-reject"):
            path = os.path.join(ROOT, d, sub)
            if not os.path.isdir(path):
                continue
            for f in sorted(x for x in os.listdir(path) if x.endswith(".json")):
                v = json.load(open(os.path.join(path, f)))
                st = json.loads(json.dumps(v["state"])) if v.get("state") else None
                res = evaluate_text(v["packet_text"], keys, state=st) if "packet_text" in v else evaluate(v["packet"], keys, state=st)
                out[f"{d}/{sub}/{f}"] = [{"id": r.invocation, "outcome": r.outcome, "invariant": r.invariant,
                                          "blame": r.blame, "gaps": r.gaps} for r in res]
    return out


def main():
    py = python_results()
    js = json.loads(subprocess.run(["node", os.path.join(ROOT, "tools", "js_results.mjs"), *SUITES], cwd=ROOT,
                                   capture_output=True, text=True, check=True).stdout)
    bad = [k for k in py if py[k] != js.get(k)]
    results = sum(len(v) for v in py.values())
    for k in bad[:20]:
        print(f"DIFFER {k}\n  python: {py[k]}\n  js:     {js.get(k)}")
    print(f"{len(py) - len(bad)}/{len(py)} vectors ({results} results): both verifiers agree on outcome, invariant, blame and gaps")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
