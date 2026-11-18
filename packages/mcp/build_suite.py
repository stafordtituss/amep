"""Bundles the conformance suites into src/amep_mcp/data/suite.json, so the server works without a checkout.

Run from the repository root:  python3 -I packages/mcp/build_suite.py
Re-run whenever vectors/ or the delegation suite changes; `--check` exits 1 if the bundle is out of date.
"""
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(ROOT, "packages/mcp/src/amep_mcp/data/suite.json")
SUITES = {
    "core": ("vectors", "0.2.1", "AMEP conformance suite"),
    "delegation": ("interop/w3c-agent-identity/delegation-continuity", "0.1",
                   "Delegation continuity across agent hops (W3C Agent Identity Registry Protocol CG)"),
}


def load(d):
    keys = json.load(open(os.path.join(ROOT, d, "keys.json"), encoding="utf-8"))
    vectors = []
    for sub in ("positive", "must-reject"):
        for f in sorted(os.listdir(os.path.join(ROOT, d, sub))):
            if not f.endswith(".json"):
                continue
            v = json.load(open(os.path.join(ROOT, d, sub, f), encoding="utf-8"))
            row = {"name": f[:-5], "description": v.get("name", ""), "expect": v["expect"], "packet": v["packet"]}
            for extra in ("question", "aria", "state"):
                if extra in v:
                    row[extra] = v[extra]
            vectors.append(row)
    return keys, vectors


def build():
    out = {"suites": {}}
    for name, (d, version, title) in SUITES.items():
        keys, vectors = load(d)
        out["suites"][name] = {"title": title, "version": version, "keys": keys, "vectors": vectors}
    return json.dumps(out, indent=None, separators=(",", ":"), ensure_ascii=False, sort_keys=True) + "\n"


if __name__ == "__main__":
    text = build()
    if "--check" in sys.argv:
        current = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
        if current != text:
            print("packages/mcp/src/amep_mcp/data/suite.json is out of date; run packages/mcp/build_suite.py", file=sys.stderr)
            sys.exit(1)
        print("suite bundle is up to date")
        sys.exit(0)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    open(OUT, "w", encoding="utf-8").write(text)
    n = {k: len(v["vectors"]) for k, v in json.loads(text)["suites"].items()}
    print(f"wrote {OUT} ({n}, {len(text) // 1024} KB)")
