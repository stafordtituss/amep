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
from amep_protocol.core import canon, evaluate, evaluate_text  # noqa: E402
from amep_protocol.verdicts import statement  # noqa: E402

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


def statements():
    """Both verifiers evaluate the same packet bytes and must produce byte-identical verdict statements (spec 10.8)."""
    import hashlib
    import tempfile
    tmp = tempfile.mkdtemp(prefix="amep-stmt-")
    manifest, mine = {}, {}
    for d in SUITES:
        keys_path = os.path.join(ROOT, d, "keys.json")
        keys = json.load(open(keys_path))
        for sub in ("positive", "must-reject"):
            path = os.path.join(ROOT, d, sub)
            if not os.path.isdir(path):
                continue
            for f in sorted(x for x in os.listdir(path) if x.endswith(".json")):
                v = json.load(open(os.path.join(path, f)))
                text = v["packet_text"] if "packet_text" in v else json.dumps(v["packet"], ensure_ascii=False)
                name = f"{d}/{sub}/{f}"
                pf = os.path.join(tmp, f"{len(manifest)}.json")
                open(pf, "w", encoding="utf-8", errors="surrogatepass").write(text)
                data = open(pf, "rb").read()
                st = json.loads(json.dumps(v["state"])) if v.get("state") else None
                res = evaluate_text(data.decode("utf-8", "surrogatepass"), keys, state=json.loads(json.dumps(st)) if st else None)
                mine[name] = hashlib.sha256(canon(statement(data, keys, res))).hexdigest()
                manifest[name] = {"packet": pf, "keys": keys_path, "state": st}
    mf = os.path.join(tmp, "manifest.json")
    json.dump(manifest, open(mf, "w"))
    js = json.loads(subprocess.run(["node", os.path.join(ROOT, "tools", "js_statements.mjs"), mf], cwd=ROOT,
                                   capture_output=True, text=True, check=True).stdout)
    return mine, js


def main():
    py = python_results()
    js = json.loads(subprocess.run(["node", os.path.join(ROOT, "tools", "js_results.mjs"), *SUITES], cwd=ROOT,
                                   capture_output=True, text=True, check=True).stdout)
    bad = [k for k in py if py[k] != js.get(k)]
    results = sum(len(v) for v in py.values())
    for k in bad[:20]:
        print(f"DIFFER {k}\n  python: {py[k]}\n  js:     {js.get(k)}")
    print(f"{len(py) - len(bad)}/{len(py)} vectors ({results} results): both verifiers agree on outcome, invariant, blame and gaps")
    sp, sj = statements()
    sbad = [k for k in sp if sp[k] != sj.get(k)]
    for k in sbad[:10]:
        print(f"STATEMENT DIFFERS {k}")
    print(f"{len(sp) - len(sbad)}/{len(sp)} vectors: both verifiers produce byte-identical verdict statements")
    return 1 if bad or sbad else 0


if __name__ == "__main__":
    sys.exit(main())
