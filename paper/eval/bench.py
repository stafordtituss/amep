"""Verification cost of the Python reference verifier.

1. Per-vector evaluation time over the conformance suites (signature checks included).
2. Evaluation time and packet size as a delegation chain grows from 1 to 16 hops.

Run from the repository root:  python3 paper/eval/bench.py
"""
from __future__ import annotations

import json
import os
import statistics
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path[:0] = [os.path.join(ROOT, "packages/python/src"), os.path.join(ROOT, "verifier/python")]
from amep_protocol.core import canon, evaluate, verdict  # noqa: E402
from amep_verifier import Signer  # noqa: E402

REPS = 200


def timed(fn, reps=REPS):
    fn()  # warm-up
    ts = []
    for _ in range(reps):
        t = time.perf_counter()
        fn()
        ts.append(time.perf_counter() - t)
    return statistics.median(ts) * 1e3  # ms


def suite_times(d):
    keys = json.load(open(os.path.join(d, "keys.json")))
    out = []
    for sub in ("positive", "must-reject"):
        for f in sorted(os.listdir(os.path.join(d, sub))):
            if f.endswith(".json"):
                v = json.load(open(os.path.join(d, sub, f)))
                st = v.get("state")
                out.append(timed(lambda: verdict(evaluate(v["packet"], keys, state=json.loads(json.dumps(st)) if st else None)), 50))
    return out


def chain_packet(hops):
    I, H, O = Signer("issuer-1", ["issuer"]), Signer("host-1", ["host"]), Signer("observer-1", ["observer"])
    keys = {s.kid: s.public() for s in (I, H, O)}
    claims = lambda depth: {"actions": ["fs.write"], "resources": ["repo:app/src/*"], "data": [], "ceiling": "write_local", "exp": 100, "depth": depth}
    m = I.sign({"id": "m-0", "kind": "mandate", "principal": "user:alice", "claims": claims(hops)})
    ds, parent = [], "m-0"
    for k in range(1, hops + 1):
        ds.append(I.sign({"id": f"d-{k}", "kind": "delegation", "parent": parent, "claims": claims(hops - k)}))
        parent = f"d-{k}"
    a = H.sign({"id": "a-1", "kind": "interpretation", "source": "curated", "adapter": "host_shell", "version": "r9"})
    i = H.sign({"id": "i-1", "kind": "invocation", "authority_ref": parent, "interpretation_ref": "a-1", "t": 10,
                "declared": {"action": "fs.write", "resource": "repo:app/src/x.ts", "effect": "write_local"}})
    e = O.sign({"id": "e-1", "kind": "effect", "invocation": "i-1", "observed_by": "hook:host", "assurance": "L1",
                "executed": {"action": "fs.write", "resource": "repo:app/src/x.ts", "effect": "write_local", "released": [], "t": 11}})
    return {"amep_version": "0.2", "mandates": [m], "delegations": ds, "interpretations": [a], "invocations": [i], "effects": [e]}, keys


def main():
    res = {}
    for name, d in (("core", "vectors"), ("delegation", "interop/w3c-agent-identity/delegation-continuity")):
        ts = suite_times(os.path.join(ROOT, d))
        res[name] = {"n": len(ts), "median_ms": statistics.median(ts), "max_ms": max(ts), "total_ms": sum(ts)}
        print(f"suite {name:10} n={len(ts):3}  median {statistics.median(ts):.3f} ms  max {max(ts):.3f} ms  total {sum(ts):.1f} ms")
    res["chain"] = []
    print("hops  objects  bytes(JCS)  median ms  verdict")
    for hops in (1, 2, 4, 8, 16):
        p, keys = chain_packet(hops)
        r = verdict(evaluate(p, keys))
        assert r.outcome == "preserved", r
        n = sum(len(v) for v in p.values() if isinstance(v, list))
        size = len(canon(p))
        ms = timed(lambda: evaluate(p, keys))
        res["chain"].append({"hops": hops, "objects": n, "bytes": size, "median_ms": ms})
        print(f"{hops:4}  {n:7}  {size:10}  {ms:9.3f}  {r.outcome}")
    json.dump(res, open(os.path.join(os.path.dirname(__file__), "bench-results.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
