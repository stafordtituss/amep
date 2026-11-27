"""Generate verdict records (draft-wright-verdict-record, kind check-run) over AMEP conformance vectors, in the vector
format of https://github.com/diggertydog/verdict-record-test-vectors.

    python3 -I interop/verdict-record/gen.py      # writes vectors/*.json and pins the held module's core digest

Each positive record states AMEP's packet verdict for one conformance vector. It cites two files of this repository
exactly as published, by SHA-256: the vector file and vectors/keys.json. Its rule runs the AMEP Python reference
verifier whose sources it names by digest. The negative records state a verdict the re-run doesn't give, or name a
verifier the checker doesn't hold.
"""
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
UPPER = "2026-11-27T20:00:00.000000Z"
ACT = "2026-11-27T18:00:00.000000Z"
VECTOR_FORMAT, KEYSET_FORMAT = "urn:amep:format:conformance-vector", "urn:amep:format:keyset"
SOURCES = [   # (vector file, what it shows)
    ("positive/valid-preserved-flow.json", "preserved"),
    ("must-reject/effect-outside-delegated-scope.json", "violated (I2), blame agent"),
    ("must-reject/self-reported-high-impact-effect.json", "unresolved (I10), the independent observer named as missing"),
    ("must-reject/revoked-between-invocation-and-effect--singletary-case-1.json", "violated (I6): revoked before the effect"),
    ("positive/revoked-mid-action--inside-the-declared-propagation-window.json",
     "preserved, with within_window naming the revocation"),
]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def core_digest():
    files = sorted((ROOT / "packages" / "python" / "src" / "amep_protocol").glob("*.py"))
    lines = "".join(f"{sha(p.read_bytes())}  {p.relative_to(ROOT).as_posix()}\n" for p in files)
    return sha(lines.encode("utf-8"))


def canon(obj):
    """Section 2.1: sorted members, no whitespace, UTF-8, integers only. Every member name here is ASCII."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def main():
    cd = core_digest()
    held = HERE / "held" / "amep_evaluate.py"
    held.write_text(re.sub(r'CORE_SHA256 = "[^"]*"', f'CORE_SHA256 = "{cd}"', held.read_text()), encoding="utf-8")
    sys.path.insert(0, str(ROOT / "packages" / "python" / "src"))
    from amep_protocol import __version__
    from amep_protocol.core import evaluate, verdict
    rule = "urn:amep:rule:evaluate:core-sha256:" + cd
    keys_bytes = (ROOT / "vectors" / "keys.json").read_bytes()
    keys = json.loads(keys_bytes)
    policy = {"citation_depth": 1, "formats": [KEYSET_FORMAT, VECTOR_FORMAT], "inputs_from_evidence_only": True,
              "judgement_kinds": []}

    def result_of(vec):
        v = verdict(evaluate(vec["packet"], keys))
        out = {"outcome": v.outcome, "invariant": v.invariant, "blame": v.blame, "gaps": list(v.gaps)}
        if getattr(v, "within_window", None):
            out["within_window"] = dict(v.within_window)
        return out

    def record(path, vec, vbytes, result, key, rule_name=rule, claim=None):
        stated = f"{result['outcome']}" + (f" ({result['invariant']})" if result["invariant"] != "-" else "")
        return {"v": "verdict-record/1", "kind": "check-run", "key": key, "version": 1, "supersedes": None,
                "writer": "AMEP reference verifier (test vectors)",
                "actor": {"type": "system", "id": "amep-protocol", "model": "amep-protocol",
                          "model_version": f"{__version__}+core-sha256:{cd}"},
                "act_time": ACT,
                "evidence": [{"format": VECTOR_FORMAT, "sha256": sha(vbytes)},
                             {"format": KEYSET_FORMAT, "sha256": sha(keys_bytes)}],
                "check": {"rule": rule_name, "inputs": {"keys": {"evidence": 1}, "vector": {"evidence": 0}},
                          "result": result},
                "body": {"claim": {"text": claim or f"AMEP conformance vector {vec['name']!r} ({path}) evaluates to {stated}"}}}

    out = []
    for n, (path, shows) in enumerate(SOURCES, 1):
        vbytes = (ROOT / "vectors" / path).read_bytes()
        vec = json.loads(vbytes)
        res = result_of(vec)
        if (res["outcome"], res["invariant"]) != (vec["expect"]["outcome"], vec["expect"]["invariant"]):
            raise SystemExit(f"{path}: the verifier disagrees with the vector's own expectation")
        slug = Path(path).stem
        out.append((f"av{n:02d}-{slug}"[:60], f"released: the re-run gives the stated verdict, {shows}", path,
                    canon(record(path, vec, vbytes, res, f"amep-{slug}")), vbytes, {"state": "released", "named": "PASS"}))

    # an01: a stated verdict the re-run doesn't give (claims preserved for an effect outside the delegated scope).
    path = SOURCES[1][0]
    vbytes = (ROOT / "vectors" / path).read_bytes()
    vec = json.loads(vbytes)
    wrong = {"outcome": "preserved", "invariant": "-", "blame": None, "gaps": []}
    out.append(("an01-verdict-not-reproduced", "refused: the re-run gives violated (I2), not the stated preserved", path,
                canon(record(path, vec, vbytes, wrong, "amep-wrong-verdict")), vbytes,
                {"state": "refused", "named": "FAIL at step 3"}))
    # an02: the record names a verifier build the checker doesn't hold, so nothing can be re-run.
    path = SOURCES[0][0]
    vbytes = (ROOT / "vectors" / path).read_bytes()
    vec = json.loads(vbytes)
    other = "urn:amep:rule:evaluate:core-sha256:" + "0" * 64
    out.append(("an02-verifier-build-not-held", "held: the rule names an AMEP verifier build the checker doesn't hold",
                path, canon(record(path, vec, vbytes, result_of(vec), "amep-other-build", rule_name=other)), vbytes,
                {"state": "held", "named": "NOT RUN at step 3"}))

    vdir = HERE / "vectors"
    vdir.mkdir(exist_ok=True)
    for f in vdir.glob("*.json"):
        f.unlink()
    for name, desc, path, rb, vbytes, exp in out:
        doc = {"name": name, "section": "2.1, 4.3", "description": desc, "source": f"vectors/{path}",
               "record_b64": base64.b64encode(rb).decode(), "record_sha256": sha(rb),
               "evidence_items": [{"b64": base64.b64encode(vbytes).decode()}, {"b64": base64.b64encode(keys_bytes).decode()}],
               "upper_time_bound": UPPER, "policy": policy, "policy_sha256": sha(canon(policy)), "expected": exp}
        (vdir / f"{name}.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(f"core sha256 {cd}; wrote {len(out)} vectors")


if __name__ == "__main__":
    main()
