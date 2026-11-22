"""Cross-implementation check of signed verdicts (spec 10.8) through the two command-line tools.
Each CLI evaluates the same packet and signs its verdict with the same key; each envelope must verify with the other
language's implementation, and the two statements must be identical apart from predicate.verifier, which names each tool.

Run from the repo root: python3 tools/verdict_roundtrip.py
"""
import base64
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PY_SRC = os.path.join(ROOT, "packages", "python", "src")
VECTOR = os.path.join(ROOT, "vectors", "must-reject", "payment-over-the-per-call-limit-without-approval.json")
KEYS = os.path.join(ROOT, "vectors", "keys.json")


def run(cmd, **kw):
    env = dict(os.environ, PYTHONPATH=PY_SRC)
    return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, **kw)


def main():
    d = tempfile.mkdtemp(prefix="amep-roundtrip-")
    packet = os.path.join(d, "packet.json")
    json.dump(json.load(open(VECTOR))["packet"], open(packet, "w"))

    sys.path.insert(0, PY_SRC)
    from amep_protocol import sdk
    k = sdk.Key.generate("verifier-1", ["observer"])
    key_file = os.path.join(d, "verifier-1.key")
    k.save(key_file) if hasattr(k, "save") else open(key_file, "wb").write(k.to_pem())
    pub = os.path.join(d, "pub.json")
    json.dump({k.kid: k.public_entry()["x"]}, open(pub, "w"))

    py_env, js_env = os.path.join(d, "py.env.json"), os.path.join(d, "js.env.json")
    sign = ["--keys", KEYS, "--sign-with", key_file, "--sign-kid", k.kid]
    run([sys.executable, "-m", "amep_protocol.cli", "verify", packet, "--verdict-out", py_env, *sign])
    run(["node", os.path.join("packages", "js", "bin", "amep-protocol.mjs"), "verify", packet, "--verdict-out", js_env, *sign])

    ok = True
    for label, envf, checker in (("Python-signed, checked by JS", py_env, ["node", os.path.join("tools", "verify_verdict.mjs")]),
                                 ("JS-signed, checked by Python", js_env, [sys.executable, os.path.join("tools", "verify_verdict.py")])):
        if not os.path.exists(envf):
            print(f"FAIL {label}: no envelope written"); ok = False; continue
        r = run([*checker, envf, pub])
        print(f"{'ok  ' if r.returncode == 0 else 'FAIL'} {label}: {r.stdout.strip()}{r.stderr.strip()}")
        ok = ok and r.returncode == 0
    if ok:
        # each CLI names itself in predicate.verifier; everything else must be identical
        a = json.loads(base64.b64decode(json.load(open(py_env))["payload"]))
        b = json.loads(base64.b64decode(json.load(open(js_env))["payload"]))
        names = (a["predicate"].pop("verifier", {}).get("name"), b["predicate"].pop("verifier", {}).get("name"))
        same = a == b
        print(("ok   " if same else "FAIL ") + f"signed statements identical apart from the verifier ({names[0]} / {names[1]})")
        ok = same
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
