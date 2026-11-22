"""Validates every conformance vector packet, and vectors/keys.json, against schemas/amep-v0.2.cddl using the
`cddl` tool (Ruby gem: gem install cddl). Run from the repo root: python3 -I tools/validate_cddl.py [path-to-cddl-tool]
"""
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SCHEMA = os.path.join(ROOT, "schemas", "amep-v0.2.cddl")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from validate_schemas import EXPECTED_INVALID  # noqa: E402  (one list: both schema languages must agree)


def find_tool():
    if len(sys.argv) > 1:
        return sys.argv[1]
    found = shutil.which("cddl") or next(iter(sorted(glob.glob(os.path.expanduser("~/.gem/ruby/*/bin/cddl")))), None)
    if not found:
        sys.exit("cddl tool not found: gem install cddl, or pass its path")
    return found


def valid(tool, schema, instance) -> tuple[bool, str]:
    r = subprocess.run([tool, schema, "validate", instance], capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def main():
    tool, bad, n = find_tool(), 0, 0
    with tempfile.TemporaryDirectory() as tmp:
        # keys.json is validated against the keyset rule, which must be the first rule for the tool
        keyset_schema = os.path.join(tmp, "keyset.cddl")
        with open(keyset_schema, "w") as f:
            f.write("root = keyset\n" + open(SCHEMA).read())
        ok, msg = valid(tool, keyset_schema, os.path.join(ROOT, "vectors", "keys.json"))
        if not ok:
            bad += 1; print("keys.json:", msg[:400])
        for sub in ("positive", "must-reject"):
            for f in sorted(os.listdir(os.path.join(ROOT, "vectors", sub))):
                if not f.endswith(".json"):
                    continue
                n += 1
                name = f"{sub}/{f}"
                doc = json.load(open(os.path.join(ROOT, "vectors", sub, f), encoding="utf-8"))
                if "packet_text" in doc:   # text vectors test the parser, not the data model
                    n -= 1
                    continue
                packet = os.path.join(tmp, "packet.json")
                with open(packet, "w", encoding="utf-8") as out:
                    json.dump(doc["packet"], out, ensure_ascii=False)
                ok, msg = valid(tool, SCHEMA, packet)
                if name in EXPECTED_INVALID:
                    if ok:
                        bad += 1; print(f"{name}: expected CDDL errors, found none")
                elif not ok:
                    bad += 1; print(f"{name}: {msg[:400]}")
    print(f"CDDL check: {n - bad}/{n} vectors as expected ({len(EXPECTED_INVALID)} deliberately invalid), keys.json checked")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
