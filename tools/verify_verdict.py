"""Check a signed AMEP verdict (a DSSE envelope over an in-toto statement, spec 10.8) with the Python implementation.
Usage: python3 tools/verify_verdict.py ENVELOPE.json PUBLIC_KEYS.json   (PUBLIC_KEYS: {"keyid": "<64 hex>"})
Prints the verdict and exits 0 when a signature verifies, 1 otherwise."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "packages", "python", "src"))
from amep_protocol.verdicts import verify_envelope  # noqa: E402

try:
    stmt = verify_envelope(json.load(open(sys.argv[1])), json.load(open(sys.argv[2])))
except ValueError as e:
    print(f"not verified: {e}")
    sys.exit(1)
v = stmt["predicate"]["verdict"]
print(f"verified: {v['outcome']} {v['invariant']} (packet sha256 {stmt['subject'][0]['digest']['sha256'][:16]}...)")
