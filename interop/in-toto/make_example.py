"""Regenerates example.statement.json from a conformance vector: the statement both reference verifiers produce for
the must-reject vector `payment-over-the-per-call-limit-without-approval`. Run from the repo root."""
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
sys.path.insert(0, os.path.join(ROOT, "packages", "python", "src"))
from amep_protocol import evaluate_text, verdicts  # noqa: E402

v = json.load(open(os.path.join(ROOT, "vectors", "must-reject", "payment-over-the-per-call-limit-without-approval.json")))
keys = json.load(open(os.path.join(ROOT, "vectors", "keys.json")))
data = json.dumps(v["packet"]).encode()
st = verdicts.statement(data, keys, evaluate_text(data.decode(), keys), {"name": "amep-protocol", "version": "0.3.1"})
json.dump(st, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "example.statement.json"), "w"), indent=2)
print(json.dumps(st, indent=2))
