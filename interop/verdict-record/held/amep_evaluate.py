"""Held by a checker of draft-wright-verdict-record: the rule "evaluate an AMEP conformance vector" and the formats
of the two files it reads.

The rule is software, so its name binds the implementation: the SHA-256 over the AMEP Python reference verifier's
source files (packages/python/src/amep_protocol/*.py, sorted by path, each line "<sha256 of file>  <path>\\n").
This module refuses to load when the checkout given in AMEP_REPO (default: this repository) has other sources, so a
re-run always runs the code the record names.

Source: https://github.com/stafordtituss/amep, interop/verdict-record/README.md.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

CORE_SHA256 = "e144faa598715d48f2a34930cc7402828f294011d2f082d260b8a0e1e5b59033"
RULE_NAME = "urn:amep:rule:evaluate:core-sha256:" + CORE_SHA256
VECTOR_FORMAT = "urn:amep:format:conformance-vector"
KEYSET_FORMAT = "urn:amep:format:keyset"

SOURCE = {"url": "https://github.com/stafordtituss/amep/tree/main/interop/verdict-record",
          "rule": RULE_NAME,
          "core_files": "packages/python/src/amep_protocol/*.py"}

ROOT = Path(os.environ.get("AMEP_REPO", Path(__file__).resolve().parents[3]))


def core_digest(root: Path) -> str:
    files = sorted((root / "packages" / "python" / "src" / "amep_protocol").glob("*.py"))
    lines = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root).as_posix()}\n" for p in files)
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


if core_digest(ROOT) != CORE_SHA256:
    raise ImportError(f"{ROOT} does not hold the AMEP verifier this rule names ({CORE_SHA256}); refusing to load")

sys.path.insert(0, str(ROOT / "packages" / "python" / "src"))
from amep_protocol.core import evaluate, verdict  # noqa: E402


class AmepEvaluate:
    """Inputs, exactly: vector and keys, each bound to its evidence item without pointer, so the input is the item's
    digest and the rule reads the exact held bytes. vector is an AMEP conformance vector (a JSON object with
    "packet"); keys is AMEP's key set (vectors/keys.json). Both are read with Python's json module, as the verifier
    reads them. The result is the packet verdict of AMEP Section 10.5: {"outcome", "invariant", "blame", "gaps"},
    plus "within_window" when the verdict carries it (Section 5.12.1). A vector with packet_text or carried state is
    outside this rule; an input that is not a held item's digest, or bytes that aren't the stated format, FAIL step 3."""
    NAME = RULE_NAME
    INPUTS = ["keys", "vector"]

    @staticmethod
    def input_problems(values, names):
        if names != AmepEvaluate.INPUTS:
            return ["the rule's inputs are exactly " + ", ".join(AmepEvaluate.INPUTS)]
        return [f"input {n} is not the digest of a held item" for n in AmepEvaluate.INPUTS
                if n in values and not isinstance(values[n], str)]

    @staticmethod
    def rerun(values, ctx):
        items = ctx["items"]
        vector = json.loads(items[values["vector"]]["bytes"].decode("utf-8"))
        keys = json.loads(items[values["keys"]]["bytes"].decode("utf-8"))
        if "packet" not in vector or "state" in vector:
            raise ValueError("the rule covers single-packet vectors without carried state")
        v = verdict(evaluate(vector["packet"], keys))
        out = {"outcome": v.outcome, "invariant": v.invariant, "blame": v.blame, "gaps": list(v.gaps)}
        if getattr(v, "within_window", None):
            out["within_window"] = dict(v.within_window)
        return out


def _json_object(b):
    try:
        doc = json.loads(b.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        return None, f"not JSON: {e}"
    return (doc, None) if isinstance(doc, dict) else (None, "not a JSON object")


class ConformanceVector:
    """An AMEP conformance vector: a JSON object with "name", "expect" and "packet" (or "packet_text")."""
    NAME = VECTOR_FORMAT

    def parses(self, b, ctx):
        return _json_object(b)[0] is not None

    def check_item(self, b, ctx):
        doc, why = _json_object(b)
        if doc is None:
            return (False, why, None)
        ok = "name" in doc and "expect" in doc and ("packet" in doc or "packet_text" in doc)
        return (ok, None if ok else "not an AMEP conformance vector", None)


class KeySet:
    """AMEP's key set: a JSON object from key id to {"kid", "alg", "x", "roles"}."""
    NAME = KEYSET_FORMAT

    def parses(self, b, ctx):
        return _json_object(b)[0] is not None

    def check_item(self, b, ctx):
        doc, why = _json_object(b)
        if doc is None:
            return (False, why, None)
        ok = bool(doc) and all(isinstance(k, dict) and k.get("alg") == "Ed25519" and "x" in k for k in doc.values())
        return (ok, None if ok else "not an AMEP key set", None)


RULES = (AmepEvaluate,)
FORMATS = (ConformanceVector(), KeySet())
