"""Validates every conformance vector (and keys.json) against schemas/v0.2/*.json.

Uses a small built-in validator for the JSON Schema 2020-12 keywords the AMEP schemas use, so it runs with no
dependencies. If the `jsonschema` package is installed it is used as well, as an independent second check.
Run from the repo root: python3 -I tools/validate_schemas.py
"""
import json
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SDIR = os.path.join(ROOT, "schemas", "v0.2")
SCHEMAS = {f: json.load(open(os.path.join(SDIR, f))) for f in os.listdir(SDIR) if f.endswith(".json")}
# Vectors that are deliberately not schema-valid (they test the verifier's handling of malformed input).
EXPECTED_INVALID = {"must-reject/malformed-timestamp.json"}

TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def is_type(v, t):
    if t == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    return isinstance(v, TYPES[t])


def resolve(ref, doc):
    file, _, frag = ref.partition("#")
    target = SCHEMAS[file] if file else doc
    for part in [p for p in frag.split("/") if p]:
        target = target[part]
    return target, (SCHEMAS[file] if file else doc)


def validate(v, s, doc, path="$"):
    errs = []
    if "$ref" in s:
        sub, sub_doc = resolve(s["$ref"], doc)
        errs += validate(v, sub, sub_doc, path)
    if "type" in s and not is_type(v, s["type"]):
        return errs + [f"{path}: expected {s['type']}"]
    if "const" in s and v != s["const"]:
        errs.append(f"{path}: expected {s['const']!r}")
    if "enum" in s and v not in s["enum"]:
        errs.append(f"{path}: {v!r} not in {s['enum']}")
    if "anyOf" in s and not any(not validate(v, alt, doc, path) for alt in s["anyOf"]):
        errs.append(f"{path}: matches none of anyOf")
    if isinstance(v, str):
        if "pattern" in s and not re.search(s["pattern"], v):
            errs.append(f"{path}: {v!r} does not match {s['pattern']}")
        if len(v) < s.get("minLength", 0):
            errs.append(f"{path}: too short")
    if is_type(v, "number") and "minimum" in s and v < s["minimum"]:
        errs.append(f"{path}: below minimum")
    if isinstance(v, list):
        if len(v) < s.get("minItems", 0):
            errs.append(f"{path}: too few items")
        if "items" in s:
            for i, x in enumerate(v):
                errs += validate(x, s["items"], doc, f"{path}[{i}]")
    if isinstance(v, dict):
        for r in s.get("required", []):
            if r not in v:
                errs.append(f"{path}: missing {r}")
        props, pats = s.get("properties", {}), s.get("patternProperties", {})
        for k, x in v.items():
            if k in props:
                errs += validate(x, props[k], doc, f"{path}.{k}")
                continue
            matched = [p for p in pats if re.search(p, k)]
            for p in matched:
                errs += validate(x, pats[p], doc, f"{path}.{k}")
            if not matched and "additionalProperties" in s:
                ap = s["additionalProperties"]
                if ap is False:
                    errs.append(f"{path}: unexpected member {k!r}")
                elif isinstance(ap, dict):
                    errs += validate(x, ap, doc, f"{path}.{k}")
    return errs


def library_validators():
    """The independent `jsonschema` library (Draft 2020-12), if installed: returns (packet_validator, keyset_validator)."""
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
    except ImportError:
        return None
    registry = Registry().with_resources([(s["$id"], Resource.from_contents(s)) for s in SCHEMAS.values()])
    return (Draft202012Validator(SCHEMAS["packet.json"], registry=registry),
            Draft202012Validator(SCHEMAS["keyset.json"], registry=registry))


def main():
    bad = 0
    lib = library_validators()
    keys = json.load(open(os.path.join(ROOT, "vectors", "keys.json")))
    for e in validate(keys, SCHEMAS["keyset.json"], SCHEMAS["keyset.json"]):
        print("keys.json:", e); bad += 1
    if lib:
        for e in lib[1].iter_errors(keys):
            print("keys.json (jsonschema):", e.message); bad += 1
    n = 0
    for sub in ("positive", "must-reject"):
        for f in sorted(os.listdir(os.path.join(ROOT, "vectors", sub))):
            if not f.endswith(".json"):
                continue
            n += 1
            name = f"{sub}/{f}"
            packet = json.load(open(os.path.join(ROOT, "vectors", sub, f)))["packet"]
            errs = validate(packet, SCHEMAS["packet.json"], SCHEMAS["packet.json"])
            lib_errs = [e.message for e in lib[0].iter_errors(packet)] if lib else None
            if lib is not None and bool(errs) != bool(lib_errs):   # the two validators must agree on every vector
                bad += 1
                print(f"{name}: validators disagree (built-in: {errs[:2]}, jsonschema: {lib_errs[:2]})")
                continue
            if name in EXPECTED_INVALID:
                if not errs:
                    print(f"{name}: expected schema errors, found none"); bad += 1
            elif errs:
                bad += 1
                print(name, *errs[:5], sep="\n  ")
    which = "built-in validator and jsonschema (agreeing)" if lib else "built-in validator only (`jsonschema` not installed)"
    print(f"schema check: {n - bad}/{n} vectors as expected ({len(EXPECTED_INVALID)} deliberately invalid), keys.json checked; {which}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
