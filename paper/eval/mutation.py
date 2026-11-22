"""Mutation analysis of the AMEP conformance suites.

Generates mutants of the reference evaluation core (packages/python/src/amep_protocol/core.py) and runs every
conformance vector against each one. A mutant is killed when at least one vector's verdict (outcome and deciding
invariant) differs from the expected one. Operators:

  CHECK   delete one evaluation check (a _check call, or a result the procedure appends)
  RULE    delete one rejection rule of the claim algebra (a `return False, ...` in narrower, effect_ok, verify_sig)
  BOUND   flip one boundary comparison (< <-> <=, > <-> >=) in a time, ceiling, depth or budget test
  VERDICT fail-open (checks that yield `unresolved` let evaluation continue) and swapped verdict precedence

Run from the repository root:  python3 paper/eval/mutation.py [--json out.json]
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import tokenize
import types

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CORE = os.path.join(ROOT, "packages/python/src/amep_protocol/core.py")
SUITES = {"core": os.path.join(ROOT, "vectors"),
          "delegation": os.path.join(ROOT, "interop/w3c-agent-identity/delegation-continuity")}


def load_suite(d):
    keys = json.load(open(os.path.join(d, "keys.json")))
    out = []
    for sub in ("positive", "must-reject"):
        for f in sorted(os.listdir(os.path.join(d, sub))):
            if f.endswith(".json"):
                v = json.load(open(os.path.join(d, sub, f)))
                out.append((f"{sub}/{f}", v, keys))
    return out


def build(src, name):
    mod = types.ModuleType(name)
    mod.__file__ = CORE
    sys.modules[name] = mod
    exec(compile(src, CORE, "exec"), mod.__dict__)
    return mod


def run(mod, suite):
    fails = []
    for f, v, keys in suite:
        try:
            st = json.loads(json.dumps(v.get("state"))) if v.get("state") is not None else None
            r = mod.verdict(mod.evaluate_text(v["packet_text"], keys, state=st) if "packet_text" in v
                            else mod.evaluate(v["packet"], keys, state=st))
            got = (r.outcome, r.invariant)
        except Exception as e:  # a crash is a detected difference
            got = ("crash", type(e).__name__)
        if got != (v["expect"]["outcome"], v["expect"]["invariant"]):
            fails.append(f)
    return fails


def func_ranges(src):
    """Line ranges (1-based, inclusive) of top-level functions."""
    lines = src.splitlines()
    starts = [(i + 1, re.match(r"def (\w+)", l).group(1)) for i, l in enumerate(lines) if l.startswith("def ")]
    out = {}
    for n, (s, name) in enumerate(starts):
        e = starts[n + 1][0] - 1 if n + 1 < len(starts) else len(lines)
        out[name] = (s, e)
    return out


def mutants(src):
    lines = src.splitlines(keepends=True)
    fr = func_ranges(src)
    in_fn = lambda ln, *names: any(fr[n][0] <= ln <= fr[n][1] for n in names)
    eval_fns = ("evaluate", "_evaluate_invocation")
    # CHECK: one per _check call and per appended violation/unresolved result in the evaluation procedure
    for i, l in enumerate(lines, 1):
        if in_fn(i, *eval_fns) and "_check(" in l and "def _check" not in l:
            inv = re.search(r'"(I\d+)"', l + (lines[i] if i < len(lines) else ""))
            yield ("CHECK", i, inv.group(1) if inv else "?", l.replace("_check(", "(lambda *a, **k: None)(", 1))
        if in_fn(i, "evaluate") and re.search(r'out\.append\(Result\([^)]*"(violated)"', l):
            inv = re.search(r'"(I\d+)"', l)
            yield ("CHECK", i, inv.group(1), l.replace("out.append(", "(lambda *a, **k: None)(", 1))
    # RULE: rejection rules of the claim algebra and the signer-role rule
    for i, l in enumerate(lines, 1):
        if in_fn(i, "narrower", "effect_ok") and "return False" in l:
            lab = {"narrower": "I1 (attenuation)", "effect_ok": "I2/I5 (effect)"}["narrower" if in_fn(i, "narrower") else "effect_ok"]
            yield ("RULE", i, lab, re.sub(r"return False, .*$", "pass", l.rstrip("\n")) + "\n")
        if in_fn(i, "verify_sig") and "wrong role" in l:
            yield ("RULE", i, "I7 (signer role)", l.replace("return False", "pass", 1))
    # BOUND: relational operators in time, ceiling, depth, budget and approval-window tests
    flip = {"<": "<=", "<=": "<", ">": ">=", ">=": ">"}
    for i, l in enumerate(lines, 1):
        if not (in_fn(i, "narrower", "effect_ok", *eval_fns)):
            continue
        if not re.search(r"to_time|CEILING\.index|depth|budget|amount_units|r_t", l):
            continue
        try:
            toks = [t for t in tokenize.generate_tokens(io.StringIO(l.lstrip()).readline) if t.type == tokenize.OP and t.string in flip]
        except tokenize.TokenError:   # a line inside a docstring or a bracketed continuation: no comparison to flip
            continue
        indent = len(l) - len(l.lstrip())
        for t in toks:
            c = indent + t.start[1]
            new = l[:c] + flip[t.string] + l[c + len(t.string):]
            yield ("BOUND", i, f"{t.string}->{flip[t.string]}", new)
    # VERDICT: fail-open (a check whose outcome is `unresolved` lets evaluation continue, as a two-valued checker
    # that treats missing evidence as permission would) and swapped verdict precedence
    for i, l in enumerate(lines, 1):
        if l.strip() == "if cond:" and "def _check" in lines[i - 2]:
            yield ("VERDICT", i, "fail-open", l.replace("if cond:", 'if cond and outcome != "unresolved":'))
        if 'for o in ("violated", "unresolved"):' in l:
            yield ("VERDICT", i, "precedence", l.replace('("violated", "unresolved")', '("unresolved", "violated")'))


def main():
    src = open(CORE).read()
    suites = {k: load_suite(d) for k, d in SUITES.items()}
    base = build(src, "amep_core_base")
    for k, s in suites.items():
        assert not run(base, s), f"unmutated core fails suite {k}"
    lines = src.splitlines(keepends=True)
    results = []
    for n, (op, ln, label, new) in enumerate(mutants(src)):
        mut = "".join(lines[:ln - 1] + [new] + lines[ln:])
        try:
            mod = build(mut, f"amep_core_m{n}")
        except SyntaxError as e:
            print(f"skip invalid mutant at line {ln}: {e}", file=sys.stderr)
            continue
        kills = {k: run(mod, s) for k, s in suites.items()}
        results.append({"op": op, "line": ln, "label": label, "src": lines[ln - 1].strip()[:110],
                        "killed_by_core": kills["core"], "killed_by_delegation": kills["delegation"]})
    by = {}
    for r in results:
        b = by.setdefault(r["op"], {"n": 0, "core": 0, "deleg": 0, "either": 0})
        b["n"] += 1
        b["core"] += bool(r["killed_by_core"])
        b["deleg"] += bool(r["killed_by_delegation"])
        b["either"] += bool(r["killed_by_core"] or r["killed_by_delegation"])
    tot = {k: sum(b[k] for b in by.values()) for k in ("n", "core", "deleg", "either")}
    nc, nd = len(suites["core"]), len(suites["delegation"])
    print(f"{'operator':8} {'mutants':>7} {f'killed(core {nc})':>16} {f'killed(deleg {nd})':>17} {'killed(either)':>15}")
    for op, b in list(by.items()) + [("total", tot)]:
        print(f"{op:8} {b['n']:>7} {b['core']:>16} {b['deleg']:>17} {b['either']:>15}")
    print("\nsurvivors (no vector in either suite detects them):")
    for r in results:
        if not (r["killed_by_core"] or r["killed_by_delegation"]):
            print(f"  {r['op']:7} line {r['line']:>3} [{r['label']}]  {r['src']}")
    if "--json" in sys.argv:
        json.dump({"by_operator": by, "total": tot, "mutants": results}, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)
    survivors = [r for r in results if not (r["killed_by_core"] or r["killed_by_delegation"])
                 and not any(e in r["src"] for e in EQUIVALENT)]
    if "--check" in sys.argv and survivors:
        print(f"\n{len(survivors)} surviving mutant(s) are not known to be equivalent: add a vector that kills each one, "
              "or document why it is equivalent in EQUIVALENT.", file=sys.stderr)
        return 1
    return 0


# Mutants shown to be equivalent for schema-valid input, identified by the source text of the mutated line.
EQUIVALENT = {
    # Depths are non-negative integers (schemas/v0.2/common.json), so a child of a depth-0 parent always fails the
    # strictly-decreasing rule that follows; deleting this rule changes no verdict on valid evidence.
    'if parent["depth"] == 0: return False, "parent may not be delegated (depth 0)"',
    # v0.3: without these two explicit checks the next statement indexes the missing or non-object value and raises,
    # which evaluate() turns into the same unresolved (I7). Kept for clear reasons; vectors cover both paths.
    '_check(not isinstance(v, dict), "unresolved", "I7", "value must be an object", need="value"',
    '_check(v is None, "unresolved", "I7", f"{n[\'id\']} limits this effect but the receipt records no value"',
    # v0.3: an approval with neither digest. Without this check Python indexes the missing effect_digest and raises,
    # which evaluate() turns into the same unresolved (I7); the check is there so that the JavaScript verifier, which
    # would compare against undefined and return violated (I8), agrees. A vector covers it.
    '_check("effect_digest" not in appr, "unresolved", "I7", "approval has no effect_digest or effect_digests"',
}


if __name__ == "__main__":
    sys.exit(main())
