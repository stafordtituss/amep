"""Exhaustive check of AMEP's hold and single-use rules (spec 5.8.1, 5.10, 5.14), mirroring formal/AMEPHolds.tla.

The model: an agent issues calls, each naming an operation and, optionally, a single-use approval. The server may
execute any issued call that hasn't been fenced. Evidence arrives in any order: the observer's receipt for an
executed call, the observer's signed "not executed" (which fences the call: it can no longer execute), and a "not
executed" signed only on the actor's side, which the actor may sign whether or not it's true. The verifier sees
every issued call (the completeness assumption, LIMITS.md section A) and whatever evidence has arrived.

Every reachable state is checked, for each configuration, against:
  Sound           when two calls took effect under the same operation or the same approval, the later one is
                  `preserved` only if the earlier one is `violated`: a double use is never left unreported;
  NoFalseAlarm    `violated` only when a call really took effect twice, or a signed statement is false;
  Settles         once every call's outcome is shown (a receipt, or the observer's "not executed"), and nobody
                  lied, nothing is `unresolved`;
  Stable          a `preserved` result stays `preserved` as evidence arrives, unless someone signs a false
                  "not executed" (then the contradiction is `violated`, I11).
Two configurations are expected to fail, and the explorer prints their traces:
  - HighImpact false (a `write_local` call): the actor's own "not executed" counts (spec 5.14, rule 5), so a host
    that lies about its first attempt gets the retry `preserved`. That's the documented limit for low-impact calls,
    and the reason the actor's word doesn't count for high-impact ones.
  - ObserverMayLie: an observer that signs "not executed" and executes anyway, with its receipt withheld, defeats
    Sound. AMEP's soundness rests on the observer's statement being true, which is what VATE's exclusion of the old
    worker provides (VATE case 3). If the receipt surfaces, the contradiction is `violated` (I11).

With --amep, every distinct evidence view is also built as a real packet and evaluated by AMEP's Python verifier,
and the verifier's result for every call must equal the model's.

Run from the repository root:  python3 -I formal/explore.py [--amep]
"""
from __future__ import annotations

import argparse
import itertools
import os
import sys
from collections import deque

NONE = "none"


def model_results(calls, ev, high_impact):
    """The model's verdict for each call, in issue order. calls: tuple of (op, ap); ev: frozenset of (kind, i)."""
    op_done, op_held, ap_used, ap_held, res = set(), set(), set(), set(), []
    for i, (o, a) in enumerate(calls):
        has_r = ("receipt", i) in ev
        stated = ("ne_obs", i) in ev or ("ne_actor", i) in ev
        shown = ("ne_obs", i) in ev or (not high_impact and ("ne_actor", i) in ev)
        if has_r and stated:
            r = "violated"                                      # 5.14 rule 4: equivocation (I11)
        elif has_r and a != NONE and a in ap_used:
            r = "violated"                                      # 5.10: single use (I8)
        elif has_r and o in op_done:
            r = "violated"                                      # 5.8.1 rule 1: executed twice (I2)
        elif has_r and ((a != NONE and a in ap_held) or o in op_held):
            r = "unresolved"                                    # held_outcome
        elif has_r or shown:
            r = "preserved"
        else:
            r = "unresolved"                                    # receipt gap (I7), or I10 for an actor-only statement
        unknown = not has_r and not shown
        if has_r and not stated:                                # an equivocating call is charged by I11, not counted
            op_done.add(o)
            if a != NONE:
                ap_used.add(a)
        if unknown and o not in op_done:
            op_held.add(o)
        if unknown and a != NONE and a not in ap_used:
            ap_held.add(a)
        res.append(r)
    return tuple(res)


def explore(max_calls, ops, aps, high_impact, observer_may_lie):
    """Breadth-first over (calls, executed, fenced, ev). Yields (state, parent) for every reachable state once."""
    init = ((), frozenset(), frozenset(), frozenset())
    seen, queue = {init: None}, deque([init])
    while queue:
        s = queue.popleft()
        calls, executed, fenced, ev = s
        nxt = []
        if len(calls) < max_calls:
            nxt += [(calls + ((o, a),), executed, fenced, ev) for o in ops for a in aps]
        for i in range(len(calls)):
            if i not in executed and i not in fenced:
                nxt.append((calls, executed | {i}, fenced, ev))
            if i in executed:
                nxt.append((calls, executed, fenced, ev | {("receipt", i)}))
            if i not in executed or observer_may_lie:
                nxt.append((calls, executed, fenced | {i}, ev | {("ne_obs", i)}))
            nxt.append((calls, executed, fenced, ev | {("ne_actor", i)}))
        for t in nxt:
            if t not in seen:
                seen[t] = s
                queue.append(t)
    return seen


def lies(executed, ev, high_impact):
    obs = any(k == "ne_obs" and i in executed for k, i in ev)
    actor = any(k == "ne_actor" and i in executed for k, i in ev)
    return obs, actor, obs or (actor and not high_impact)


def double(calls, executed):
    """Pairs (i, j), i < j, of calls that both took effect under the same operation or the same approval."""
    return {(i, j) for i, j in itertools.combinations(range(len(calls)), 2)
            if i in executed and j in executed
            and (calls[i][0] == calls[j][0] or (calls[i][1] != NONE and calls[i][1] == calls[j][1]))}


def check(seen, high_impact):
    failures = {}
    for s, parent in seen.items():
        calls, executed, fenced, ev = s
        res = model_results(calls, ev, high_impact)
        obs_lie, actor_lie, _ = lies(executed, ev, high_impact)
        d = double(calls, executed)
        if any(res[j] == "preserved" and res[i] != "violated" for i, j in d):
            failures.setdefault("Sound", s)
        if "violated" in res and not d and not (obs_lie or actor_lie):
            failures.setdefault("NoFalseAlarm", s)
        complete = all((("receipt", i) in ev) if i in executed else (("ne_obs", i) in ev) for i in range(len(calls)))
        if complete and not (obs_lie or actor_lie) and "unresolved" in res:
            failures.setdefault("Settles", s)
        if parent is not None and not (obs_lie or actor_lie):
            pres = model_results(parent[0], parent[3], high_impact)
            if any(pres[i] == "preserved" and res[i] != "preserved" for i in range(len(pres))):
                failures.setdefault("Stable", s)
    return failures


def trace(seen, s):
    out = []
    while s is not None:
        out.append(s)
        s = seen[s]
    return out[::-1]


def show(s):
    calls, executed, fenced, ev = s
    return (f"calls={[f'{o}/{a}' for o, a in calls]} executed={sorted(executed)} "
            f"evidence={sorted(f'{k}({i})' for k, i in ev)}")


# ---------- the cross-check against AMEP's verifier ----------

def amep_checker(high_impact):
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.join(here, "..")
    sys.path.insert(0, os.path.join(root, "verifier", "python"))
    sys.path.insert(0, os.path.join(root, "packages", "python", "src"))
    import json
    from amep_verifier import Signer
    from amep_protocol.core import approval_digest, digest, evaluate_text

    effect_class = "write_shared" if high_impact else "write_local"
    I = Signer("owner", ["issuer", "approver"])
    H = Signer("host", ["host", "observer"])     # the actor's side, which can also sign call statements
    O = Signer("server", ["observer"])           # the executing server
    keys = {s.kid: s.public() for s in (I, H, O)}
    mandate = I.sign({"id": "m-1", "kind": "mandate", "principal": "urn:example:owner",
                      "claims": {"actions": ["files.write"], "resources": ["store:x/*"], "ceiling": effect_class,
                                 "exp": 100}}, v=2)
    adapter = H.sign({"id": "a-1", "kind": "interpretation", "source": "curated", "adapter": "files", "version": "1"}, v=2)
    body = {"action": "files.write", "resource": "store:x/report", "effect": effect_class, "released": []}
    approvals = {a: I.sign({"id": a, "kind": "approval", "effect_digest": approval_digest({**body, "t": 0}),
                            "presence": "host_ui", "expiry": 90}, v=2) for a in ("a1", "a2")}
    cache = {}

    def results(calls, ev):
        key = (calls, ev)
        if key in cache:
            return cache[key]
        invs, effects, stmts, used_aps = [], [], [], set()
        for i, (o, a) in enumerate(calls):
            inv = {"id": f"i-{i}", "kind": "invocation", "authority_ref": "m-1", "interpretation_ref": "a-1",
                   "actor": "urn:example:agent", "t": 10 + 10 * i, "operation": o,
                   "declared": {"action": "files.write", "resource": "store:x/report", "effect": effect_class}}
            if a != NONE:
                inv["approval_ref"] = a
                used_aps.add(a)
            inv = H.sign(inv, v=2)
            invs.append(inv)
            if ("receipt", i) in ev:
                effects.append(O.sign({"id": f"e-{i}", "kind": "effect", "invocation": inv["id"], "observed_by": "server",
                                       "assurance": "L3", "executed": {**body, "t": 11 + 10 * i},
                                       "invocation_digest": digest(inv)}, v=2))
            for kind, signer, by in (("ne_obs", O, "server"), ("ne_actor", H, "host")):
                if (kind, i) in ev:
                    stmts.append(signer.sign({"id": f"c-{i}-{by}", "kind": "call_statement", "invocation": inv["id"],
                                              "observed_by": by, "disposition": "not_executed", "effect_count": 0,
                                              "t": 12 + 10 * i, "invocation_digest": digest(inv)}, v=2))
        packet = {"amep_version": "0.3", "mandates": [mandate], "delegations": [], "interpretations": [adapter],
                  "approvals": [approvals[a] for a in sorted(used_aps)], "invocations": invs, "effects": effects}
        if stmts:
            packet["call_statements"] = stmts
        res = evaluate_text(json.dumps(packet), keys)
        by_id = {r.invocation: r for r in res}
        out = tuple((by_id[f"i-{i}"].outcome, by_id[f"i-{i}"].invariant, by_id[f"i-{i}"].reason) for i in range(len(calls)))
        cache[key] = out
        return out

    return results


CONFIGS = [  # (name, HighImpact, ObserverMayLie, the properties expected to hold)
    ("high-impact, honest observer", True, False, {"Sound", "NoFalseAlarm", "Settles", "Stable"}),
    ("low-impact, honest observer", False, False, {"NoFalseAlarm", "Settles", "Stable"}),
    ("high-impact, observer may lie", True, True, {"NoFalseAlarm", "Settles"}),
]


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--calls", type=int, default=3)
    p.add_argument("--amep", action="store_true", help="also compare every evidence view with AMEP's Python verifier")
    args = p.parse_args()
    ops, aps = ("o1", "o2"), (NONE, "a1")
    bad = 0
    for name, hi, lie, expect in CONFIGS:
        seen = explore(args.calls, ops, aps, hi, lie)
        failures = check(seen, hi)
        held = sorted({"Sound", "NoFalseAlarm", "Settles", "Stable"} - set(failures))
        print(f"{name}: {len(seen)} states; hold: {', '.join(held)}"
              + (f"; fail: {', '.join(sorted(failures))}" if failures else ""))
        for prop in sorted(set(failures) & expect):
            bad += 1
            print(f"  UNEXPECTED: {prop} fails:")
            for s in trace(seen, failures[prop]):
                print("    " + show(s))
        for prop in sorted(set(failures) - expect):
            print(f"  expected counterexample to {prop}:")
            for s in trace(seen, failures[prop]):
                print("    " + show(s), "->", model_results(s[0], s[3], hi))
        if args.amep:
            amep = amep_checker(hi)
            views = {(s[0], s[3]) for s in seen}
            diffs = [(c, e) for c, e in views if tuple(r[0] for r in amep(c, e)) != model_results(c, e, hi)]
            print(f"  AMEP's verifier on {len(views)} evidence views: "
                  + ("agrees with the model on every call" if not diffs else f"{len(diffs)} differ"))
            for c, e in sorted(diffs, key=lambda x: (len(x[0]), len(x[1])))[:5]:
                bad += 1
                print(f"    calls={[f'{o}/{a}' for o, a in c]} evidence={sorted(f'{k}({i})' for k, i in e)}")
                print(f"      model {model_results(c, e, hi)}")
                print(f"      AMEP  {amep(c, e)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
