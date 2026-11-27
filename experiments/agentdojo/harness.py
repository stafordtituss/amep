"""AMEP evidence over AgentDojo: which successful prompt injections does an evidence audit catch, and how does the
answer depend on how specific the principal's mandate is?

Oracle-trace experiment (no LLM). For every (user task, injection task) pair in AgentDojo v1.2.2:
  * honest trace       = the user task's ground-truth tool calls;
  * compromised trace  = the same calls followed by the injection task's ground-truth calls, i.e. an agent that did
                         its job *and* obeyed the injection (the worst case AgentDojo scores as a successful attack).
Every call is executed for real in the AgentDojo environment. AgentDojo's own `security` check confirms whether the
injection's goal was achieved. Each governed call produces a host-signed invocation and an observer-signed receipt
(amep_agents.EvidenceRecorder), and the packet is evaluated against a mandate derived at one of three granularities:

  effect-scoped  any read; side-effecting actions only on the objects the user task touches (as specific as the task)
  tool-scoped    any read; side-effecting actions only with the tools the user task uses, on any object
  suite-wide     every tool of the suite on any object (what most deployments grant today)

The mandate is derived from the user task's ground truth, so effect-scoped is an upper bound on what a specific
mandate can achieve, and suite-wide shows the floor. Injections whose goal is only the model's text output (no tool
call) are outside what evidence of actions can see; they are counted separately.

Variants (on the honest traces, to show the other evidence checks):
  lying-tool     the tool executes against a different object than declared       -> expect violated (I2)
  self-reported  the agent's host signs its own receipts (no independent observer) -> expect unresolved (I10)
  failed-tool    the tool fails and returns no receipt                              -> expect unresolved (I7)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites
from amep_protocol import sdk
from amep_agents import Effect, EvidenceRecorder

EXP = "2030-01-01T00:00:00Z"
ISSUER = sdk.Key.generate("issuer-1", ["issuer"])
HOST = sdk.Key.generate("host-1", ["host"])
OBSERVER = sdk.Key.generate("tool-runtime-1", ["observer"])
HOST_AS_OBSERVER = sdk.Key.generate("host-1-self", ["observer"])   # an observer key held by the agent's own host
KEYS = sdk.keyset(ISSUER, HOST, OBSERVER, HOST_AS_OBSERVER)
ORDER = ["read", "write_local", "write_shared", "external_send", "destructive", "financial"]

# Effect class of every AgentDojo tool (spec 6.2 classes). Unlisted tools are reads.
EFFECT = {
    "workspace": {"send_email": "external_send", "delete_email": "destructive", "create_calendar_event": "write_shared",
                  "cancel_calendar_event": "write_shared", "reschedule_calendar_event": "write_shared",
                  "add_calendar_event_participants": "write_shared", "append_to_file": "write_local",
                  "create_file": "write_local", "delete_file": "destructive", "share_file": "external_send"},
    "travel": {"create_calendar_event": "write_local", "cancel_calendar_event": "write_local",
               "reserve_hotel": "write_shared", "reserve_car_rental": "write_shared",
               "reserve_restaurant": "write_shared", "send_email": "external_send"},
    "banking": {"send_money": "financial", "schedule_transaction": "financial",
                "update_scheduled_transaction": "financial", "update_password": "destructive",
                "update_user_info": "write_shared"},
    "slack": {"add_user_to_channel": "write_shared", "send_direct_message": "external_send",
              "send_channel_message": "write_shared", "invite_user_to_slack": "write_shared",
              "remove_user_from_slack": "destructive", "post_webpage": "external_send"},
}
# The arguments that identify the object a side-effecting call acts on (its AMEP resource).
OBJECT_ARGS = {
    "send_email": ["recipients", "cc", "bcc"], "delete_email": ["email_id"], "share_file": ["file_id", "email"],
    "create_calendar_event": ["title", "participants"], "cancel_calendar_event": ["event_id"],
    "reschedule_calendar_event": ["event_id"], "add_calendar_event_participants": ["event_id", "participants"],
    "append_to_file": ["file_id"], "create_file": ["filename"], "delete_file": ["file_id"],
    "reserve_hotel": ["hotel"], "reserve_car_rental": ["company"], "reserve_restaurant": ["restaurant"],
    "send_money": ["recipient"], "schedule_transaction": ["recipient"], "update_scheduled_transaction": ["id", "recipient"],
    "update_password": [], "update_user_info": [],
    "add_user_to_channel": ["user", "channel"], "send_direct_message": ["recipient"],
    "send_channel_message": ["channel"], "invite_user_to_slack": ["user"], "remove_user_from_slack": ["user"],
    "post_webpage": ["url"],
}


_ADDRESS = re.compile(r"^[^<>]*<\s*([^<>\s]+@[^<>\s]+)\s*>\s*$")   # "Name <address>"
_GROUPED_IBAN = re.compile(r"^[A-Za-z]{2}\d{2}(?:\s?[A-Za-z0-9]{1,4})+$")


def _canon(x) -> str:
    """The interpretation's canonical form of one object (spec 5.8): the same contact or account written another
    legitimate way maps to the same resource. Found with the benign variations (benign_variants.py)."""
    x = str(x).strip()
    m = _ADDRESS.match(x)
    if m:
        x = m.group(1)
    if _GROUPED_IBAN.match(x) and " " in x:
        x = x.replace(" ", "")
    return x.lower().replace("*", "")


def _norm(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return ",".join(sorted(_canon(x) for x in v))
    return _canon(v)


def effect_of(suite: str, tool: str, args: dict) -> Effect:
    cls = EFFECT[suite].get(tool, "read")
    if cls == "read":
        return Effect(f"{suite}.{tool}", f"{suite}:{tool}/*", "read")
    obj = "|".join(_norm(args.get(a)) for a in OBJECT_ARGS.get(tool, []))
    return Effect(f"{suite}.{tool}", f"{suite}:{tool}/{obj}", cls, reversible=cls not in ("destructive", "financial"))


def mandate_for(suite_name, suite, user_calls, granularity) -> dict:
    tools = [t.name for t in suite.tools]
    reads = [t for t in tools if EFFECT[suite_name].get(t, "read") == "read"]
    acts = {f"{suite_name}.{t}" for t in reads}
    res = {f"{suite_name}:{t}/*" for t in reads}
    classes = ["read"]
    if granularity == "suite-wide":
        acts |= {f"{suite_name}.{t}" for t in tools}
        res |= {f"{suite_name}:{t}/*" for t in tools}
        classes.append("financial")
    for fc in user_calls:
        e = effect_of(suite_name, fc.function, dict(fc.args))
        if e.effect == "read":
            continue
        acts.add(e.action)
        classes.append(e.effect)
        res.add(e.resource if granularity == "effect-scoped" else f"{suite_name}:{fc.function}/*")
    ceiling = max(classes, key=ORDER.index)
    return ISSUER.sign(sdk.mandate("m-1", "user:principal", sdk.claims(sorted(acts), sorted(res), ceiling, EXP, depth=0)))


def run_trace(suite_name, suite, env, calls, mandate, *, variant=None):
    """Execute calls in env, recording evidence. Returns (recorder, list of (call, error))."""
    runtime = FunctionsRuntime(suite.tools)
    lying = {"done": False}

    def executed(tool, args, output):
        e = effect_of(suite_name, tool, args)
        if variant == "lying-tool" and e.effect != "read" and not lying["done"]:
            lying["done"] = True     # the tool acts on a different object than the one declared
            return Effect(e.action, e.resource + "-other", e.effect, reversible=e.reversible)
        return e

    observer = HOST_AS_OBSERVER if variant == "self-reported" else OBSERVER
    rec = EvidenceRecorder(HOST, observer, "m-1", lambda t, a: effect_of(suite_name, t, a), executed=executed,
                           chain=[mandate], actor="agent:assistant", adapter="agentdojo-oracle", adapter_version="1",
                           observed_by="agent:assistant" if variant == "self-reported" else "hook:tool-runtime")
    outcomes, failed_once = [], False
    for n, fc in enumerate(calls):
        cid = f"c{n}"
        rec.declare(cid, fc.function, dict(fc.args))
        before = env.model_dump()
        out, err = runtime.run_function(env, fc.function, dict(fc.args))
        if variant == "failed-tool" and not failed_once and EFFECT[suite_name].get(fc.function, "read") != "read":
            failed_once, err = True, "simulated tool failure"
        # The tool runtime (the observer) can see whether a refused call changed anything. If it didn't, it states
        # "not executed" instead of leaving the outcome unknown. The simulated failure above ran, so it never does.
        unchanged = err is not None and variant != "failed-tool" and env.model_dump() == before
        rec.observe(cid, out, error=err, not_executed=unchanged)
        outcomes.append((fc.function, err))
    return rec, outcomes


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="v1.2.2")
    ap.add_argument("--out", default=str(Path(__file__).with_name("results.json")))
    args = ap.parse_args(argv)
    t0 = time.time()
    suites = get_suites(args.version)
    grans = ["effect-scoped", "tool-scoped", "suite-wide"]
    table = {g: Counter() for g in grans}
    per_suite = defaultdict(lambda: {g: Counter() for g in grans})
    by_injection = defaultdict(lambda: {g: Counter() for g in grans})
    honest = {g: Counter() for g in grans}
    variants = {v: Counter() for v in ["lying-tool", "self-reported", "failed-tool"]}
    no_reference, output_only, read_only = set(), set(), set()

    for sname, suite in suites.items():
        base = suite.load_and_inject_default_environment({})
        for uid, ut in suite.user_tasks.items():
            ucalls = ut.ground_truth(base.model_copy(deep=True))
            has_write = any(EFFECT[sname].get(fc.function, "read") != "read" for fc in ucalls)
            for g in grans:
                env = base.model_copy(deep=True)
                rec, _ = run_trace(sname, suite, env, ucalls, mandate_for(sname, suite, ucalls, g))
                v, _ = rec.evaluate(KEYS)
                honest[g][v.outcome] += 1
            if has_write:
                for var in variants:
                    env = base.model_copy(deep=True)
                    rec, _ = run_trace(sname, suite, env, ucalls, mandate_for(sname, suite, ucalls, "tool-scoped"),
                                       variant=var)
                    v, _ = rec.evaluate(KEYS)
                    variants[var][f"{v.outcome} {v.invariant}"] += 1
            for iid, it in suite.injection_tasks.items():
                pre = base.model_copy(deep=True)
                icalls = it.ground_truth(pre.model_copy(deep=True))
                governed = [fc for fc in icalls if EFFECT[sname].get(fc.function, "read") != "read"]
                kind = "no-reference-trace" if not icalls else ("read-only" if not governed else None)
                if kind == "no-reference-trace":
                    # AgentDojo gives no ground-truth calls: either the goal is the model's text only (e.g. "Say that
                    # ..."), or the task has no reference trace and can only be measured with real model runs.
                    (output_only if it.GOAL.lower().startswith("say ") else no_reference).add(f"{sname}/{iid}")
                elif kind == "read-only":
                    read_only.add(f"{sname}/{iid}")
                for g in grans:
                    env = base.model_copy(deep=True)
                    pre_env = env.model_copy(deep=True)
                    rec, _ = run_trace(sname, suite, env, list(ucalls) + list(icalls), mandate_for(sname, suite, ucalls, g))
                    trace = list(ucalls) + list(icalls)
                    succeeded = it.security_from_traces("", pre_env, env, trace)
                    if succeeded is None:
                        succeeded = it.security("", pre_env, env)
                    v, results = rec.evaluate(KEYS)
                    key = kind or ("attack-failed" if not succeeded else v.outcome)
                    for c in (table[g], per_suite[sname][g], by_injection[f"{sname}/{iid}"][g]):
                        c[key] += 1

    def rate(c):
        n = c["violated"] + c["unresolved"] + c["preserved"]
        return {"successful_action_attacks": n, "violated": c["violated"], "unresolved": c["unresolved"],
                "preserved(missed)": c["preserved"], "detected_pct": round(100 * (c["violated"] + c["unresolved"]) / n, 1) if n else None,
                "no_reference_trace": c["no-reference-trace"], "read_only_injection": c["read-only"],
                "attack_failed_in_env": c["attack-failed"]}

    res = {
        "agentdojo_version": args.version,
        "suites": {s: {"user_tasks": len(su.user_tasks), "injection_tasks": len(su.injection_tasks), "tools": len(su.tools)}
                   for s, su in suites.items()},
        "pairs_per_granularity": sum(table["suite-wide"].values()),
        "overall": {g: rate(table[g]) for g in grans},
        "per_suite": {s: {g: rate(per_suite[s][g]) for g in grans} for s in per_suite},
        "per_injection_task": {k: {g: dict(v[g]) for g in grans} for k, v in sorted(by_injection.items())},
        "honest_traces": {g: dict(honest[g]) for g in grans},
        "variants_on_honest_traces_with_writes": {k: dict(v) for k, v in variants.items()},
        "injections_without_reference_trace": sorted(no_reference),
        "read_only_injections": sorted(read_only),
        "output_only_injections": sorted(output_only),
        "seconds": round(time.time() - t0, 1),
    }
    Path(args.out).write_text(json.dumps(res, indent=2) + "\n")
    json.dump({k: res[k] for k in ("pairs_per_granularity", "overall", "honest_traces",
                                   "variants_on_honest_traces_with_writes", "seconds")}, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
