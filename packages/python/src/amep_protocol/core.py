"""AMEP evaluation core: RFC 8785 canonicalization, signature and signer-role checks, the claim algebra,
and the evaluation procedure of the AMEP specification (spec/amep-v0.2.md, section 10).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

CEILING = ["read", "write_local", "write_shared", "external_send", "destructive", "financial"]

# Protected Resource registry, spec 19.7. Deployments add their own guardrail config, keys and evidence
# store via evaluate(..., extra_protected=...) (spec 8.1).
GUARDRAIL_MARKERS = ("/.claude/", "/.codex/", "/.cursor/", "/.gemini/", "/.git/hooks/", "/.ssh/authorized_keys")
GUARDRAIL_NAMES = ("AGENTS.md", "CLAUDE.md", ".mcp.json", ".zshrc", ".bashrc")

# Signer roles, spec 12.5: a key may sign only the object kinds its roles allow.
SIGNER_ROLES = {
    "mandate": {"issuer"}, "revocation": {"issuer"}, "status": {"issuer"},
    "delegation": {"issuer", "host"}, "intent": {"issuer", "host"},
    "interpretation": {"host"}, "invocation": {"host"}, "decision": {"host"},
    "effect": {"observer"}, "approval": {"approver"}, "finding": {"host", "observer"},
}

COST_BASE = {"read": 0, "write_local": 1, "write_shared": 3, "external_send": 5, "destructive": 10, "financial": 20}
DATA_MULT = {"public": 1, "internal": 1, "source": 1, "confidential": 2, "secret": 5, "phi": 5, "pci": 5}


class Malformed(ValueError):
    """The packet violates the data model; the affected invocation is unresolved (I7)."""


def is_guardrail(resource: str, extra=()) -> bool:
    """Resources are canonical; still match markers anywhere so ~/, $HOME and absolute forms are all caught."""
    r = "/" + resource.replace("~", "home", 1).lstrip("/")
    return any(m in r for m in (*GUARDRAIL_MARKERS, *extra)) or r.rsplit("/", 1)[-1] in GUARDRAIL_NAMES


# ---------------- time (spec 5.1.1) ----------------
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$")


def to_time(v) -> float:
    if isinstance(v, bool):
        raise Malformed("time must be a number or an RFC 3339 string")
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, str) and RFC3339.match(v):
        return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
    raise Malformed(f"malformed time {v!r}")


# ---------------- RFC 8785 canonical form (spec 12.1) ----------------
def _jcs_number(v) -> str:
    if isinstance(v, int):
        return str(v)
    if v != v or v in (float("inf"), float("-inf")):
        raise Malformed("NaN and Infinity are not allowed")
    if v == 0:
        return "0"
    sign, r = ("-", repr(-v)) if v < 0 else ("", repr(v))   # repr = shortest round-trip digits, like ECMAScript
    mant, _, e = r.partition("e")
    ip, _, fp = mant.partition(".")
    digits, exp10 = (ip + fp).lstrip("0"), int(e or 0) - len(fp)
    while digits.endswith("0"):
        digits, exp10 = digits[:-1], exp10 + 1
    k, n = len(digits), len(digits) + exp10                  # value = 0.digits x 10^n
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        x = n - 1
        out = (digits if k == 1 else digits[0] + "." + digits[1:]) + "e" + ("+" if x >= 0 else "-") + str(abs(x))
    return sign + out


def _jcs(v) -> str:
    if v is None or isinstance(v, bool):
        return json.dumps(v)
    if isinstance(v, (int, float)):
        return _jcs_number(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(_jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda s: s.encode("utf-16-be"))  # UTF-16 code-unit order
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _jcs(v[k]) for k in keys) + "}"
    raise Malformed(f"not JSON: {type(v).__name__}")


def canon(obj) -> bytes:
    return _jcs(obj).encode("utf-8")


def digest(obj) -> str:
    return hashlib.sha256(canon(obj)).hexdigest()


def approval_digest(x: dict) -> str:
    """Spec 5.10: approvals bind the executed-effect body without its time, so they can be issued in advance."""
    return digest({k: v for k, v in x.items() if k != "t"})


def verify_sig(obj, keys: dict) -> bool:
    if not isinstance(obj, dict):
        return False
    proof = obj.get("proof") or {}
    k = keys.get(proof.get("kid"))
    if not k or proof.get("alg") != "Ed25519" or k.get("alg") != "Ed25519":
        return False
    if not set(k.get("roles", [])) & SIGNER_ROLES.get(obj.get("kind"), set()):
        return False  # valid key, wrong role: e.g. a host key minting a mandate or approving its own action
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(k["x"])).verify(
            bytes.fromhex(proof["sig"]), canon({kk: vv for kk, vv in obj.items() if kk != "proof"}))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False


# ---------------- claim algebra (spec 6.3, 7) ----------------
def pat_match(value: str, pattern: str) -> bool:
    return pattern == "*" or value == pattern or (pattern.endswith("*") and value.startswith(pattern[:-1]))


def subsumed(child_pats, parent_pats) -> bool:
    return all(any(p == "*" or c == p or (p.endswith("*") and c.rstrip("*").startswith(p[:-1])) for p in parent_pats)
               for c in child_pats)


def narrower(child: dict, parent: dict) -> tuple[bool, str]:
    if not subsumed(child["actions"], parent["actions"]): return False, "actions widened"
    if not subsumed(child["resources"], parent["resources"]): return False, "resources widened"
    if not set(child.get("data", [])) <= set(parent.get("data", [])): return False, "data classes widened"
    if CEILING.index(child["ceiling"]) > CEILING.index(parent["ceiling"]): return False, "effect ceiling raised"
    if to_time(child["exp"]) > to_time(parent["exp"]): return False, "validity extended"
    if "nbf" in parent and ("nbf" not in child or to_time(child["nbf"]) < to_time(parent["nbf"])):
        return False, "validity extended (nbf)"
    if "purpose" in parent and child.get("purpose") != parent["purpose"]: return False, "purpose changed"
    # spec 7.1: denies only grow. Every parent deny must be covered by an equal-or-broader child deny.
    for key in ("deny_actions", "deny_resources"):
        if not all(subsumed([p], child.get(key, [])) for p in parent.get(key, [])):
            return False, f"{key} removed"
    if "budget" in parent and child.get("budget", parent["budget"]) > parent["budget"]: return False, "risk budget widened"
    # spec 7.2: absent depth on the parent = unbounded; depth 0 = no further delegation;
    # otherwise the child MUST carry a strictly smaller depth
    if "depth" in parent:
        if parent["depth"] == 0: return False, "parent may not be delegated (depth 0)"
        if "depth" not in child: return False, "delegation depth missing under a bounded parent"
        if child["depth"] >= parent["depth"]: return False, "delegation depth not decreasing"
    return True, ""


def meet(a: dict, b: dict) -> dict:
    m = {"actions": [x for x in a["actions"] if subsumed([x], b["actions"])],
         "resources": [x for x in a["resources"] if subsumed([x], b["resources"])],
         "data": sorted(set(a.get("data", [])) & set(b.get("data", []))),
         "ceiling": CEILING[min(CEILING.index(a["ceiling"]), CEILING.index(b["ceiling"]))],
         "exp": min(to_time(a["exp"]), to_time(b["exp"]))}
    nbfs = [to_time(c["nbf"]) for c in (a, b) if "nbf" in c]
    if nbfs: m["nbf"] = max(nbfs)
    if "purpose" in a or "purpose" in b: m["purpose"] = a.get("purpose", b.get("purpose"))
    for key in ("deny_actions", "deny_resources"):   # denies are unioned: no hop or intent can lift one
        if key in a or key in b: m[key] = sorted(set(a.get(key, [])) | set(b.get(key, [])))
    return m


def effect_ok(x: dict, c: dict) -> tuple[bool, str]:
    if not any(pat_match(x["action"], p) for p in c["actions"]): return False, "action outside claims"
    if any(pat_match(x["action"], p) for p in c.get("deny_actions", [])): return False, "action denied"
    if not any(pat_match(x["resource"], p) for p in c["resources"]): return False, "resource outside claims"
    if any(pat_match(x["resource"], p) for p in c.get("deny_resources", [])): return False, "resource denied"
    if CEILING.index(x["effect"]) > CEILING.index(c["ceiling"]): return False, "effect above ceiling"
    for d in x.get("released", []):
        if d not in c.get("data", []): return False, f"released {d} not allowed"
    if to_time(x["t"]) > c["exp"]: return False, "after validity"
    if "nbf" in c and to_time(x["t"]) < c["nbf"]: return False, "before validity"
    return True, ""


def cost(x: dict) -> int:
    mult = max([DATA_MULT.get(d.split("->")[0], 1) for d in x.get("released", [])] or [1])
    rev = 1 if x["effect"] == "read" or (x.get("reversible") and x["effect"] != "external_send") else 3
    return COST_BASE[x["effect"]] * mult * rev


# ---------------- evaluation (spec 10) ----------------
@dataclass
class Result:
    invocation: str
    outcome: str
    invariant: str
    reason: str


class Stop(Exception):
    def __init__(self, outcome, invariant, reason):
        self.r = (outcome, invariant, reason)


def _check(cond, outcome, invariant, reason):
    if cond:
        raise Stop(outcome, invariant, reason)


def evaluate(packet: dict, keys: dict, extra_protected=(), state: dict | None = None) -> list[Result]:
    """state (spec 10.6): carries approval use and risk-budget spending across packets. Read on entry, updated on exit."""
    objs = {o["id"]: o for kind in ("mandates", "delegations", "intents", "interpretations", "invocations",
                                    "effects", "approvals", "findings")
            for o in packet.get(kind, []) if isinstance(o, dict) and "id" in o}
    revocations, statuses = packet.get("revocations", []), packet.get("statuses", [])
    effects = packet.get("effects", [])
    state = {} if state is None else state
    spent: dict[str, int] = dict(state.get("spent", {}))
    # approval id -> (invocation id, body digest) of its first use, including uses in earlier packets
    approval_use: dict[str, tuple] = {k: tuple(v) for k, v in state.get("approvals_used", {}).items()}
    out: list[Result] = []
    invocations = packet.get("invocations", [])
    order = {i.get("id"): n for n, i in enumerate(invocations)}
    # spec 5.9.1 data lineage: data classes each invocation's output carries, through derived_from, earlier only
    taint: dict[str, set] = {}
    for n, i in enumerate(invocations):
        own = {d for e in effects if e.get("invocation") == i.get("id") for d in (e.get("executed") or {}).get("accessed", [])}
        for j in i.get("derived_from", []):
            if order.get(j, n) < n:
                own |= taint.get(j, set())
        taint[i.get("id")] = own
    decisions = [d for d in packet.get("decisions", []) if verify_sig(d, keys)]
    # spec 5.13: a verified pre-execution quarantine withholds findings from every LATER invocation
    quarantined: dict[str, int] = {}
    for d in decisions:
        if d.get("mode") == "quarantine" and d.get("phase") == "pre_execution" and d.get("invocation") in order:
            for f in d.get("quarantined", []):
                quarantined[f] = min(quarantined.get(f, len(invocations)), order[d["invocation"]])
    for n, inv in enumerate(invocations):
        rid = inv.get("id", "?")
        try:
            leaked = [f for f in inv.get("influenced_by", []) if f in quarantined and n > quarantined[f]]
            _check(bool(leaked) and not inv.get("principal_confirmed"), "violated", "I4", f"quarantined content reached the agent ({', '.join(leaked)})")
            _evaluate_invocation(inv, packet, objs, keys, revocations, statuses, effects, spent, approval_use, extra_protected, order, taint)
            out.append(Result(rid, "preserved", "-", "continuity preserved"))
        except Stop as s:
            out.append(Result(rid, *s.r))
        except (Malformed, KeyError, TypeError, ValueError, AttributeError) as e:
            out.append(Result(rid, "unresolved", "I7", f"malformed evidence: {e}"))

    # spec 10.3: decision reconciliation. Only PRE-execution decisions can be contradicted or confirm a block;
    # a post-execution decision is detection and a simulation is hypothetical (spec 5.13).
    eff_by_inv = {e.get("invocation") for e in effects}
    for d in decisions:
        if d.get("mode") not in ("deny", "hold") or d.get("phase") != "pre_execution":
            continue
        enf = d.get("enforcement", {})
        if d.get("invocation") in eff_by_inv:
            out = [r for r in out if r.invocation != d["invocation"]]
            out.append(Result(d["invocation"], "violated", "I11", "effect executed despite a deny/hold decision (enforcement contradicted)"))
        elif enf.get("fail_mode") == "closed" or enf.get("applied") == "confirmed":
            out = [r for r in out if r.invocation != d["invocation"]]
            out.append(Result(d["invocation"], "preserved", "-", "denied before execution; no effect (enforcement confirmed)"))
    # spec 10.4: orphan effects
    inv_ids = {i.get("id") for i in packet.get("invocations", [])}
    for e in effects:
        if e.get("invocation") not in inv_ids:
            out.append(Result(e.get("id", "?"), "violated", "I11", "effect without any authorized invocation (bypass)"))
    state["spent"] = spent
    state["approvals_used"] = {k: list(v) for k, v in approval_use.items()}
    return out


def _evaluate_invocation(inv, packet, objs, keys, revocations, statuses, effects, spent, approval_use, extra_protected, order, taint):
    rid, t_inv = inv["id"], to_time(inv["t"])
    # 1. chain
    chain, node, seen = [], objs.get(inv.get("authority_ref")), set()
    while node and node["id"] not in seen:
        seen.add(node["id"]); chain.append(node); node = objs.get(node.get("parent"))
    chain.reverse()
    _check(not chain or chain[0].get("kind") != "mandate", "unresolved", "I7", "no root mandate")
    # 2. signatures (and signer roles) on everything the decision rests on
    interp = objs.get(inv.get("interpretation_ref"))
    needed = chain + [inv] + ([interp] if interp else [])
    if "intent_ref" in inv:
        intent = objs.get(inv["intent_ref"])
        _check(not intent or intent.get("kind") != "intent", "unresolved", "I7", "cited intent not found")
        needed.append(intent)
    _check(any(not verify_sig(o, keys) for o in needed), "unresolved", "I7", "missing or invalid signature, or signer lacks the role")
    _check(any(order.get(j, order[rid]) >= order[rid] for j in inv.get("derived_from", [])),
           "unresolved", "I7", "lineage reference not found among earlier invocations")
    # 3-4. interpretation
    _check(not interp or interp.get("source") not in ("curated", "customer"), "unresolved", "I3", "no approved interpretation")
    pinned = packet.get("pinned_adapters", {})
    _check(bool(pinned) and pinned.get(interp.get("adapter")) != interp.get("version"), "unresolved", "I3", "adapter revision not approved (pin mismatch)")
    # 5. attenuation
    for p, c in zip(chain, chain[1:]):
        ok, why = narrower(c["claims"], p["claims"])
        _check(not ok, "violated", "I1", f"{c['id']}: {why}")
    # 6. liveness: signed revocations and signed status assertions (spec 5.12)
    ids = {n["id"] for n in chain}
    revs = [r for r in revocations if r.get("target") in ids]
    _check(any(verify_sig(r, keys) and to_time(r["t"]) <= t_inv for r in revs), "violated", "I6", "ancestor revoked before invocation")
    sts = [s for s in statuses if s.get("target") in ids and verify_sig(s, keys)]
    _check(any(s.get("revoked_at") is not None and to_time(s["revoked_at"]) <= t_inv for s in sts), "violated", "I6", "status shows ancestor revoked before invocation")
    _check(any(not verify_sig(r, keys) for r in revs), "unresolved", "I7", "unverifiable revocation on the chain")
    for n in chain:
        if (n.get("revocation") or {}).get("status_ref"):
            fresh = [s for s in sts if s["target"] == n["id"] and to_time(s["as_of"]) >= t_inv]
            _check(not fresh, "unresolved", "I7", f"no signed revocation status for {n['id']} as of the invocation")
    # 7. self-protection on the declared target
    _check(is_guardrail(inv["declared"]["resource"], extra_protected), "violated", "I9", "targets guardrail/evidence store")
    # 8-9. influence: a finding counts as trusted only if it exists, is signed and is labelled trusted (spec 5.11)
    mine = [e for e in effects if e.get("invocation") == rid]
    untrusted = [f for f in inv.get("influenced_by", [])
                 if not (objs.get(f) and verify_sig(objs[f], keys) and objs[f].get("integrity_label") == "trusted")]
    _check(bool(untrusted) and inv["declared"]["effect"] != "read" and not inv.get("principal_confirmed"),
           "violated" if mine else "unresolved", "I4", "mutation shaped by untrusted content")
    # 10. effect receipts
    _check(not mine, "unresolved", "I7", "no executed-effect receipt")
    high_impact = CEILING.index(inv["declared"]["effect"]) >= CEILING.index("write_shared")
    eff_claims = chain[0]["claims"]
    for n in chain[1:]:
        eff_claims = meet(n["claims"], eff_claims)
    if "intent_ref" in inv:
        eff_claims = meet(objs[inv["intent_ref"]]["claims"], eff_claims)
    appr = objs.get(inv.get("approval_ref")) if "approval_ref" in inv else None
    bodies = {}
    # 11-15. every receipt for this invocation is checked (spec 10.2); identical bodies are one effect
    for e in mine:
        _check(not verify_sig(e, keys), "unresolved", "I7", "effect receipt unsigned or signer lacks the role")
        if high_impact:
            _check(not inv.get("actor"), "unresolved", "I10", "actor not recorded; observer independence cannot be shown")
            _check(e.get("observed_by") == inv["actor"] or e.get("assurance") == "L0", "unresolved", "I10", "high-impact effect only self-reported")
        x = e["executed"]
        if "mediated" in inv:
            _check(canon(x) != canon(inv["mediated"]), "violated", "I2", "executed differs from mediated effect")
        else:
            _check((x["action"], x["resource"]) != (inv["declared"]["action"], inv["declared"]["resource"]), "violated", "I2", "declared != executed")
        _check(is_guardrail(x["resource"], extra_protected), "violated", "I9", "executed effect targets guardrail/evidence store")
        ok, why = effect_ok(x, eff_claims)
        _check(not ok, "violated", "I5" if why.startswith("released") else "I2", why)
        # spec 5.9.1: data classes carried in through lineage (or read by this effect) reach the recipient too
        if "recipient" in x:
            inherited = set(x.get("accessed", []))
            for j in inv.get("derived_from", []):
                inherited |= taint.get(j, set())
            leaked = sorted(f"{d}->{x['recipient']}" for d in inherited if f"{d}->{x['recipient']}" not in eff_claims.get("data", []))
            _check(bool(leaked), "violated", "I5", f"derived data released: {', '.join(leaked)}")
        bodies.setdefault(approval_digest(x), x)
    if "approval_ref" in inv:
        _check(not appr or not verify_sig(appr, keys), "unresolved", "I7", "approval missing, unsigned or not signed by an approver")
        for d, x in bodies.items():
            t_x = to_time(x["t"])
            _check(appr["effect_digest"] != d, "violated", "I8", "approval not bound to the executed effect")
            _check(bool(appr.get("consumed")), "violated", "I8", "approval already consumed")
            _check("expiry" in appr and to_time(appr["expiry"]) < max(t_inv, t_x), "violated", "I8", "approval expired")
            _check("nbf" in appr and to_time(appr["nbf"]) > t_inv, "violated", "I8", "approval not yet valid")
            first = approval_use.setdefault(appr["id"], (rid, d))
            _check(first != (rid, d), "violated", "I8", f"approval already used by {first[0]}")
    # 16. risk budget: recorded spend must match receipts; over budget needs a bound approval
    c = sum(cost(x) for x in bodies.values())
    _check("budget_spent" in inv and inv["budget_spent"] != c, "violated", "I7", "recorded budget spend does not match receipts")
    over = next((n["id"] for n in chain if "budget" in n["claims"] and spent.get(n["id"], 0) + c > n["claims"]["budget"]), None)
    _check(bool(over) and not appr, "violated", "I2", f"risk budget of {over} exceeded without approval")
    for n in chain:
        spent[n["id"]] = spent.get(n["id"], 0) + c


def verdict(results: list[Result]) -> Result:
    """Spec 10.5: violated beats unresolved beats preserved; first result with that outcome decides."""
    for o in ("violated", "unresolved"):
        r = next((r for r in results if r.outcome == o), None)
        if r:
            return r
    return results[0] if results else Result("-", "unresolved", "I7", "empty packet")


