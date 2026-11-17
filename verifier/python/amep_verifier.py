"""AMEP v0.2 reference verifier (Python) and conformance-vector generator.

Implements spec/amep-v0.2.md section 10. Offline: verifies Ed25519 signatures over the RFC 8785 (JCS)
canonical form, checks signer roles, and evaluates continuity per invocation:
  I1 attenuation · I2 effect within authority · I3 interpretation · I4 influence · I5 release
  I6 liveness · I7 evidence · I8 approval binding · I9 self-protection · I10 observer independence
  I11 no orphan effects
Each result is preserved | violated | unresolved with the deciding invariant.

Run:
  python3 -I verifier/python/amep_verifier.py              regenerate vectors/ and check them in memory
  python3 -I verifier/python/amep_verifier.py --check DIR  check the vector files in DIR as stored on disk
Requires: cryptography (Ed25519).
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


# ---------------- signing ----------------
class Signer:
    def __init__(self, kid: str, roles=()):
        # Deterministic TEST keys (seed = SHA-256 of a public label + kid), so regenerating the vectors is
        # reproducible. Never use this derivation for real keys.
        seed = hashlib.sha256(f"amep-test-vector-key-v1:{kid}".encode()).digest()
        self.kid, self.key, self.roles = kid, Ed25519PrivateKey.from_private_bytes(seed), list(roles)

    def public(self) -> dict:
        raw = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"kid": self.kid, "alg": "Ed25519", "x": raw.hex(), "roles": self.roles}

    def sign(self, body: dict) -> dict:
        body = {k: v for k, v in body.items() if k != "proof"}
        return {**body, "proof": {"kid": self.kid, "alg": "Ed25519", "sig": self.key.sign(canon(body)).hex()}}


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


def evaluate(packet: dict, keys: dict, extra_protected=()) -> list[Result]:
    objs = {o["id"]: o for kind in ("mandates", "delegations", "intents", "interpretations", "invocations",
                                    "effects", "approvals", "findings")
            for o in packet.get(kind, []) if isinstance(o, dict) and "id" in o}
    revocations, statuses = packet.get("revocations", []), packet.get("statuses", [])
    effects = packet.get("effects", [])
    spent: dict[str, int] = {}
    approval_use: dict[str, tuple] = {}   # approval id -> (invocation id, body digest) of its first use
    out: list[Result] = []
    invocations = packet.get("invocations", [])
    order = {i.get("id"): n for n, i in enumerate(invocations)}
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
            _evaluate_invocation(inv, packet, objs, keys, revocations, statuses, effects, spent, approval_use, extra_protected)
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
    return out


def _evaluate_invocation(inv, packet, objs, keys, revocations, statuses, effects, spent, approval_use, extra_protected):
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


# ---------------- vector suite ----------------
T0 = 1767225600  # 2026-01-01T00:00:00Z, base for the RFC 3339 vectors


def iso(off: int) -> str:
    return datetime.utcfromtimestamp(T0 + off).strftime("%Y-%m-%dT%H:%M:%SZ")


def base(issuer: Signer, host: Signer, observer: Signer):
    root = issuer.sign({"id": "m-1", "kind": "mandate", "principal": "user:alice", "claims": {
        "actions": ["fs.*", "process.exec"], "resources": ["repo:app/*"], "data": ["source->internal"], "ceiling": "write_local", "exp": 100, "depth": 2}})
    dele = issuer.sign({"id": "d-1", "kind": "delegation", "parent": "m-1", "claims": {
        "actions": ["fs.write"], "resources": ["repo:app/src/*"], "data": ["source->internal"], "ceiling": "write_local", "exp": 90, "depth": 1}})
    interp = host.sign({"id": "a-1", "kind": "interpretation", "source": "curated", "adapter": "host_shell", "version": "r9"})
    inv = host.sign({"id": "i-1", "kind": "invocation", "authority_ref": "d-1", "interpretation_ref": "a-1", "t": 10,
                     "declared": {"action": "fs.write", "resource": "repo:app/src/auth.ts", "effect": "write_local"}})
    eff = observer.sign({"id": "e-1", "kind": "effect", "invocation": "i-1", "observed_by": "hook:host", "assurance": "L1",
                         "executed": {"action": "fs.write", "resource": "repo:app/src/auth.ts", "effect": "write_local", "released": [], "t": 11}})
    return {"mandates": [root], "delegations": [dele], "interpretations": [interp], "invocations": [inv], "effects": [eff]}


def vectors():
    I, H, O, X = Signer("issuer-1", ["issuer", "approver"]), Signer("host-1", ["host"]), Signer("observer-1", ["observer"]), Signer("attacker")
    keys = {s.kid: s.public() for s in (I, H, O)}
    V = []

    def add(name, expect, mutate):
        p = base(I, H, O)
        mutate(p, I, H, O, X)
        V.append((name, expect, p))

    def claims_of(p, which, **kw):
        return {**p[which][0]["claims"], **kw}

    def approve(p, aid, **kw):
        return I.sign({"id": aid, "kind": "approval", "effect_digest": approval_digest(p["effects"][0]["executed"]), "presence": "webauthn", **kw})

    def high_impact(p, actor="agent:assistant-1", observed_by="proxy:egress", assurance="L2"):
        p.update(mandates=[I.sign({**p["mandates"][0], "claims": claims_of(p, "mandates", ceiling="external_send")})])
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", ceiling="external_send")})])
        inv = {**p["invocations"][0], "declared": {**p["invocations"][0]["declared"], "effect": "external_send"}}
        if actor: inv["actor"] = actor
        p.update(invocations=[H.sign(inv)])
        p.update(effects=[O.sign({**p["effects"][0], "observed_by": observed_by, "assurance": assurance,
                                  "executed": {**p["effects"][0]["executed"], "effect": "external_send"}})])

    add("valid preserved flow", ("preserved", "-"), lambda p, *a: None)
    add("missing effect receipt", ("unresolved", "I7"), lambda p, *a: p.update(effects=[]))
    add("forged mandate (attacker key)", ("unresolved", "I7"), lambda p, I, H, O, X: p.update(mandates=[X.sign({**p["mandates"][0]})]))
    add("unknown interpretation", ("unresolved", "I3"), lambda p, I, H, O, X: p.update(interpretations=[H.sign({**p["interpretations"][0], "source": "judge"})]))
    add("expand-then-shrink delegation", ("violated", "I1"), lambda p, I, H, O, X: p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", ceiling="destructive")})]))
    add("revoked root with live child", ("violated", "I6"), lambda p, I, *a: p.update(revocations=[I.sign({"kind": "revocation", "target": "m-1", "t": 5})]))
    add("declared != executed (path retarget)", ("violated", "I2"), lambda p, I, H, O, X: p.update(effects=[O.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "resource": "repo:app/.env"}})]))
    add("effect outside delegated scope", ("violated", "I2"), lambda p, I, H, O, X: (
        p.update(invocations=[H.sign({**p["invocations"][0], "declared": {"action": "fs.write", "resource": "repo:app/README.md", "effect": "write_local"}})]),
        p.update(effects=[O.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "resource": "repo:app/README.md"}})])))
    add("secret released externally (I5)", ("violated", "I5"), lambda p, I, H, O, X: p.update(effects=[O.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "released": ["secret->external"]}})]))
    add("injection-driven mutation", ("violated", "I4"), lambda p, I, H, O, X: p.update(invocations=[H.sign({**p["invocations"][0], "influenced_by": ["f-1"]})]))
    add("guardrail write (I9)", ("violated", "I9"), lambda p, I, H, O, X: p.update(invocations=[H.sign({**p["invocations"][0], "declared": {"action": "fs.write", "resource": "~/.claude/settings.json", "effect": "write_local"}})]))
    add("guardrail write via absolute path (I9)", ("violated", "I9"), lambda p, I, H, O, X: p.update(invocations=[H.sign({**p["invocations"][0], "declared": {"action": "fs.write", "resource": "/Users/dev/.claude/settings.json", "effect": "write_local"}})]))
    add("approval digest mismatch (TOCTOU)", ("violated", "I8"), lambda p, I, H, O, X: (
        p.update(approvals=[I.sign({"id": "ap-1", "kind": "approval", "effect_digest": "0" * 64, "presence": "webauthn"})]),
        p.update(invocations=[H.sign({**p["invocations"][0], "approval_ref": "ap-1"})])))
    add("tampered effect receipt", ("unresolved", "I7"), lambda p, *a: p["effects"][0]["executed"].update(resource="repo:app/src/other.ts"))
    add("mediated effect honored", ("preserved", "-"), lambda p, I, H, O, X: (
        p.update(invocations=[H.sign({**p["invocations"][0], "declared": {"action": "fs.write", "resource": "repo:app/src/*", "effect": "write_local"},
                                      "mediated": p["effects"][0]["executed"]})])))
    add("intent narrower than grant", ("violated", "I2"), lambda p, I, H, O, X: (
        p.update(intents=[I.sign({"id": "n-1", "kind": "intent", "claims": {"actions": ["fs.write"], "resources": ["repo:app/tests/*"], "data": ["source->internal"], "ceiling": "write_local", "exp": 90}})]),
        p.update(invocations=[H.sign({**p["invocations"][0], "intent_ref": "n-1"})])))
    add("identity-only authorization (no mandate)", ("unresolved", "I7"), lambda p, *a: p.update(mandates=[], delegations=[]))
    add("missing parent lineage", ("unresolved", "I7"), lambda p, I, H, O, X: p.update(mandates=[]))
    add("unsigned invocation", ("unresolved", "I7"), lambda p, I, H, O, X: p["invocations"][0].pop("proof"))
    add("invocation signed by unknown key", ("unresolved", "I7"), lambda p, I, H, O, X: p.update(invocations=[X.sign({**p["invocations"][0]})]))
    add("unapproved adapter revision", ("unresolved", "I3"), lambda p, *a: p.update(pinned_adapters={"host_shell": "r8"}))
    add("approved adapter revision (pinned)", ("preserved", "-"), lambda p, *a: p.update(pinned_adapters={"host_shell": "r9"}))
    add("interpretation from provider hint only", ("unresolved", "I3"), lambda p, I, H, O, X: p.update(interpretations=[H.sign({**p["interpretations"][0], "source": "provider_hint"})]))
    add("lying adapter caught by backend (L3)", ("violated", "I2"), lambda p, I, H, O, X: p.update(effects=[O.sign({**p["effects"][0], "assurance": "L3", "observed_by": "provider:github",
        "executed": {**p["effects"][0]["executed"], "action": "fs.delete"}})]))
    add("stale approval (expired)", ("violated", "I8"), lambda p, I, H, O, X: (
        p.update(approvals=[approve(p, "ap-2", expiry=5)]), p.update(invocations=[H.sign({**p["invocations"][0], "approval_ref": "ap-2"})])))
    add("approval replay (consumed)", ("violated", "I8"), lambda p, I, H, O, X: (
        p.update(approvals=[approve(p, "ap-3", consumed=True)]), p.update(invocations=[H.sign({**p["invocations"][0], "approval_ref": "ap-3"})])))
    add("valid bound approval", ("preserved", "-"), lambda p, I, H, O, X: (
        p.update(approvals=[approve(p, "ap-4", expiry=50)]), p.update(invocations=[H.sign({**p["invocations"][0], "approval_ref": "ap-4"})])))
    add("unsigned approval", ("unresolved", "I7"), lambda p, I, H, O, X: (
        p.update(approvals=[{"id": "ap-5", "kind": "approval", "effect_digest": approval_digest(p["effects"][0]["executed"]), "presence": "none"}]),
        p.update(invocations=[H.sign({**p["invocations"][0], "approval_ref": "ap-5"})])))
    add("effect after mandate validity", ("violated", "I2"), lambda p, I, H, O, X: p.update(effects=[O.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "t": 95}})]))
    add("revoked after the action (still preserved)", ("preserved", "-"), lambda p, I, *a: p.update(revocations=[I.sign({"kind": "revocation", "target": "m-1", "t": 50})]))
    add("delegation extends validity", ("violated", "I1"), lambda p, I, H, O, X: p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", exp=200)})]))
    add("delegation widens resources", ("violated", "I1"), lambda p, I, H, O, X: p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", resources=["repo:*"])})]))
    add("delegation adds data class", ("violated", "I1"), lambda p, I, H, O, X: p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", data=["source->internal", "secret->external"])})]))
    add("delegation depth not decreasing", ("violated", "I1"), lambda p, I, H, O, X: p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", depth=2)})]))
    add("two-hop chain within bounds", ("preserved", "-"), lambda p, I, H, O, X: (
        p["delegations"].append(I.sign({"id": "d-2", "kind": "delegation", "parent": "d-1", "claims": {"actions": ["fs.write"], "resources": ["repo:app/src/*"], "data": ["source->internal"], "ceiling": "write_local", "exp": 80, "depth": 0}})),
        p.update(invocations=[H.sign({**p["invocations"][0], "authority_ref": "d-2"})])))
    add("influence confirmed by principal", ("preserved", "-"), lambda p, I, H, O, X: p.update(invocations=[H.sign({**p["invocations"][0], "influenced_by": ["f-1"], "principal_confirmed": True})]))
    add("influenced read-only action", ("preserved", "-"), lambda p, I, H, O, X: (
        p.update(invocations=[H.sign({**p["invocations"][0], "influenced_by": ["f-1"], "declared": {"action": "fs.read", "resource": "repo:app/src/auth.ts", "effect": "read"}})]),
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", actions=["fs.write", "fs.read"])})]),
        p.update(effects=[O.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "action": "fs.read", "effect": "read"}})])))
    add("mediated effect not honored", ("violated", "I2"), lambda p, I, H, O, X: p.update(invocations=[H.sign({**p["invocations"][0], "mediated": {**p["effects"][0]["executed"], "resource": "repo:app/src/build/x"}})]))
    add("self-reported high-impact effect", ("unresolved", "I10"), lambda p, *a: high_impact(p, observed_by="agent:assistant-1", assurance="L0"))
    add("bypass: effect without invocation", ("violated", "I11"), lambda p, I, H, O, X: p["effects"].append(O.sign({"id": "e-9", "kind": "effect", "invocation": "i-404", "observed_by": "provider:github", "assurance": "L3",
        "executed": {"action": "fs.delete", "resource": "repo:app/main", "effect": "destructive", "released": [], "t": 12}})))

    # risk budget; base effect = write_local, not reversible -> 3 points
    def budgets(p, I, H, mb, db, spend=None, extra_inv=None):
        p.update(mandates=[I.sign({**p["mandates"][0], "claims": claims_of(p, "mandates", budget=mb)})])
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", budget=db)})])
        inv = {**p["invocations"][0], **(extra_inv or {})}
        if spend is not None:
            inv["budget_spent"] = spend
        p.update(invocations=[H.sign(inv)])
    add("within risk budget", ("preserved", "-"), lambda p, I, H, O, X: budgets(p, I, H, 10, 5, 3))
    add("delegation widens risk budget", ("violated", "I1"), lambda p, I, H, O, X: budgets(p, I, H, 10, 20, 3))
    add("risk budget exceeded without approval", ("violated", "I2"), lambda p, I, H, O, X: budgets(p, I, H, 10, 2, 3))
    add("risk budget exceeded, human approved", ("preserved", "-"), lambda p, I, H, O, X: (
        p.update(approvals=[approve(p, "ap-6", expiry=50)]), budgets(p, I, H, 10, 2, 3, {"approval_ref": "ap-6"})))
    add("recorded budget spend mismatch", ("violated", "I7"), lambda p, I, H, O, X: budgets(p, I, H, 10, 5, 0))
    add("reversible write is cheaper", ("preserved", "-"), lambda p, I, H, O, X: (
        p.update(effects=[O.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "reversible": True}})]), budgets(p, I, H, 10, 1, 1)))
    add("cumulative spend exceeds budget", ("violated", "I2"), lambda p, I, H, O, X: (
        budgets(p, I, H, 10, 5, 3),
        p["invocations"].append(H.sign({**p["invocations"][0], "id": "i-2", "t": 12, "budget_spent": 3})),
        p["effects"].append(O.sign({**p["effects"][0], "id": "e-2", "invocation": "i-2"}))))
    def decision(H, did, mode="deny", phase="pre_execution", inv="i-1", **kw):
        return H.sign({"id": did, "kind": "decision", "invocation": inv, "outcome": "violated", "mode": mode, "phase": phase, **kw})
    add("deny contradicted by executed effect", ("violated", "I11"), lambda p, I, H, O, X:
        p.update(decisions=[decision(H, "cd-1", enforcement={"pep": "host-hook/1.0", "fail_mode": "open", "encoded_as": "ask"})]))
    add("deny honoured on fail-closed host (no effect)", ("preserved", "-"), lambda p, I, H, O, X: (
        p.update(decisions=[decision(H, "cd-2", enforcement={"pep": "host-hook/2.0", "fail_mode": "closed", "applied": "confirmed"})]),
        p.update(effects=[])))
    add("deny on fail-open host, no effect record", ("unresolved", "I7"), lambda p, I, H, O, X: (
        p.update(decisions=[decision(H, "cd-3", enforcement={"pep": "host-hook/1.0", "fail_mode": "open"})]),
        p.update(effects=[])))

    # ---- draft.1: verifier/spec divergences (Appendix E.2) ----
    add("delegation without depth under bounded parent", ("violated", "I1"), lambda p, I, H, O, X: p.update(
        delegations=[I.sign({**p["delegations"][0], "claims": {k: v for k, v in p["delegations"][0]["claims"].items() if k != "depth"}})]))
    add("delegation from a zero-depth parent", ("violated", "I1"), lambda p, I, H, O, X: (
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", depth=0)})]),
        p["delegations"].append(I.sign({"id": "d-2", "kind": "delegation", "parent": "d-1", "claims": claims_of(p, "delegations", exp=80, depth=0)})),
        p.update(invocations=[H.sign({**p["invocations"][0], "authority_ref": "d-2"})])))
    add("intent reference unresolved", ("unresolved", "I7"), lambda p, I, H, O, X: p.update(invocations=[H.sign({**p["invocations"][0], "intent_ref": "n-404"})]))
    add("unsigned intent", ("unresolved", "I7"), lambda p, I, H, O, X: (
        p.update(intents=[{"id": "n-2", "kind": "intent", "claims": {"actions": ["fs.write"], "resources": ["repo:app/src/*"], "data": ["source->internal"], "ceiling": "write_local", "exp": 90}}]),
        p.update(invocations=[H.sign({**p["invocations"][0], "intent_ref": "n-2"})])))
    add("effect before validity (nbf)", ("violated", "I2"), lambda p, I, H, O, X: (
        p.update(mandates=[I.sign({**p["mandates"][0], "claims": claims_of(p, "mandates", nbf=20)})]),
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", nbf=20)})])))
    add("delegation drops nbf", ("violated", "I1"), lambda p, I, H, O, X: p.update(mandates=[I.sign({**p["mandates"][0], "claims": claims_of(p, "mandates", nbf=5)})]))
    add("delegation changes purpose", ("violated", "I1"), lambda p, I, H, O, X: (
        p.update(mandates=[I.sign({**p["mandates"][0], "claims": claims_of(p, "mandates", purpose="bugfix")})]),
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", purpose="release")})])))
    add("mediated into a guardrail path (I9)", ("violated", "I9"), lambda p, I, H, O, X: (
        p.update(effects=[O.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "resource": "repo:app/src/.claude/settings.json"}})]),
        p.update(invocations=[H.sign({**p["invocations"][0], "declared": {"action": "fs.write", "resource": "repo:app/src/*", "effect": "write_local"},
                                      "mediated": p["effects"][0]["executed"]})])))
    add("validity window and purpose carried through", ("preserved", "-"), lambda p, I, H, O, X: (
        p.update(mandates=[I.sign({**p["mandates"][0], "claims": claims_of(p, "mandates", nbf=5, purpose="bugfix")})]),
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", nbf=8, purpose="bugfix")})])))

    # ---- draft.2: review fixes ----
    # 1. signer roles (spec 12.5)
    add("mandate minted by host key", ("unresolved", "I7"), lambda p, I, H, O, X: p.update(mandates=[H.sign({**p["mandates"][0]})]))
    add("self-approval signed by host key", ("unresolved", "I7"), lambda p, I, H, O, X: (
        p.update(approvals=[H.sign({"id": "ap-7", "kind": "approval", "effect_digest": approval_digest(p["effects"][0]["executed"]), "presence": "host_ui", "expiry": 50})]),
        p.update(invocations=[H.sign({**p["invocations"][0], "approval_ref": "ap-7"})])))
    # 2. signed revocations and status freshness (spec 5.12)
    add("unsigned revocation on the chain", ("unresolved", "I7"), lambda p, *a: p.update(revocations=[{"kind": "revocation", "target": "m-1", "t": 5}]))
    revocable = lambda p, I: p.update(mandates=[I.sign({**p["mandates"][0], "revocation": {"status_ref": "https://issuer.example/status/m-1"}})])
    add("revocable mandate without status", ("unresolved", "I7"), lambda p, I, *a: revocable(p, I))
    add("stale revocation status", ("unresolved", "I7"), lambda p, I, *a: (
        revocable(p, I), p.update(statuses=[I.sign({"kind": "status", "target": "m-1", "as_of": 3})])))
    add("fresh revocation status", ("preserved", "-"), lambda p, I, *a: (
        revocable(p, I), p.update(statuses=[I.sign({"kind": "status", "target": "m-1", "as_of": 12})])))
    add("status shows revoked before action", ("violated", "I6"), lambda p, I, *a: (
        revocable(p, I), p.update(statuses=[I.sign({"kind": "status", "target": "m-1", "as_of": 12, "revoked_at": 7})])))
    # 3. actor required for high-impact effects
    add("independently observed high-impact effect", ("preserved", "-"), lambda p, *a: high_impact(p))
    add("high-impact effect without actor", ("unresolved", "I10"), lambda p, *a: high_impact(p, actor=None))
    # 4. every receipt for an invocation is evaluated
    add("second effect outside declared", ("violated", "I2"), lambda p, I, H, O, X: p["effects"].append(
        O.sign({**p["effects"][0], "id": "e-2", "executed": {**p["effects"][0]["executed"], "resource": "repo:app/src/secrets.ts", "t": 12}})))
    add("same effect observed twice (host and backend)", ("preserved", "-"), lambda p, I, H, O, X: (
        budgets(p, I, H, 10, 5, 3),
        p["effects"].append(O.sign({**p["effects"][0], "id": "e-2", "observed_by": "provider:git", "assurance": "L3"}))))
    # 5. approvals bind the body without t; single use across the packet
    add("approval reused for a second invocation", ("violated", "I8"), lambda p, I, H, O, X: (
        p.update(approvals=[approve(p, "ap-8", expiry=50)]),
        p.update(invocations=[H.sign({**p["invocations"][0], "approval_ref": "ap-8"})]),
        p["invocations"].append(H.sign({**p["invocations"][0], "id": "i-2", "t": 20})),
        p["effects"].append(O.sign({**p["effects"][0], "id": "e-2", "invocation": "i-2", "executed": {**p["effects"][0]["executed"], "t": 21}}))))
    # 6. findings must be signed to count as trusted
    finding = lambda label: {"id": "f-2", "kind": "finding", "source_locator": "repo:app/README.md", "content_hash": "ab" * 32, "integrity_label": label}
    add("mutation influenced only by trusted content", ("preserved", "-"), lambda p, I, H, O, X: (
        p.update(findings=[H.sign(finding("trusted"))]), p.update(invocations=[H.sign({**p["invocations"][0], "influenced_by": ["f-2"]})])))
    add("unsigned finding claims trusted", ("violated", "I4"), lambda p, I, H, O, X: (
        p.update(findings=[finding("trusted")]), p.update(invocations=[H.sign({**p["invocations"][0], "influenced_by": ["f-2"]})])))

    # 7. RFC 3339 times
    def rfc3339(p, I, H, O, effect_t=11):
        p.update(mandates=[I.sign({**p["mandates"][0], "claims": claims_of(p, "mandates", exp=iso(100))})])
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", exp=iso(90))})])
        p.update(invocations=[H.sign({**p["invocations"][0], "t": iso(10)})])
        p.update(effects=[O.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "t": iso(effect_t)}})])
    add("RFC 3339 timestamps", ("preserved", "-"), lambda p, I, H, O, X: rfc3339(p, I, H, O))
    add("RFC 3339 effect after expiry", ("violated", "I2"), lambda p, I, H, O, X: rfc3339(p, I, H, O, effect_t=95))
    add("malformed timestamp", ("unresolved", "I7"), lambda p, I, H, O, X: p.update(invocations=[H.sign({**p["invocations"][0], "t": "2026-01-01 00:00:10"})]))
    # 8. RFC 8785: UTF-16 key order and ECMAScript number form
    add("JCS canonical form (unicode keys, floats)", ("preserved", "-"), lambda p, I, H, O, X: p.update(invocations=[H.sign({**p["invocations"][0],
        "x-note": "café ☕", "x-é": 1, "x-z": 0.1, "x-｡": "halfwidth", "x-\U0001F600": "astral", "x-big": 1e21, "x-small": 1.5e-7, "x-whole": 100.0, "x-neg": -2.5})]))

    # ---- draft.3: decision phase, quarantine, deny lists, scenario vectors A1/A3/A6 ----
    # phase (spec 5.13): only pre-execution decisions can confirm a block or be contradicted
    add("post-execution decision cannot claim a block", ("unresolved", "I7"), lambda p, I, H, O, X: (
        p.update(decisions=[decision(H, "cd-4", phase="post_execution", enforcement={"pep": "audit-ingest/1.0", "fail_mode": "closed", "applied": "confirmed"})]),
        p.update(effects=[])))
    add("simulated deny is not enforcement", ("preserved", "-"), lambda p, I, H, O, X:
        p.update(decisions=[decision(H, "cd-5", phase="simulation")]))
    # A6: an audit log reveals an unknown agent's read; detection must not read as mediation
    add("audit-only discovery of an unknown agent (A6)", ("violated", "I11"), lambda p, I, H, O, X: (
        p["effects"].append(O.sign({"id": "e-6", "kind": "effect", "invocation": "unknown:audit-7731", "observed_by": "provider:ehr", "assurance": "L3",
            "executed": {"action": "saas.read", "resource": "ehr:patient/991", "effect": "read", "released": ["phi->internal"], "t": 30}})),
        p.update(decisions=[decision(H, "cd-6", mode="observe", phase="post_execution", inv="unknown:audit-7731", reason="detected after execution from provider audit log")])))
    # quarantine (A1): untrusted repository content is withheld from later steps
    untrusted = lambda H: H.sign({"id": "f-1", "kind": "finding", "source_locator": "repo:app/README.md", "content_hash": "cd" * 32,
                                  "hidden_mechanism": "html_comment", "integrity_label": "untrusted",
                                  "requested": {"action": "http.post", "object": "env", "recipient": "external"}})
    def quarantine(p, I, H, O, confirmed=None):
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", actions=["fs.write", "fs.read"])})])
        read = H.sign({**p["invocations"][0], "declared": {"action": "fs.read", "resource": "repo:app/src/README.md", "effect": "read"}})
        later = {**p["invocations"][0], "id": "i-2", "t": 20, "influenced_by": ["f-1"],
                 "declared": {"action": "fs.read", "resource": "repo:app/src/auth.ts", "effect": "read"}}
        if confirmed: later["principal_confirmed"] = True
        p.update(findings=[untrusted(H)], invocations=[read, H.sign(later)],
                 effects=[O.sign({**p["effects"][0], "executed": {"action": "fs.read", "resource": "repo:app/src/README.md", "effect": "read", "released": [], "t": 11}}),
                          O.sign({**p["effects"][0], "id": "e-2", "invocation": "i-2", "executed": {"action": "fs.read", "resource": "repo:app/src/auth.ts", "effect": "read", "released": [], "t": 21}})],
                 decisions=[decision(H, "cd-7", mode="quarantine", outcome="preserved", quarantined=["f-1"],
                                     enforcement={"pep": "host-hook/2.0", "fail_mode": "closed", "host_supports": ["replace_output"]})])
    add("quarantined content reached the agent (A1)", ("violated", "I4"), lambda p, I, H, O, X: quarantine(p, I, H, O))
    add("quarantined content promoted by the principal", ("preserved", "-"), lambda p, I, H, O, X: quarantine(p, I, H, O, confirmed=True))
    # deny lists (spec 5.3, 7)
    def denies(p, I, mandate_deny, delegation_deny):
        p.update(mandates=[I.sign({**p["mandates"][0], "claims": claims_of(p, "mandates", **mandate_deny)})])
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", **delegation_deny)})])
    secret = {"deny_resources": ["repo:app/src/secrets/*"]}
    def to_secret(p, H, O):
        p.update(invocations=[H.sign({**p["invocations"][0], "declared": {**p["invocations"][0]["declared"], "resource": "repo:app/src/secrets/key.ts"}})])
        p.update(effects=[O.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "resource": "repo:app/src/secrets/key.ts"}})])
    add("effect on a denied resource", ("violated", "I2"), lambda p, I, H, O, X: (denies(p, I, secret, secret), to_secret(p, H, O)))
    add("denied action", ("violated", "I2"), lambda p, I, H, O, X: denies(p, I, {"deny_actions": ["fs.write"]}, {"deny_actions": ["fs.write"]}))
    add("delegation removes a deny", ("violated", "I1"), lambda p, I, H, O, X: denies(p, I, secret, {}))
    add("intent cannot lift a deny", ("violated", "I2"), lambda p, I, H, O, X: (
        denies(p, I, secret, secret), to_secret(p, H, O),
        p.update(intents=[I.sign({"id": "n-3", "kind": "intent", "claims": {"actions": ["fs.write"], "resources": ["repo:app/src/*"], "data": ["source->internal"], "ceiling": "write_local", "exp": 90}})]),
        p.update(invocations=[H.sign({**p["invocations"][0], "intent_ref": "n-3"})])))
    add("delegation adds a deny", ("preserved", "-"), lambda p, I, H, O, X: denies(p, I, secret, {"deny_resources": ["repo:app/src/secrets/*", "repo:app/src/generated/*"]}))
    # A3: cleanup approved for ./build, executed against the whole repository
    def build_cleanup(p, I, H, O, executed_resource):
        c = {"actions": ["fs.delete"], "resources": ["repo:app/build/*"], "data": [], "ceiling": "destructive", "exp": 90}
        p.update(mandates=[I.sign({**p["mandates"][0], "claims": {**c, "exp": 100, "depth": 2}})])
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": {**c, "depth": 1}})])
        p.update(invocations=[H.sign({**p["invocations"][0], "actor": "agent:assistant-1", "declared": {"action": "fs.delete", "resource": "repo:app/build/", "effect": "destructive"}})])
        p.update(effects=[O.sign({**p["effects"][0], "observed_by": "fs-audit:host", "assurance": "L2",
                                  "executed": {"action": "fs.delete", "resource": executed_resource, "effect": "destructive", "released": [], "t": 11}})])
    add("build cleanup within scope", ("preserved", "-"), lambda p, I, H, O, X: build_cleanup(p, I, H, O, "repo:app/build/"))
    add("destructive command drift (A3)", ("violated", "I2"), lambda p, I, H, O, X: build_cleanup(p, I, H, O, "repo:app/"))
    return keys, V


def check_dir(d: str) -> int:
    keys = json.load(open(os.path.join(d, "keys.json")))
    n = ok = 0
    for sub in ("positive", "must-reject"):
        for f in sorted(os.listdir(os.path.join(d, sub))):
            if not f.endswith(".json"):
                continue
            v = json.load(open(os.path.join(d, sub, f)))
            r = verdict(evaluate(v["packet"], keys))
            n += 1
            if (r.outcome, r.invariant) == (v["expect"]["outcome"], v["expect"]["invariant"]):
                ok += 1
            else:
                print(f"FAIL {sub}/{f}: got {r.outcome}/{r.invariant} ({r.reason})")
    print(f"python verifier agrees with expected outcomes on {ok}/{n} vectors (from disk)")
    return 0 if ok == n else 1


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        sys.exit(check_dir(sys.argv[2]))
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "vectors")
    keys, V = vectors()
    passed = 0
    for sub in ("positive", "must-reject"):
        os.makedirs(f"{out_dir}/{sub}", exist_ok=True)
        for f in os.listdir(f"{out_dir}/{sub}"):
            if f.endswith(".json"):
                os.remove(f"{out_dir}/{sub}/{f}")
    json.dump(keys, open(f"{out_dir}/keys.json", "w"), indent=1)
    for name, (exp_out, exp_inv), packet in V:
        r = verdict(evaluate(packet, keys))
        slug = "".join(ch if ch.isalnum() else "-" for ch in name.lower()).strip("-")
        folder = "positive" if exp_out == "preserved" else "must-reject"
        json.dump({"name": name, "expect": {"outcome": exp_out, "invariant": exp_inv}, "packet": packet},
                  open(f"{out_dir}/{folder}/{slug}.json", "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        ok = (r.outcome, r.invariant) == (exp_out, exp_inv)
        passed += ok
        if not ok:
            print(f"FAIL  {name:45} -> {r.outcome:10} {r.invariant:3} {r.reason}   (expected {exp_out}/{exp_inv})")
    print(f"{passed}/{len(V)} vectors pass (in memory)")
    sys.exit(0 if passed == len(V) else 1)
