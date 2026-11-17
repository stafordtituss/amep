"""Generate the delegation-continuity test materials for the W3C Agent Identity Registry Protocol CG.

Scenario (the CG's hiring use case, extended with one delegation hop):
  H  did:web:acme.example:people:hr-lead          the human principal
  A  did:aria:acme.example:hiring-agent           holds H's mandate
  B  did:aria:acme.example:scheduling-agent       receives a narrower delegation from A
  T  service:calendar.acme.example                the tool B calls; it signs what it actually did

ARIA scopes (namespace:resource:action) are written as AMEP claims:
  calendar:interview:write  ->  action "calendar.write", resources "calendar:interview/..."

Run from the repository root:
  python3 -I interop/w3c-agent-identity/delegation-continuity/generate.py
Writes keys.json, positive/ and must-reject/ next to this file and checks every vector with the
AMEP reference verifier. Keys are deterministic TEST keys; never use them for anything else.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..", "..")
sys.path.insert(0, os.path.join(ROOT, "verifier", "python"))
sys.path.insert(0, os.path.join(ROOT, "packages", "python", "src"))

from amep_verifier import Signer  # noqa: E402
from amep_protocol.core import approval_digest, evaluate, verdict  # noqa: E402

H_DID = "did:web:acme.example:people:hr-lead"
A_DID = "did:aria:acme.example:hiring-agent"
B_DID = "did:aria:acme.example:scheduling-agent"
C_DID = "did:aria:acme.example:reminder-agent"
T_ID = "service:calendar.acme.example"
EXEC_DENY = ["calendar:interview/executive/*"]


def base(I, Hk, O):
    mandate = I.sign({"id": "m-1", "kind": "mandate", "principal": H_DID, "claims": {
        "actions": ["hiring.read", "calendar.write", "communication.send"],
        "resources": ["hiring:candidate/*", "calendar:interview/*", "communication:candidate/*"],
        "deny_resources": EXEC_DENY,
        "data": ["candidate_pii->internal"], "ceiling": "external_send", "exp": 100, "depth": 2}})
    delegation = I.sign({"id": "d-1", "kind": "delegation", "parent": "m-1", "claims": {
        "actions": ["calendar.write"], "resources": ["calendar:interview/req-1042/*"],
        "deny_resources": EXEC_DENY,
        "data": ["candidate_pii->internal"], "ceiling": "write_shared", "exp": 90, "depth": 0}})
    interp = Hk.sign({"id": "a-1", "kind": "interpretation", "source": "curated", "adapter": "calendar_api", "version": "v3"})
    inv = Hk.sign({"id": "i-1", "kind": "invocation", "authority_ref": "d-1", "interpretation_ref": "a-1", "actor": B_DID, "t": 10,
                   "declared": {"action": "calendar.write", "resource": "calendar:interview/req-1042/slot-3", "effect": "write_shared"}})
    eff = O.sign({"id": "e-1", "kind": "effect", "invocation": "i-1", "observed_by": T_ID, "assurance": "L3",
                  "executed": {"action": "calendar.write", "resource": "calendar:interview/req-1042/slot-3", "effect": "write_shared",
                               "released": [], "reversible": True, "t": 11}})
    return {"mandates": [mandate], "delegations": [delegation], "interpretations": [interp], "invocations": [inv], "effects": [eff]}


def build():
    I, Hk, O, X = Signer("issuer-1", ["issuer", "approver"]), Signer("host-1", ["host"]), Signer("observer-1", ["observer"]), Signer("attacker")
    keys = {s.kid: s.public() for s in (I, Hk, O)}
    V = []

    def add(slug, question, expect, aria, mutate=lambda p: None):
        p = base(I, Hk, O)
        mutate(p)
        V.append({"name": slug, "question": question, "aria": aria, "expect": {"outcome": expect[0], "invariant": expect[1]}, "packet": p})

    def dclaims(p, **kw):
        return {**p["delegations"][0]["claims"], **kw}

    def set_delegation(p, **kw):
        p["delegations"][0] = I.sign({**p["delegations"][0], "claims": dclaims(p, **kw)})

    def set_effect(p, **kw):
        e = p["effects"][0]
        p["effects"][0] = O.sign({**e, "executed": {**e["executed"], **kw}})

    def set_inv(p, **kw):
        p["invocations"][0] = Hk.sign({**p["invocations"][0], **kw})

    def revocable(p):
        p["mandates"][0] = I.sign({**p["mandates"][0], "revocation": {"status_ref": "https://acme.example/status/m-1"}})

    def approve(p, aid, **kw):
        return I.sign({"id": aid, "kind": "approval", "effect_digest": approval_digest(p["effects"][0]["executed"]), "presence": "webauthn", **kw})

    # ---- preserved ----
    add("within-bounds", "Can B prove whose authority it holds, and that the effect stayed inside it?", ("preserved", "-"),
        "§6: every hop signed, scope only narrows, principal traceable")
    add("deny-added-by-delegate", "A delegate may add restrictions.", ("preserved", "-"),
        "§6 scope narrowing; deny overrides allow",
        lambda p: set_delegation(p, deny_resources=EXEC_DENY + ["calendar:interview/req-1042/panel-2/*"]))
    add("revoked-after-the-action", "Was the authority in force at the time of the action (state at a past date)?", ("preserved", "-"),
        "§7 revocation is terminal, but not retroactive; agenda 4.3.6",
        lambda p: p.update(revocations=[I.sign({"kind": "revocation", "target": "m-1", "t": 50})]))
    add("fresh-status", "Revocable authority, status checked after the action.", ("preserved", "-"),
        "§7 Bitstring Status List freshness",
        lambda p: (revocable(p), p.update(statuses=[I.sign({"kind": "status", "target": "m-1", "as_of": 12})])))
    add("approval-bound-to-effect", "A required human approval covers exactly the effect executed.", ("preserved", "-"),
        "hitlRequired: approval present and bound",
        lambda p: (p.update(approvals=[approve(p, "ap-1", expiry=50)]), set_inv(p, approval_ref="ap-1")))

    # ---- must reject: the chain itself ----
    add("delegation-widens-scope", "Did the effective scope expand along the chain?", ("violated", "I1"),
        "§6 scope can only narrow",
        lambda p: set_delegation(p, resources=["calendar:*"]))
    add("delegation-raises-effect-class", "B's grant carries a higher effect class (sending outside the organization) than the authority it came from.", ("violated", "I1"),
        "§6 scope can only narrow (action class)",
        lambda p: (p.__setitem__("mandates", [I.sign({**p["mandates"][0], "claims": {**p["mandates"][0]["claims"], "ceiling": "write_shared"}})]),
                   set_delegation(p, ceiling="external_send")))
    add("delegation-drops-a-deny", "Did a constraint from H's authorization fail to survive the delegation?", ("violated", "I1"),
        "§6; a matching deny overrides an allow",
        lambda p: p["delegations"].__setitem__(0, I.sign({**p["delegations"][0], "claims": {k: v for k, v in dclaims(p).items() if k != "deny_resources"}})))
    add("delegation-outlives-parent", "Does the delegation stay valid after the authority it came from expires?", ("violated", "I1"),
        "§6 scope can only narrow (validity)",
        lambda p: set_delegation(p, exp=200))
    add("redelegation-without-right", "Did A have authority to re-delegate? (B, holding depth 0, delegates on to C)", ("violated", "I1"),
        "§4 maxDelegationDepth, §6 delegationDepth",
        lambda p: (p["delegations"].append(I.sign({"id": "d-2", "kind": "delegation", "parent": "d-1", "claims": dclaims(p, exp=80, depth=0)})),
                   set_inv(p, authority_ref="d-2", actor=C_DID)))
    add("depth-not-decreasing", "Each hop must spend delegation depth.", ("violated", "I1"),
        "§6 delegationDepth",
        lambda p: set_delegation(p, depth=2))

    # ---- must reject: the effect ----
    add("effect-outside-delegated-scope", "B acts on a different requisition than it was delegated.", ("violated", "I2"),
        "receiver policy; scope is intent only",
        lambda p: (set_inv(p, declared={"action": "calendar.write", "resource": "calendar:interview/req-2077/slot-1", "effect": "write_shared"}),
                   set_effect(p, resource="calendar:interview/req-2077/slot-1")))
    add("executed-differs-from-declared", "The tool reports it deleted the slot B said it would write.", ("violated", "I2"),
        "evidence of the action, not the declared scope",
        lambda p: set_effect(p, action="calendar.delete", effect="destructive", reversible=False))

    # ---- must reject: liveness ----
    add("root-revoked-before-action", "Has any upstream authorization since been revoked?", ("violated", "I6"),
        "§7 revocation is terminal and propagates down the chain",
        lambda p: p.update(revocations=[I.sign({"kind": "revocation", "target": "m-1", "t": 5})]))
    add("status-shows-revoked", "The status list shows the root revoked before the action.", ("violated", "I6"),
        "§7 Bitstring Status List",
        lambda p: (revocable(p), p.update(statuses=[I.sign({"kind": "status", "target": "m-1", "as_of": 12, "revoked_at": 7})])))
    add("stale-status", "The only status available predates the action.", ("unresolved", "I7"),
        "§7 freshness (ARIA AP: max age 3600 s)",
        lambda p: (revocable(p), p.update(statuses=[I.sign({"kind": "status", "target": "m-1", "as_of": 3})])))

    # ---- must reject: evidence ----
    add("identity-only", "B has a valid identity but no evidence of delegated authority.", ("unresolved", "I7"),
        "identity is not authorization", lambda p: p.update(mandates=[], delegations=[]))
    add("self-issued-delegation", "B signs its own delegation with a key that holds no issuer role.", ("unresolved", "I7"),
        "§6 every hop signed by the delegator",
        lambda p: p["delegations"].__setitem__(0, X.sign({**p["delegations"][0]})))
    add("approval-for-a-different-effect", "The human approved one effect; another was executed (time of check vs time of use).", ("violated", "I8"),
        "hitlRequired: approval must bind to the effect",
        lambda p: (p.update(approvals=[I.sign({"id": "ap-2", "kind": "approval", "effect_digest": "0" * 64, "presence": "webauthn", "expiry": 50})]),
                   set_inv(p, approval_ref="ap-2")))
    add("approval-replayed", "An approval already consumed is presented again.", ("violated", "I8"),
        "hitlRequired: single use",
        lambda p: (p.update(approvals=[approve(p, "ap-3", expiry=50, consumed=True)]), set_inv(p, approval_ref="ap-3")))
    return keys, V


def main():
    keys, V = build()
    for sub in ("positive", "must-reject"):
        os.makedirs(os.path.join(HERE, sub), exist_ok=True)
        for f in os.listdir(os.path.join(HERE, sub)):
            if f.endswith(".json"):
                os.remove(os.path.join(HERE, sub, f))
    json.dump(keys, open(os.path.join(HERE, "keys.json"), "w"), indent=1)
    ok = 0
    for v in V:
        r = verdict(evaluate(json.loads(json.dumps(v["packet"])), keys))
        good = (r.outcome, r.invariant) == (v["expect"]["outcome"], v["expect"]["invariant"])
        ok += good
        if not good:
            print(f"FAIL {v['name']}: got {r.outcome}/{r.invariant} ({r.reason}), expected {v['expect']}")
        sub = "positive" if v["expect"]["outcome"] == "preserved" else "must-reject"
        json.dump(v, open(os.path.join(HERE, sub, v["name"] + ".json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"{ok}/{len(V)} vectors match their expected outcome")
    return 0 if ok == len(V) else 1


if __name__ == "__main__":
    sys.exit(main())
