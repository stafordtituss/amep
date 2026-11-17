"""AMEP v0.2 reference verifier (Python) and conformance-vector generator.

Generates the conformance vectors and checks them with the amep_protocol package (packages/python). Offline: verifies Ed25519 signatures over the RFC 8785 (JCS)
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
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "packages", "python", "src"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from amep_protocol.core import approval_digest, canon, evaluate, verdict  # noqa: E402

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

    def add(name, expect, mutate, state=None):
        p = base(I, H, O)
        mutate(p, I, H, O, X)
        V.append((name, expect, p, state))

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

    # ---- draft.4: data lineage (A5) and cross-packet state ----
    def read_then_send(p, I, H, O, recipient="external", derived=("i-1",)):
        c = {"actions": ["fs.read", "http.post"], "resources": ["repo:app/*", "https://api.example/*"],
             "data": ["confidential->internal"], "ceiling": "external_send"}
        p.update(mandates=[I.sign({**p["mandates"][0], "claims": {**c, "exp": 100, "depth": 2}})])
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": {**c, "exp": 90, "depth": 1}})])
        read = H.sign({**p["invocations"][0], "declared": {"action": "fs.read", "resource": "repo:app/docs/plan.md", "effect": "read"}})
        send = H.sign({**p["invocations"][0], "id": "i-2", "t": 20, "actor": "agent:assistant-1", "derived_from": list(derived),
                       "declared": {"action": "http.post", "resource": "https://api.example/upload", "effect": "external_send"}})
        p.update(invocations=[read, send], effects=[
            O.sign({**p["effects"][0], "executed": {"action": "fs.read", "resource": "repo:app/docs/plan.md", "effect": "read",
                                                    "released": [], "accessed": ["confidential"], "t": 11}}),
            O.sign({**p["effects"][0], "id": "e-2", "invocation": "i-2", "observed_by": "proxy:egress", "assurance": "L2",
                    "executed": {"action": "http.post", "resource": "https://api.example/upload", "effect": "external_send",
                                 "released": [], "recipient": recipient, "t": 21}})])
    add("data leaving after a read (A5)", ("violated", "I5"), lambda p, I, H, O, X: read_then_send(p, I, H, O))
    add("derived data sent to an allowed recipient", ("preserved", "-"), lambda p, I, H, O, X: read_then_send(p, I, H, O, recipient="internal"))
    add("lineage reference not found", ("unresolved", "I7"), lambda p, I, H, O, X: read_then_send(p, I, H, O, derived=("i-404",)))
    # cross-packet state (spec 10.6): the verifier carries approval use and budget spending between packets
    body_digest = approval_digest({"action": "fs.write", "resource": "repo:app/src/auth.ts", "effect": "write_local", "released": []})
    add("approval reused across packets", ("violated", "I8"), lambda p, I, H, O, X: (
        p.update(approvals=[approve(p, "ap-9", expiry=50)]), p.update(invocations=[H.sign({**p["invocations"][0], "approval_ref": "ap-9"})])),
        state={"approvals_used": {"ap-9": ["i-0", body_digest]}, "spent": {}})
    add("budget spent in earlier packets", ("violated", "I2"), lambda p, I, H, O, X: budgets(p, I, H, 10, 5, 3),
        state={"approvals_used": {}, "spent": {"m-1": 4, "d-1": 4}})
    add("budget from earlier packets still within limit", ("preserved", "-"), lambda p, I, H, O, X: budgets(p, I, H, 10, 5, 3),
        state={"approvals_used": {}, "spent": {"m-1": 2, "d-1": 2}})
    return keys, V


def check_dir(d: str) -> int:
    keys = json.load(open(os.path.join(d, "keys.json")))
    n = ok = 0
    for sub in ("positive", "must-reject"):
        for f in sorted(os.listdir(os.path.join(d, sub))):
            if not f.endswith(".json"):
                continue
            v = json.load(open(os.path.join(d, sub, f)))
            r = verdict(evaluate(v["packet"], keys, state=v.get("state")))
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
    for name, (exp_out, exp_inv), packet, state in V:
        doc = {"name": name, "expect": {"outcome": exp_out, "invariant": exp_inv}, "packet": packet}
        if state is not None:
            doc["state"] = json.loads(json.dumps(state))   # stored before evaluation mutates it
        r = verdict(evaluate(packet, keys, state=state))
        slug = "".join(ch if ch.isalnum() else "-" for ch in name.lower()).strip("-")
        folder = "positive" if exp_out == "preserved" else "must-reject"
        json.dump(doc, open(f"{out_dir}/{folder}/{slug}.json", "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        ok = (r.outcome, r.invariant) == (exp_out, exp_inv)
        passed += ok
        if not ok:
            print(f"FAIL  {name:45} -> {r.outcome:10} {r.invariant:3} {r.reason}   (expected {exp_out}/{exp_inv})")
    print(f"{passed}/{len(V)} vectors pass (in memory)")
    sys.exit(0 if passed == len(V) else 1)
