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

from amep_protocol.core import approval_digest, canon, evaluate, evaluate_text, signing_input, verdict  # noqa: E402

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

    def sign(self, body: dict, v: int = 1) -> dict:
        """v=1: the v0.2 signing input. v=2: the domain-separated input of spec 12.2 (AMEP 0.3)."""
        body = {k: v_ for k, v_ in body.items() if k != "proof"}
        if v == 2:
            proof = {"kid": self.kid, "alg": "Ed25519", "v": 2}
            return {**body, "proof": {**proof, "sig": self.key.sign(signing_input({**body, "proof": proof})).hex()}}
        # strict=False so the suite can contain numbers outside the I-JSON range that verifiers must reject
        return {**body, "proof": {"kid": self.kid, "alg": "Ed25519", "sig": self.key.sign(canon(body, strict=False)).hex()}}



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
    # Principal confirmation (spec 5.11, v0.3.3), from tclancy's review (stafordtituss/amep#34): the confirmation is an
    # approval signed by the principal's approver key that names the findings shown, bound to the executed effect.
    # A host-signed principal_confirmed: true on its own leaves the call unresolved, never cleared.
    def influenced(p, H, **kw):
        p.update(invocations=[H.sign({**p["invocations"][0], "influenced_by": ["f-1"], **kw})])
    def confirmed(p, I, H, signer=None, findings=("f-1",), presence="webauthn", approver="user:alice"):
        influenced(p, H, principal_confirmed=True)
        ap = {"id": "ap-c", "kind": "approval", "effect_digest": approval_digest(p["effects"][0]["executed"]),
              "presence": presence, "approver": approver, "findings": list(findings)}
        p.update(approvals=[(signer or I).sign(ap)],
                 invocations=[H.sign({**{k: v for k, v in p["invocations"][0].items() if k != "proof"}, "approval_ref": "ap-c"})])
    add("influence confirmed by principal", ("preserved", "-"), lambda p, I, H, O, X: confirmed(p, I, H))
    add("influence confirmed only by the host's flag", ("unresolved", "I4"), lambda p, I, H, O, X: influenced(p, H, principal_confirmed=True))
    add("principal confirmation that does not name the finding", ("unresolved", "I4"), lambda p, I, H, O, X: confirmed(p, I, H, findings=("f-2",)))
    add("principal confirmation signed by a host key", ("unresolved", "I4"), lambda p, I, H, O, X: confirmed(p, I, H, signer=H))
    # From tclancy's follow-up on #39: the principal must be present, and the confirmation must be the principal's.
    add("principal confirmation with host_ui presence", ("unresolved", "I4"), lambda p, I, H, O, X: confirmed(p, I, H, presence="host_ui"))
    add("principal confirmation by an approver other than the principal", ("unresolved", "I4"), lambda p, I, H, O, X: confirmed(p, I, H, approver="user:mallory"))
    add("influenced read-only action", ("preserved", "-"), lambda p, I, H, O, X: (
        p.update(invocations=[H.sign({**p["invocations"][0], "influenced_by": ["f-1"], "declared": {"action": "fs.read", "resource": "repo:app/src/auth.ts", "effect": "read"}})]),
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", actions=["fs.write", "fs.read"])})]),
        p.update(effects=[O.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "action": "fs.read", "effect": "read"}})])))
    add("mediated effect not honored", ("violated", "I2"), lambda p, I, H, O, X: p.update(invocations=[H.sign({**p["invocations"][0], "mediated": {**p["effects"][0]["executed"], "resource": "repo:app/src/build/x"}})]))
    add("self-reported high-impact effect", ("unresolved", "I10"), lambda p, *a: high_impact(p, observed_by="agent:assistant-1", assurance="L0"))
    # spec 10.2: the same effect recorded by several observers is one effect, so the actor's own receipt beside an
    # independent receipt of the same body is corroborated. Found while mapping the OWASP Agentic Evidence scenario A1
    # (OWASP/Agentic-Evidence#2): an asserted tool.result next to an independent observation came out unresolved.
    def corroborate(p, O, copies):
        e = {k: v for k, v in p["effects"][0].items() if k != "proof"}
        for n in range(copies):
            p["effects"].append(O.sign({**e, "id": f"e-self-{n}", "observed_by": "agent:assistant-1", "assurance": "L1"}))
    add("self-reported high-impact effect corroborated by an independent observer", ("preserved", "-"), lambda p, I, H, O, X: (
        high_impact(p), corroborate(p, O, 1)))
    add("self-report of two executions, one independently observed", ("unresolved", "I10"), lambda p, I, H, O, X: (
        high_impact(p), corroborate(p, O, 2)))
    # From tclancy's review (stafordtituss/amep#36): an invocation missing from the packet may have been left out by its
    # assembler, so the effect is unresolved (need invocation), with no one blamed (spec 10.4, v0.3.3).
    add("bypass: effect without invocation", ("unresolved", "I11"), lambda p, I, H, O, X: p["effects"].append(O.sign({"id": "e-9", "kind": "effect", "invocation": "i-404", "observed_by": "provider:github", "assurance": "L3",
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
    def decision(H, did, mode="deny", phase="pre_execution", inv="i-1", v=1, **kw):
        body = {"id": did, "kind": "decision", "invocation": inv, "outcome": "violated", "mode": mode, "phase": phase, **kw}
        return H.sign(body, v=2) if v == 2 else H.sign(body)
    add("deny contradicted by executed effect", ("violated", "I11"), lambda p, I, H, O, X:
        p.update(decisions=[decision(H, "cd-1", enforcement={"pep": "host-hook/1.0", "fail_mode": "open", "encoded_as": "ask"})]))
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
        "x-note": "café ☕", "x-é": 1, "x-z": 0.1, "x-｡": "halfwidth", "x-\U0001F600": "astral", "x-big": 1e15, "x-small": 1.5e-7, "x-whole": 100.0, "x-neg": -2.5})]))

    # ---- draft.3: decision phase, quarantine, deny lists, scenario vectors A1/A3/A6 ----
    # phase (spec 5.13): only pre-execution decisions can confirm a block or be contradicted
    add("post-execution decision cannot claim a block", ("unresolved", "I7"), lambda p, I, H, O, X: (
        p.update(decisions=[decision(H, "cd-4", phase="post_execution", enforcement={"pep": "audit-ingest/1.0", "fail_mode": "closed", "applied": "confirmed"})]),
        p.update(effects=[])))
    add("simulated deny is not enforcement", ("preserved", "-"), lambda p, I, H, O, X:
        p.update(decisions=[decision(H, "cd-5", phase="simulation")]))
    # A6: an audit log reveals an unknown agent's read; detection must not read as mediation
    add("audit-only discovery of an unknown agent (A6)", ("unresolved", "I11"), lambda p, I, H, O, X: (
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
        approvals = []
        if confirmed == "signed":   # the principal's own confirmation, bound to the effect of i-2 (spec 5.11, v0.3.3)
            later["approval_ref"] = "ap-q"
            approvals = [I.sign({"id": "ap-q", "kind": "approval", "presence": "webauthn", "approver": "user:alice", "findings": ["f-1"],
                                 "effect_digest": approval_digest({"action": "fs.read", "resource": "repo:app/src/auth.ts", "effect": "read", "released": [], "t": 21})})]
        if approvals: p["approvals"] = approvals
        p.update(findings=[untrusted(H)], invocations=[read, H.sign(later)],
                 effects=[O.sign({**p["effects"][0], "executed": {"action": "fs.read", "resource": "repo:app/src/README.md", "effect": "read", "released": [], "t": 11}}),
                          O.sign({**p["effects"][0], "id": "e-2", "invocation": "i-2", "executed": {"action": "fs.read", "resource": "repo:app/src/auth.ts", "effect": "read", "released": [], "t": 21}})],
                 decisions=[decision(H, "cd-7", mode="quarantine", outcome="preserved", quarantined=["f-1"],
                                     enforcement={"pep": "host-hook/2.0", "fail_mode": "closed", "host_supports": ["replace_output"]})])
    add("quarantined content reached the agent (A1)", ("violated", "I4"), lambda p, I, H, O, X: quarantine(p, I, H, O))
    add("quarantined content promoted by the principal", ("preserved", "-"), lambda p, I, H, O, X: quarantine(p, I, H, O, confirmed="signed"))
    add("quarantined content promoted only by the host's flag", ("unresolved", "I4"), lambda p, I, H, O, X: quarantine(p, I, H, O, confirmed=True))
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

    # Suite v0.2.1: vectors added from mutation analysis of the reference evaluator (paper/eval/mutation.py).
    # Each one distinguishes a rule, or the inclusive edge of a bound, that no earlier vector isolated.
    def deleg(p, I, **kw):
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", **kw)})])

    def mand(p, I, **kw):
        p.update(mandates=[I.sign({**p["mandates"][0], "claims": claims_of(p, "mandates", **kw)})])

    def times(p, H, O, inv_t=None, eff_t=None):
        if inv_t is not None:
            p.update(invocations=[H.sign({**p["invocations"][0], "t": inv_t})])
        if eff_t is not None:
            p.update(effects=[O.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "t": eff_t}})])

    def shared(p, I, H, O, observed_by, assurance, ceiling="write_shared"):
        """A write_shared effect (high impact, spec 8.3) by a named actor."""
        mand(p, I, ceiling="write_shared")
        deleg(p, I, ceiling=ceiling)
        p.update(invocations=[H.sign({**p["invocations"][0], "actor": "agent:assistant-1",
                                      "declared": {**p["invocations"][0]["declared"], "effect": "write_shared"}})])
        p.update(effects=[O.sign({**p["effects"][0], "observed_by": observed_by, "assurance": assurance,
                                  "executed": {**p["effects"][0]["executed"], "effect": "write_shared"}})])

    def with_approval(p, I, H, aid, **kw):
        p.update(approvals=[approve(p, aid, **kw)])
        p.update(invocations=[H.sign({**p["invocations"][0], "approval_ref": aid})])

    # rules no earlier vector isolated
    add("delegation widens actions", ("violated", "I1"), lambda p, I, H, O, X: deleg(p, I, actions=["fs.write", "net.send"]))
    add("action outside delegated actions", ("violated", "I2"), lambda p, I, H, O, X: (
        mand(p, I, actions=["fs.*", "process.exec"]),
        p.update(invocations=[H.sign({**p["invocations"][0], "declared": {**p["invocations"][0]["declared"], "action": "process.exec"}})]),
        p.update(effects=[O.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "action": "process.exec"}})])))
    add("effect class above delegated ceiling", ("violated", "I2"), lambda p, I, H, O, X: shared(p, I, H, O, "proxy:egress", "L2", ceiling="write_local"))
    add("write_shared effect only self-reported", ("unresolved", "I10"), lambda p, I, H, O, X: shared(p, I, H, O, "agent:assistant-1", "L1"))
    add("intent reference names a non-intent object", ("unresolved", "I7"), lambda p, I, H, O, X:
        p.update(invocations=[H.sign({**p["invocations"][0], "intent_ref": "d-1"})]))
    add("approval not yet valid", ("violated", "I8"), lambda p, I, H, O, X: with_approval(p, I, H, "ap-10", nbf=20))
    add("violation outranks unresolved in one packet", ("violated", "I2"), lambda p, I, H, O, X: (
        p.update(invocations=[H.sign({**p["invocations"][0], "id": "i-0", "t": 9}), p["invocations"][0]]),
        p.update(effects=[O.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "resource": "repo:app/.env"}})])))
    # inclusive edges of every time, budget and window bound (spec 7.1 rule 5, 7.3 rule 7, 5.10, 5.12)
    add("delegation expiring with its parent", ("preserved", "-"), lambda p, I, H, O, X: deleg(p, I, exp=100))
    add("delegation keeps the parent's full budget", ("preserved", "-"), lambda p, I, H, O, X: (mand(p, I, budget=10), deleg(p, I, budget=10)))
    add("effect at the last instant of validity", ("preserved", "-"), lambda p, I, H, O, X: times(p, H, O, eff_t=90))
    add("effect at the first instant of validity", ("preserved", "-"), lambda p, I, H, O, X: (
        mand(p, I, nbf=11), deleg(p, I, nbf=11), times(p, H, O, inv_t=11, eff_t=11)))
    add("revoked at the instant of the action", ("violated", "I6"), lambda p, I, *a: p.update(revocations=[I.sign({"kind": "revocation", "target": "m-1", "t": 10})]))
    add("status shows revocation at the instant of the action", ("violated", "I6"), lambda p, I, *a: (
        revocable(p, I), p.update(statuses=[I.sign({"kind": "status", "target": "m-1", "as_of": 12, "revoked_at": 10})])))
    add("status current as of the action", ("preserved", "-"), lambda p, I, *a: (
        revocable(p, I), p.update(statuses=[I.sign({"kind": "status", "target": "m-1", "as_of": 11})])))
    add("approval used at its expiry instant", ("preserved", "-"), lambda p, I, H, O, X: with_approval(p, I, H, "ap-11", expiry=11))
    add("approval valid from the instant of the action", ("preserved", "-"), lambda p, I, H, O, X: with_approval(p, I, H, "ap-12", nbf=10))

    # Suite v0.2.2: an agent acting directly under a mandate whose validity uses RFC 3339 times (spec 5.2 allows
    # either form). Found by the AgentDojo experiment (experiments/agentdojo): with no delegation in the chain, both
    # reference verifiers compared the effect time with the unconverted string, so Python returned unresolved/I7 for
    # every such packet and JavaScript never detected an effect after expiry.
    def direct(p, I, H, O, **kw):
        mand(p, I, **kw)
        p.update(delegations=[], invocations=[H.sign({**p["invocations"][0], "authority_ref": "m-1"})])
    add("action under a mandate with RFC 3339 validity", ("preserved", "-"), lambda p, I, H, O, X:
        direct(p, I, H, O, exp="1970-01-01T00:01:40Z", nbf="1970-01-01T00:00:01Z"))
    add("effect after a mandate's RFC 3339 expiry", ("violated", "I2"), lambda p, I, H, O, X:
        direct(p, I, H, O, exp="1970-01-01T00:00:10Z"))
    add("effect before a mandate's RFC 3339 nbf", ("violated", "I2"), lambda p, I, H, O, X:
        direct(p, I, H, O, exp="1970-01-01T00:01:40Z", nbf="1970-01-01T00:00:20Z"))

    # Suite v0.2.3: numbers outside the I-JSON range (spec 12.1). Python keeps 2^53 + 1 exact while ECMAScript
    # rounds it to 2^53, so before this rule the two reference verifiers canonicalized the same signed packet
    # differently and returned different verdicts. Both must now treat any |n| > 2^53 - 1 as malformed.
    def ticket(p, H, n):
        p["invocations"] = [H.sign({**p["invocations"][0], "x-ticket": n})]
    add("extension number at the largest I-JSON integer", ("preserved", "-"), lambda p, I, H, O, X:
        ticket(p, H, 2 ** 53 - 1))
    add("extension number at 2^53, outside I-JSON", ("unresolved", "I7"), lambda p, I, H, O, X:
        ticket(p, H, 2 ** 53))
    add("extension number 2^53 + 1, which ECMAScript cannot represent", ("unresolved", "I7"), lambda p, I, H, O, X:
        ticket(p, H, 2 ** 53 + 1))
    # JSON does not distinguish integers from floats: a verifier cannot tell 1e21 from 1000000000000000000000,
    # which Python keeps exact, so the range applies to every number (until v0.2.3, the JCS vector used 1e21).
    add("extension float 1e21, outside the safe range", ("unresolved", "I7"), lambda p, I, H, O, X:
        ticket(p, H, 1e21))

    # ---------------- Suite v0.3.0 ----------------
    # 1. Well-formed I-JSON within bounds (spec 12.1). Text vectors carry the packet as JSON text ("packet_text"),
    # because a duplicate member name or a lone surrogate cannot be written from a parsed object. A verifier parses
    # the text with its strict parser; text that is not I-JSON makes every invocation unresolved (I7).
    def text_add(name, expect, text):
        V.append((name, expect, {"__text__": text}, None))

    good_text = json.dumps(base(I, H, O), ensure_ascii=False)
    # A duplicate inside the SIGNED executed body: last-wins parsers see the signed value (auth.ts), first-wins
    # parsers show repo:app/.env. Before v0.3 both reference verifiers silently took the last value.
    dup = good_text.replace('"executed": {"action": "fs.write", "resource": ',
                            '"executed": {"action": "fs.write", "resource": "repo:app/.env", "resource": ', 1)
    assert dup != good_text
    text_add("duplicate member name in a signed effect body", ("unresolved", "I7"), dup)
    text_add("duplicate member name in an extension member", ("unresolved", "I7"),
             good_text.replace("{", '{"x-note": "a", "x-note": "b", ', 1))
    text_add("lone surrogate in a string", ("unresolved", "I7"), good_text.replace("{", '{"x-note": "\\ud800", ', 1))
    text_add("noncharacter in a string", ("unresolved", "I7"), good_text.replace("{", '{"x-note": "\\ufdd0", ', 1))
    text_add("well-formed packet given as text", ("preserved", "-"), good_text)

    def resource_as(p, H, O, res):
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", resources=["repo:app/src/*"])})])
        p.update(invocations=[H.sign({**p["invocations"][0], "declared": {**p["invocations"][0]["declared"], "resource": res}})])
        p.update(effects=[O.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "resource": res}})])
    add("identifier in NFC with non-ASCII characters", ("preserved", "-"), lambda p, I, H, O, X:
        resource_as(p, H, O, "repo:app/src/café.ts"))
    add("identifier not in NFC (decomposed accent)", ("unresolved", "I7"), lambda p, I, H, O, X:
        resource_as(p, H, O, "repo:app/src/café.ts"))
    add("control character in an identifier", ("unresolved", "I7"), lambda p, I, H, O, X:
        resource_as(p, H, O, "repo:app/src/auth.ts\u0007"))

    def deep(n):
        v = "leaf"
        for _ in range(n):
            v = {"x": v}
        return v
    add("nesting at the depth bound", ("preserved", "-"), lambda p, I, H, O, X:
        p.update(invocations=[H.sign({**p["invocations"][0], "x-deep": deep(28)})]))
    add("nesting beyond the depth bound", ("unresolved", "I7"), lambda p, I, H, O, X:
        p.update(invocations=[H.sign({**p["invocations"][0], "x-deep": deep(40)})]))
    add("string beyond the size bound", ("unresolved", "I7"), lambda p, I, H, O, X:
        p.update(invocations=[H.sign({**p["invocations"][0], "x-note": "a" * 8193})]))

    # 2. One exact Ed25519 acceptance rule (spec 12.2). With OpenSSL 3.6 the identity public key accepted the
    # signature (R = identity, S = 0) for every message; OpenSSL 4.1 rejects it. AMEP rejects it everywhere.
    identity = "01" + "00" * 31
    keys["weak-identity-key"] = {"kid": "weak-identity-key", "alg": "Ed25519", "x": identity, "roles": ["observer"]}
    keys["weak-order2-key"] = {"kid": "weak-order2-key", "alg": "Ed25519", "x": "ec" + "ff" * 30 + "7f", "roles": ["observer"]}

    def forged(p, kid, sig):
        body = {k: v for k, v in p["effects"][0].items() if k != "proof"}
        p.update(effects=[{**body, "proof": {"kid": kid, "alg": "Ed25519", "sig": sig}}])
    add("receipt under a small-order (identity) public key", ("unresolved", "I7"), lambda p, I, H, O, X:
        forged(p, "weak-identity-key", identity + "00" * 32))
    add("receipt under a small-order (order 2) public key", ("unresolved", "I7"), lambda p, I, H, O, X:
        forged(p, "weak-order2-key", identity + "00" * 32))

    def malleable(p, O):
        e = p["effects"][0]
        sig = bytes.fromhex(e["proof"]["sig"])
        s = int.from_bytes(sig[32:], "little") + 2 ** 252 + 27742317777372353535851937790883648493
        e["proof"]["sig"] = (sig[:32] + s.to_bytes(32, "little")).hex()
    add("receipt signature with S >= L (malleated)", ("unresolved", "I7"), lambda p, I, H, O, X: malleable(p, O))

    # 3. Versioning and domain-separated proofs (spec 12.2, 16)
    def v03(p, I, H, O):
        p["amep_version"] = "0.3"
        for kind, s in (("mandates", I), ("delegations", I), ("interpretations", H), ("invocations", H), ("effects", O)):
            p[kind] = [s.sign(o, v=2) for o in p.get(kind, [])]
    add("AMEP 0.3 packet with domain-separated proofs", ("preserved", "-"), lambda p, I, H, O, X: v03(p, I, H, O))
    add("AMEP 0.3 packet with a version-1 proof", ("unresolved", "I7"), lambda p, I, H, O, X: (
        v03(p, I, H, O), p.update(effects=[O.sign(p["effects"][0])])))
    add("version-1 signature relabelled as version 2", ("unresolved", "I7"), lambda p, I, H, O, X: (
        v03(p, I, H, O), p.update(effects=[{**O.sign(p["effects"][0]), "proof": {**O.sign(p["effects"][0])["proof"], "v": 2}}])))
    add("unsupported amep_version", ("unresolved", "I7"), lambda p, I, H, O, X: p.update(amep_version="0.4"))
    add("AMEP 0.3 claim member the verifier does not understand", ("unresolved", "I7"), lambda p, I, H, O, X: (
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", max_recipients=3)})]), v03(p, I, H, O)))
    add("AMEP 0.3 extension claim member is ignored", ("preserved", "-"), lambda p, I, H, O, X: (
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", **{"x-team": "payments"})})]), v03(p, I, H, O)))
    add("unversioned packet keeps v0.2 handling of unknown claim members", ("preserved", "-"), lambda p, I, H, O, X:
        p.update(delegations=[I.sign({**p["delegations"][0], "claims": claims_of(p, "delegations", max_recipients=3)})]))

    # 4. Liveness at each effect's time (spec 8 I6). Cases proposed by Cliff Singletary on audit@ietf.org
    # (19 Nov 2026): revocation between invocation and effect, exactly at the effect, and between two effects.
    def two_effects(p, O, t1, t2):
        e1 = O.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "t": t1}})
        e2 = O.sign({**p["effects"][0], "id": "e-2", "executed": {**p["effects"][0]["executed"], "t": t2}})
        p.update(effects=[e1, e2])
    rev = lambda p, I, t: p.update(revocations=[I.sign({"kind": "revocation", "target": "m-1", "t": t})])  # noqa: E731
    add("revoked between invocation and effect (Singletary case 1)", ("violated", "I6"), lambda p, I, H, O, X: (
        times(p, H, O, eff_t=20), rev(p, I, 15)))
    add("revoked exactly at the effect time (Singletary case 2)", ("violated", "I6"), lambda p, I, H, O, X: (
        times(p, H, O, eff_t=20), rev(p, I, 20)))
    add("revoked between two effects of one invocation (Singletary case 3)", ("violated", "I6"), lambda p, I, H, O, X: (
        two_effects(p, O, 12, 20), rev(p, I, 15)))
    add("revoked after the last effect", ("preserved", "-"), lambda p, I, H, O, X: (
        two_effects(p, O, 12, 20), rev(p, I, 21)))
    add("status current at the invocation but stale at the effect", ("unresolved", "I7"), lambda p, I, *a: (
        revocable(p, I), p.update(statuses=[I.sign({"kind": "status", "target": "m-1", "as_of": 10})])))
    window = lambda p, I, w: p.update(mandates=[I.sign({**p["mandates"][0], "revocation": {"window": w}})])  # noqa: E731
    # From tclancy's review (stafordtituss/amep#35): the window is part of the signed grant, so an effect inside it is
    # within the authority as granted, and nothing is missing (spec 5.12.1, v0.3.3). The window is bounded at an hour.
    # The result carries the revocation as a structured member, within_window (spec 5.12.1, v0.3.5,
    # stafordtituss/amep#41, from tclancy and OWASP/Agentic-Evidence#21), so these can be counted without parsing text.
    add("revoked mid-action, inside the declared propagation window", ("preserved", "-", {"ref": "m-1", "revoked_at": 15, "window": 10}), lambda p, I, H, O, X: (
        window(p, I, 10), times(p, H, O, eff_t=20), rev(p, I, 15)))
    # Named for what it is, a malformed grant, not missing evidence (Jon Odalen, Weaveframe, OWASP/Agentic-Evidence#21).
    add("grant declaring a propagation window over the one-hour maximum (malformed)", ("unresolved", "I7"), lambda p, I, H, O, X: (
        window(p, I, 3601), times(p, H, O, eff_t=20), rev(p, I, 15)))
    add("propagation window of exactly an hour", ("preserved", "-", {"ref": "m-1", "revoked_at": 15, "window": 3600}), lambda p, I, H, O, X: (
        window(p, I, 3600), times(p, H, O, eff_t=20), rev(p, I, 15)))
    add("revoked after the effect, with a declared propagation window", ("preserved", "-", None), lambda p, I, H, O, X: (
        window(p, I, 10), times(p, H, O, eff_t=20), rev(p, I, 25)))
    # Clocks of different operators (spec 5.12.2, v0.3.4), stafordtituss/amep#43, from OWASP/Agentic-Evidence#21
    # (unordered-revocation): the authority source and the observer each declare a clock skew in the key set. Where an
    # effect falls within their combined skew of the boundary that decides the verdict, the order is not established.
    IS, OS = Signer("issuer-skewed", ["issuer"]), Signer("observer-skewed", ["observer"])
    OB = Signer("observer-skew-malformed", ["observer"])
    keys[IS.kid] = {**IS.public(), "operator": "op:authority-source.example", "clock_skew": 2}
    keys[OS.kid] = {**OS.public(), "operator": "op:store.example", "clock_skew": 2}
    keys[OB.kid] = {**OB.public(), "operator": "op:store.example", "clock_skew": 7200}
    def skewed(p, I, O, rev_t, eff_t, signer=None, w=None):
        if w is not None: window(p, I, w)
        p.update(revocations=[IS.sign({"kind": "revocation", "target": "m-1", "t": rev_t})])
        p.update(effects=[(signer or OS).sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "t": eff_t}})])
    add("revocation and effect on different operators' clocks, within their skew", ("unresolved", "I6"), lambda p, I, H, O, X:
        skewed(p, I, O, 13, 11))
    add("revocation and effect on different operators' clocks, outside their skew", ("preserved", "-"), lambda p, I, H, O, X:
        skewed(p, I, O, 16, 11))
    add("effect within the clocks' skew of the end of the propagation window", ("unresolved", "I6"), lambda p, I, H, O, X:
        skewed(p, I, O, 3, 12, w=10))
    add("clock skew longer than an hour", ("unresolved", "I7"), lambda p, I, H, O, X:
        skewed(p, I, O, 50, 11, signer=OB))
    # A default bound for keys of different named operators that declare no skew (spec 5.12.2, v0.3.7),
    # stafordtituss/amep#60, raised by Jon Odalen (OWASP/Agentic-Evidence#21); boundary cases from Brennan Zambo.
    IA, OBN = Signer("issuer-operator-a", ["issuer"]), Signer("observer-operator-b", ["observer"])
    OBT, OAN = Signer("observer-operator-b-tight", ["observer"]), Signer("observer-operator-a", ["observer"])
    keys[IA.kid] = {**IA.public(), "operator": "op:authority-a.example"}
    keys[OBN.kid] = {**OBN.public(), "operator": "op:store-b.example"}
    keys[OBT.kid] = {**OBT.public(), "operator": "op:store-b.example", "clock_skew": 0.1}
    keys[OAN.kid] = {**OAN.public(), "operator": "op:authority-a.example"}
    def named(p, rev_t, eff_t, observer):
        p.update(revocations=[IA.sign({"kind": "revocation", "target": "m-1", "t": rev_t})])
        p.update(effects=[observer.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "t": eff_t}})])
    add("different named operators, no skew declared, within the default bound", ("unresolved", "I6"), lambda p, I, H, O, X:
        named(p, 13, 11, OBN))
    add("different named operators, no skew declared, exactly at the default bound", ("unresolved", "I6"), lambda p, I, H, O, X:
        named(p, 21, 11, OBN))
    add("different named operators, no skew declared, just outside the default bound", ("preserved", "-"), lambda p, I, H, O, X:
        named(p, 22, 11, OBN))
    add("one operator declares a tight skew, the other none", ("unresolved", "I6"), lambda p, I, H, O, X:
        named(p, 15, 11, OBT))
    add("one named operator, no skew declared: ordered as given", ("preserved", "-"), lambda p, I, H, O, X:
        named(p, 12, 11, OAN))
    add("revoked mid-action, after the propagation window", ("violated", "I6"), lambda p, I, H, O, X: (
        window(p, I, 3), times(p, H, O, eff_t=20), rev(p, I, 15)))

    # 5. Quantities and limits (spec 7.6). A payments review of the MCP extension proposal (vendrell46,
    # modelcontextprotocol/agents-ig#31, 21 Nov 2026) showed that without an approval nothing bounded the amount:
    # 840000.00 EUR came out preserved under a budget of 100 points.
    B = Signer("bank-observer-1", ["observer"])
    PSP = Signer("psp-observer-2", ["observer"])
    keys[B.kid] = B.public()
    keys[PSP.kid] = PSP.public()

    def pay(p, amounts, limits=None, value=True, approve_n=(), deleg_limits=None, unit="iso4217:EUR", spent=None,
            num_amount=False, one_call=False, observers=None, bare=False, window_from=None):
        """A v0.3 packet: an assistant pays payees under a mandate (and optionally a delegation).
        spent: the bank's signed monthly totals, one per payment; the limits then name the bank in counted_by.
        one_call: every payment is an effect of one invocation (one tool call that pays several times).
        observers: per payment, "bank" (default) or "psp", a second payment service.
        Each figure in spent is the bank's total for the window that contains the payment, stated as {from, total}
        (amep#10, vendrell46). bare: give bare figures instead, which name no window. window_from: state this start."""
        claims = {"actions": ["payments.send"], "resources": ["payee:*"], "ceiling": "financial", "exp": 100}
        if limits is not None:
            if spent:
                limits = [{**lim, "counted_by": "service:bank.example"} if "per_period" in lim else lim for lim in limits]
            claims["limits"] = limits
        p.clear()
        p["amep_version"] = "0.3"
        p["mandates"] = [I.sign({"id": "m-1", "kind": "mandate", "principal": "user:alice", "claims": claims}, v=2)]
        auth = "m-1"
        if deleg_limits is not None:
            p["delegations"] = [I.sign({"id": "d-1", "kind": "delegation", "parent": "m-1",
                                        "claims": {**claims, "limits": deleg_limits}}, v=2)]
            auth = "d-1"
        p["interpretations"] = [H.sign({"id": "a-1", "kind": "interpretation", "source": "curated", "adapter": "bank_api", "version": "v3"}, v=2)]
        p["invocations"], p["effects"], p["approvals"] = [], [], []
        for n, amt in enumerate(amounts, 1):
            body = {"action": "payments.send", "resource": "payee:city-utility", "effect": "financial", "released": [],
                    "t": 11 + (n - 1 if one_call else 10 * (n - 1))}
            if value:
                body["value"] = {"amount": float(amt) if num_amount else amt, "unit": unit}
                if spent and spent[n - 1] is not None:
                    figures = spent[n - 1] if isinstance(spent[n - 1], dict) else {"2592000": spent[n - 1]}
                    body["value"]["period_spent"] = figures if bare else {
                        k: {"from": (body["t"] // int(k)) * int(k) if window_from is None else window_from, "total": f} if isinstance(f, str) else f
                        for k, f in figures.items()}
            iid = "i-1" if one_call else f"i-{n}"
            if not one_call or n == 1:
                inv = {"id": iid, "kind": "invocation", "authority_ref": auth, "interpretation_ref": "a-1",
                       "actor": "agent:payments-assistant", "t": body["t"] - 1,
                       "declared": {"action": "payments.send", "resource": "payee:city-utility", "effect": "financial"}}
                if n in approve_n:
                    # the approval is signed before execution, so it cannot know the bank's running total
                    approved = {**body, "value": {k: x for k, x in body["value"].items() if k != "period_spent"}} if value else body
                    p["approvals"].append(I.sign({"id": f"ap-{n}", "kind": "approval", "effect_digest": approval_digest(approved),
                                                  "presence": "webauthn", "expiry": 90}, v=2))
                    inv["approval_ref"] = f"ap-{n}"
                p["invocations"].append(H.sign(inv, v=2))
            psp = observers and observers[n - 1] == "psp"
            p["effects"].append((PSP if psp else B).sign({"id": f"e-{n}", "kind": "effect", "invocation": iid,
                                                          "observed_by": "service:psp.example" if psp else "service:bank.example",
                                                          "assurance": "L3", "executed": body}, v=2))
        if not p["approvals"]:
            del p["approvals"]

    EUR = lambda **kw: [{"unit": "iso4217:EUR", **kw}]  # noqa: E731
    MONTH = 2592000
    add("payment within the per-call limit", ("preserved", "-"), lambda p, *a: pay(p, ["84.10"], EUR(per_call="500.00")))
    add("payment over the per-call limit without approval", ("violated", "I2"), lambda p, *a: pay(p, ["840000.00"], EUR(per_call="500.00")))
    add("payment over the per-call limit with a bound approval", ("preserved", "-"), lambda p, *a:
        pay(p, ["840000.00"], EUR(per_call="500.00"), approve_n=(1,)))
    add("limited payment whose receipt records no amount", ("unresolved", "I7"), lambda p, *a:
        pay(p, ["84.10"], EUR(per_call="500.00"), value=False))
    add("payment in an asset the mandate does not authorize", ("violated", "I2"), lambda p, *a:
        pay(p, ["84.10"], EUR(per_call="500.00"), unit="iso4217:USD"))
    add("amount written as a JSON number", ("unresolved", "I7"), lambda p, *a:
        pay(p, ["84.10"], EUR(per_call="500.00"), num_amount=True))
    add("amount with a leading zero", ("unresolved", "I7"), lambda p, *a: pay(p, ["084.10"], EUR(per_call="500.00")))
    add("amount in exponent form", ("unresolved", "I7"), lambda p, *a: pay(p, ["8.41e1"], EUR(per_call="500.00")))
    add("negative amount", ("unresolved", "I7"), lambda p, *a: pay(p, ["-84.10"], EUR(per_call="500.00")))
    add("payments within the period limit, observer total consistent", ("preserved", "-"), lambda p, *a:
        pay(p, ["300.00", "150.00"], EUR(per_call="500.00", per_period="500.00", period=MONTH), spent=["300.00", "450.00"]))
    add("payments each within the per-call limit but over the period limit", ("violated", "I2"), lambda p, *a:
        pay(p, ["300.00", "300.00"], EUR(per_call="500.00", per_period="500.00", period=MONTH), spent=["300.00", "600.00"]))
    add("period limit without an observer total or earlier state", ("unresolved", "I7"), lambda p, *a:
        pay(p, ["300.00"], EUR(per_period="500.00", period=MONTH)))
    add("observer period total below the recorded payments", ("violated", "I7"), lambda p, *a:
        pay(p, ["300.00", "300.00"], EUR(per_period="5000.00", period=MONTH), spent=["300.00", "300.00"]))
    add("approved payment still counts toward the period limit", ("violated", "I2"), lambda p, *a:
        pay(p, ["900.00", "100.00"], EUR(per_call="1000.00", per_period="500.00", period=MONTH), approve_n=(1,), spent=["900.00", "1000.00"]))
    V.append(("period limit carried across packets in verifier state", ("violated", "I2"), None,
              {"period_totals": {"m-1|iso4217:EUR|2592000|0": "450.00"}}))
    _p = {}
    pay(_p, ["100.00"], EUR(per_period="500.00", period=MONTH))
    V[-1] = (V[-1][0], V[-1][1], _p, V[-1][3])
    # A review of the v0.3 limits by Carlos Vendrell Felici (Zealynx Security), stafordtituss/amep#10, 22 Nov 2026:
    # identical payments in one call had counted as one, per_call capped one effect rather than the call, one
    # period_spent stood for every period, observer shares were taken for the principal's total, caip19 amounts were
    # ambiguous, and limits differing only in actions shared one running total.
    add("one approval, the approved payment executed twice in one call", ("violated", "I8"), lambda p, *a:
        pay(p, ["840000.00", "840000.00"], EUR(per_call="500.00"), approve_n=(1,), one_call=True))
    add("two identical payments in one call count twice toward the period limit", ("violated", "I2"), lambda p, *a:
        pay(p, ["300.00", "300.00"], EUR(per_period="500.00", period=MONTH), one_call=True))
    V[-1] = (V[-1][0], V[-1][1], V[-1][2], {"period_totals": {"m-1|iso4217:EUR|2592000|0": "0.00"}})
    add("per_call caps the whole call, not each effect", ("violated", "I2"), lambda p, *a:
        pay(p, ["60.00", "60.00"], EUR(per_call="100.00"), one_call=True))
    add("one effect over the per-effect limit", ("violated", "I2"), lambda p, *a:
        pay(p, ["60.00", "160.00"], EUR(per_effect="100.00"), one_call=True))
    add("per_effect caps each effect of a call", ("preserved", "-"), lambda p, *a:
        pay(p, ["60.00", "60.00"], EUR(per_effect="100.00"), one_call=True))
    add("observer totals are kept per period: day within, month over", ("violated", "I2"), lambda p, *a:
        pay(p, ["80.00"], EUR(per_period="100.00", period=86400) + EUR(per_period="1000.00", period=MONTH),
            spent=[{"86400": "80.00", "2592000": "1030.00"}]))
    add("observer totals are kept per period: both within", ("preserved", "-"), lambda p, *a:
        pay(p, ["80.00"], EUR(per_period="100.00", period=86400) + EUR(per_period="1000.00", period=MONTH),
            spent=[{"86400": "80.00", "2592000": "880.00"}]))
    add("payments through two services against one cap", ("violated", "I2"), lambda p, *a:
        pay(p, ["300.00", "300.00"], EUR(per_period="500.00", period=MONTH), spent=["300.00", "300.00"], observers=["bank", "psp"]))
    add("a total from an observer the limit does not name is not the principal's total", ("unresolved", "I7"), lambda p, *a:
        pay(p, ["300.00"], EUR(per_period="500.00", period=MONTH), spent=["300.00"], observers=["psp"]))
    add("a period limit without a counting observer needs earlier state", ("unresolved", "I7"), lambda p, *a: (
        pay(p, ["300.00"], EUR(per_period="500.00", period=MONTH), spent=["300.00"]),
        p["mandates"][0]["claims"]["limits"][0].pop("counted_by"),
        p.update(mandates=[I.sign(p["mandates"][0], v=2)])))
    add("limits differing only in actions keep separate totals", ("preserved", "-"), lambda p, *a:
        pay(p, ["200.00"], EUR(per_period="1000.00", period=MONTH, actions=["payments.*"]) +
            EUR(per_period="300.00", period=MONTH, actions=["payments.send"]), spent=["200.00"]))
    add("approval still matches when the bank adds its running total", ("preserved", "-"), lambda p, *a:
        pay(p, ["900.00"], EUR(per_call="500.00", per_period="5000.00", period=MONTH), approve_n=(1,), spent=["900.00"]))
    add("receipt that names no observer", ("unresolved", "I7"), lambda p, *a: (
        pay(p, ["84.10"], EUR(per_call="500.00")),
        p.update(effects=[B.sign({k: x for k, x in p["effects"][0].items() if k != "observed_by"}, v=2)])))
    USDC = "caip19:eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
    add("caip19 amount in the asset's smallest unit", ("violated", "I2"), lambda p, *a:
        pay(p, ["100000001"], [{"unit": USDC, "per_call": "100000000"}], unit=USDC))
    add("caip19 amount with a fractional part", ("unresolved", "I7"), lambda p, *a:
        pay(p, ["100.5"], [{"unit": USDC, "per_call": "100000000"}], unit=USDC))
    add("delegation raises the per-call limit", ("violated", "I1"), lambda p, *a:
        pay(p, ["84.10"], EUR(per_call="500.00"), deleg_limits=EUR(per_call="5000.00")))
    add("delegation adds a stricter limit", ("preserved", "-"), lambda p, *a:
        pay(p, ["84.10"], EUR(per_call="500.00"), deleg_limits=EUR(per_call="100.00")))
    add("delegation's stricter limit is enforced", ("violated", "I2"), lambda p, *a:
        pay(p, ["184.10"], EUR(per_call="500.00"), deleg_limits=EUR(per_call="100.00")))
    add("malformed limit (period without per_period)", ("unresolved", "I7"), lambda p, *a:
        pay(p, ["84.10"], EUR(per_call="500.00", period=MONTH)))

    # Quantity limits beyond money: an in-scope bulk read that exceeds a record cap (data exfiltration volume).
    def records(p, n_records, unit="count:records", limit_extra=None):
        claims = {"actions": ["crm.read"], "resources": ["crm:customers/*"], "ceiling": "read", "exp": 100,
                  "limits": [{"unit": "count:records", "per_call": "500", "actions": ["crm.read"], **(limit_extra or {})}]}
        p.clear()
        p["amep_version"] = "0.3"
        p["mandates"] = [I.sign({"id": "m-1", "kind": "mandate", "principal": "user:alice", "claims": claims}, v=2)]
        p["interpretations"] = [H.sign({"id": "a-1", "kind": "interpretation", "source": "curated", "adapter": "crm_api", "version": "v1"}, v=2)]
        p["invocations"] = [H.sign({"id": "i-1", "kind": "invocation", "authority_ref": "m-1", "interpretation_ref": "a-1", "t": 10,
                                    "declared": {"action": "crm.read", "resource": "crm:customers/all", "effect": "read"}}, v=2)]
        p["effects"] = [B.sign({"id": "e-1", "kind": "effect", "invocation": "i-1", "observed_by": "service:crm.example", "assurance": "L3",
                                "executed": {"action": "crm.read", "resource": "crm:customers/all", "effect": "read", "t": 11,
                                             "value": {"amount": n_records, "unit": unit}}}, v=2)]
    add("bulk read within the record limit", ("preserved", "-"), lambda p, *a: records(p, "320"))
    add("in-scope bulk read over the record limit", ("violated", "I2"), lambda p, *a: records(p, "10000000"))
    add("record limit, quantity reported in another unit", ("unresolved", "I7"), lambda p, *a: records(p, "52428800", unit="bytes:utf8"))
    add("AMEP 0.3 limit member the verifier does not understand", ("unresolved", "I7"), lambda p, *a:
        records(p, "320", limit_extra={"per_recipient": "10"}))
    add("value given as a string instead of an object", ("unresolved", "I7"), lambda p, *a: (
        pay(p, ["84.10"], EUR(per_call="500.00")),
        p.update(effects=[B.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "value": "84.10 EUR"}}, v=2)])))

    # Limit order and observer windows, from vendrell46's rerun (stafordtituss/amep#10, 23 Nov 2026). The verdict must
    # not depend on the order the limits are listed in, and an observer's figure counts only for the window it names.
    DAYLIM = {"unit": "iso4217:EUR", "per_period": "100.00", "period": 86400}
    MONTHLIM = {"unit": "iso4217:EUR", "per_period": "1000.00", "period": MONTH}
    add("limit order: the daily limit listed first", ("violated", "I2"), lambda p, *a: pay(
        p, ["30.00"], [DAYLIM, MONTHLIM], spent=[{str(MONTH): "1030.00"}]))
    add("limit order: the monthly limit listed first", ("violated", "I2"), lambda p, *a: pay(
        p, ["30.00"], [MONTHLIM, DAYLIM], spent=[{str(MONTH): "1030.00"}]))
    add("observer figure that names no window does not count", ("unresolved", "I7"), lambda p, *a: pay(
        p, ["300.00"], EUR(per_period="500.00", period=MONTH), spent=["300.00"], bare=True))
    add("observer figure for another window does not count", ("unresolved", "I7"), lambda p, *a: pay(
        p, ["300.00"], EUR(per_period="500.00", period=MONTH), spent=["300.00"], window_from=20 * 86400))
    add("observer's own month is not held against it", ("violated", "I2"), lambda p, *a: pay(
        p, ["300.00"], EUR(per_period="500.00", period=MONTH), spent=["300.00"], window_from=20 * 86400),
        state={"period_totals": {"m-1|iso4217:EUR|2592000|0": "400.00"}, "spent": {}, "approvals_used": {}})

    # Cases invited on stafordtituss/amep#10 (22 Nov 2026), on the readings adopted there. A monthly figure doesn't
    # settle a daily limit. A share from an observer the limit doesn't name adds to a total that verifier state anchors.
    # Identical receipts in the same second still count twice. caip19 amounts beyond 2^53 compare exactly, up to the
    # grammar's 39 digits (a uint128). For money the amount is the debit (spec 5.9.2): fees are included, so an approval
    # of the amount before fees doesn't bind, and with currency conversion only a limit in the debit's unit applies.
    def same_second(p):
        """Every receipt of the call at the first receipt's time, so the bodies are identical, t included."""
        t = p["effects"][0]["executed"]["t"]
        p.update(effects=[B.sign({**e, "executed": {**e["executed"], "t": t}}, v=2) for e in p["effects"]])

    def approved_before_fees(p, amount):
        """Replace the approval with one signed for `amount`, the payment before fees, instead of the debit."""
        x = p["effects"][0]["executed"]
        p.update(approvals=[I.sign({**p["approvals"][0],
                                    "effect_digest": approval_digest({**x, "value": {**x["value"], "amount": amount}})}, v=2)])

    add("a monthly figure does not settle a daily limit", ("unresolved", "I7"), lambda p, *a: pay(
        p, ["80.00"], [DAYLIM, MONTHLIM], spent=[{str(MONTH): "880.00"}]))
    add("payment through a second service adds to the total in verifier state", ("violated", "I2"), lambda p, *a: pay(
        p, ["300.00"], EUR(per_period="500.00", period=MONTH), spent=["300.00"], observers=["psp"]),
        state={"period_totals": {"m-1|iso4217:EUR|2592000|0": "300.00"}})
    add("payment through a second service within the total in verifier state", ("preserved", "-"), lambda p, *a: pay(
        p, ["300.00"], EUR(per_period="500.00", period=MONTH), spent=["300.00"], observers=["psp"]),
        state={"period_totals": {"m-1|iso4217:EUR|2592000|0": "100.00"}})
    add("one approval, the approved payment executed twice in the same second", ("violated", "I8"), lambda p, *a: (
        pay(p, ["840000.00", "840000.00"], EUR(per_call="500.00"), approve_n=(1,), one_call=True), same_second(p)))
    add("two identical payments in the same second count twice toward the period limit", ("violated", "I2"), lambda p, *a: (
        pay(p, ["300.00", "300.00"], EUR(per_period="500.00", period=MONTH), one_call=True), same_second(p)),
        state={"period_totals": {"m-1|iso4217:EUR|2592000|0": "0.00"}})
    NEAR, ONE_NEAR = "caip19:near:mainnet/slip44:397", "1" + "0" * 24   # 24 decimals: 1 NEAR is 10^24 yoctoNEAR
    U128 = str(2 ** 128 - 1)   # 39 digits, the most the amount grammar allows
    add("caip19 amount of 25 digits, one unit over the limit", ("violated", "I2"), lambda p, *a:
        pay(p, [ONE_NEAR[:-1] + "1"], [{"unit": NEAR, "per_call": ONE_NEAR}], unit=NEAR))
    add("caip19 amount of 25 digits, exactly at the limit", ("preserved", "-"), lambda p, *a:
        pay(p, [ONE_NEAR], [{"unit": NEAR, "per_call": ONE_NEAR}], unit=NEAR))
    add("caip19 amount at the largest uint128", ("preserved", "-"), lambda p, *a:
        pay(p, [U128], [{"unit": NEAR, "per_call": U128}], unit=NEAR))
    add("amount with 40 integer digits", ("unresolved", "I7"), lambda p, *a:
        pay(p, [U128 + "0"], [{"unit": NEAR, "per_call": U128}], unit=NEAR))
    add("an approval of the amount before fees does not bind the debit", ("violated", "I8"), lambda p, *a: (
        pay(p, ["606.00"], EUR(per_call="500.00"), approve_n=(1,)), approved_before_fees(p, "600.00")))
    add("converted payment within the limit in the debit currency", ("preserved", "-"), lambda p, *a:
        pay(p, ["460.00"], [{"unit": "iso4217:USD", "per_call": "100.00"}] + EUR(per_call="500.00")))
    add("converted payment over the limit in the debit currency", ("violated", "I2"), lambda p, *a:
        pay(p, ["560.00"], [{"unit": "iso4217:USD", "per_call": "1000.00"}] + EUR(per_call="500.00")))

    # 6. Call statements and binding (spec 5.14). From the review of the MCP extension proposal by Brennan Zambo
    # (modelcontextprotocol/agents-ig#31): a missing receipt must be distinguishable from "nothing was executed", a
    # genuine receipt must not be presentable for a different call, and arguments rewritten in transit must show.
    from amep_protocol.core import digest as _digest

    def stmt(p, O, disposition="completed", count=1, inv_digest=True, args="a" * 64, signer=None, observed_by="hook:host", **kw):
        body = {"id": f"c-{len(p.get('call_statements', [])) + 1}", "kind": "call_statement", "invocation": "i-1",
                "observed_by": observed_by, "disposition": disposition, "effect_count": count, "t": 12, **kw}
        if inv_digest is True:
            body["invocation_digest"] = _digest(p["invocations"][0])
        elif inv_digest:
            body["invocation_digest"] = inv_digest
        if args:
            body["args_digest"] = args
        p.setdefault("call_statements", []).append((signer or O).sign(body, v=2))

    def bound(p, I, H, O, sent_args="a" * 64):
        v03(p, I, H, O)
        if sent_args:
            p["invocations"] = [H.sign({**p["invocations"][0], "args_digest": sent_args}, v=2)]
        p["effects"] = [O.sign({**p["effects"][0], "invocation_digest": _digest(p["invocations"][0])}, v=2)]

    add("call statement and receipt bound to the signed invocation", ("preserved", "-"), lambda p, I, H, O, X: (
        bound(p, I, H, O), stmt(p, O)))
    add("receipt replayed from another invocation", ("unresolved", "I7"), lambda p, I, H, O, X: (
        bound(p, I, H, O), p.update(effects=[O.sign({**p["effects"][0], "invocation_digest": "b" * 64}, v=2)])))
    add("call statement bound to another invocation", ("unresolved", "I7"), lambda p, I, H, O, X: (
        bound(p, I, H, O), stmt(p, O, inv_digest="c" * 64)))
    add("arguments rewritten in transit", ("violated", "I2"), lambda p, I, H, O, X: (
        bound(p, I, H, O), stmt(p, O, args="d" * 64)))
    add("arguments rewritten in transit, nothing executed", ("unresolved", "I7"), lambda p, I, H, O, X: (
        bound(p, I, H, O), p.update(effects=[]), stmt(p, O, disposition="not_executed", count=0, args="d" * 64)))
    add("signed statement that nothing was executed", ("preserved", "-"), lambda p, I, H, O, X: (
        bound(p, I, H, O), p.update(effects=[]), stmt(p, O, disposition="not_executed", count=0)))
    add("receipt contradicts a not-executed statement", ("violated", "I11"), lambda p, I, H, O, X: (
        bound(p, I, H, O), stmt(p, O, disposition="not_executed", count=0)))
    add("not-executed statement that counts effects", ("unresolved", "I7"), lambda p, I, H, O, X: (
        bound(p, I, H, O), p.update(effects=[]), stmt(p, O, disposition="not_executed", count=1)))
    add("statement promises two receipts, one present", ("unresolved", "I7"), lambda p, I, H, O, X: (
        bound(p, I, H, O), stmt(p, O, count=2)))
    add("more receipts than the call statement counts", ("violated", "I7"), lambda p, I, H, O, X: (
        bound(p, I, H, O),
        p["effects"].append(O.sign({**p["effects"][0], "id": "e-2", "executed": {**p["effects"][0]["executed"], "t": 12}}, v=2)),
        stmt(p, O, count=1)))
    add("call failed after its effects, counts consistent", ("preserved", "-"), lambda p, I, H, O, X: (
        bound(p, I, H, O), stmt(p, O, disposition="failed_after_effects", count=1)))
    add("unsigned call statement", ("unresolved", "I7"), lambda p, I, H, O, X: (
        bound(p, I, H, O), stmt(p, O), p["call_statements"][0].pop("proof")))
    add("call statement signed by a host key", ("unresolved", "I7"), lambda p, I, H, O, X: (
        bound(p, I, H, O), stmt(p, O, signer=H)))
    add("call statement with an unknown disposition", ("unresolved", "I7"), lambda p, I, H, O, X: (
        bound(p, I, H, O), stmt(p, O, disposition="partial")))
    add("high-impact call reported not executed only by the actor", ("unresolved", "I10"), lambda p, I, H, O, X: (
        high_impact(p), bound(p, I, H, O), p.update(effects=[]),
        stmt(p, O, disposition="not_executed", count=0, observed_by="agent:assistant-1")))
    add("high-impact call reported not executed by an independent observer", ("preserved", "-"), lambda p, I, H, O, X: (
        high_impact(p), bound(p, I, H, O), p.update(effects=[]),
        stmt(p, O, disposition="not_executed", count=0, observed_by="proxy:egress")))
    add("call statement with a negative effect count", ("unresolved", "I7"), lambda p, I, H, O, X: (
        bound(p, I, H, O), stmt(p, O, count=-1)))
    # issue #15: a host's own fail_mode/applied claim settles "no effect" only for read and write_local (I10)
    closed_deny = {"pep": "host-hook/2.0", "fail_mode": "closed", "applied": "confirmed"}
    add("high-impact deny on a fail-closed host, no independent record", ("unresolved", "I10"), lambda p, I, H, O, X: (
        high_impact(p), p.update(effects=[]), p.update(decisions=[decision(H, "cd-15a", enforcement=closed_deny)])))
    add("high-impact deny on a fail-closed host, reported not executed by an independent observer", ("preserved", "-"), lambda p, I, H, O, X: (
        high_impact(p), bound(p, I, H, O), p.update(effects=[]),
        stmt(p, O, disposition="not_executed", count=0, observed_by="proxy:egress"),
        p.update(decisions=[decision(H, "cd-15b", v=2, enforcement=closed_deny)])))
    add("deny on a fail-closed host contradicted by an observed effect", ("violated", "I11"), lambda p, I, H, O, X:
        p.update(decisions=[decision(H, "cd-15c", enforcement=closed_deny)]))
    # the host's own fail_mode/applied never settles "nothing executed" (#15): the observer's not_executed statement does
    add("deny honoured on fail-closed host (no effect)", ("preserved", "-"), lambda p, I, H, O, X: (
        bound(p, I, H, O), p.update(effects=[]), stmt(p, O, disposition="not_executed", count=0),
        p.update(decisions=[decision(H, "cd-2", v=2, enforcement={"pep": "host-hook/2.0", "fail_mode": "closed", "applied": "confirmed"})])))
    add("deny on a fail-closed host with no other record", ("unresolved", "I7"), lambda p, I, H, O, X: (
        p.update(decisions=[decision(H, "cd-2b", enforcement={"pep": "host-hook/2.0", "fail_mode": "closed", "applied": "confirmed"})]),
        p.update(effects=[])))
    # spec 12.5 (v0.3): observer independence by operator, not only by name (LIMITS.md, gap C1). host-2 and observer-2
    # are run by the same operator; observer-3 by another one.
    H2, O2, O3 = Signer("host-2", ["host"]), Signer("observer-2", ["observer"]), Signer("observer-3", ["observer"])
    for sgn, op in ((H2, "op:agent-platform.example"), (O2, "op:agent-platform.example"), (O3, "op:independent-audit.example")):
        keys[sgn.kid] = {**sgn.public(), "operator": op}

    def by_operator(p, observer):
        high_impact(p)
        p["invocations"] = [H2.sign(p["invocations"][0])]
        p["effects"] = [observer.sign(p["effects"][0])]
    add("high-impact effect observed only by a key of the host's own operator", ("unresolved", "I10"), lambda p, I, H, O, X:
        by_operator(p, O2))
    add("high-impact effect observed by a key of another operator", ("preserved", "-"), lambda p, I, H, O, X:
        by_operator(p, O3))

    # Admissions (spec 8, I10, v0.3.2): the actor's own record can't show it stayed within authority, but it can show it
    # didn't. Found in the MasDrift analysis: an agent's own log of a forbidden external send stayed unresolved.
    def admit(p, signer, observed_by, executed_res="repo:app/docs/launch.md", declared_res="repo:app/docs/launch.md"):
        high_impact(p, observed_by=observed_by, assurance="L1")
        inv = {**p["invocations"][0], "declared": {**p["invocations"][0]["declared"], "resource": declared_res}}
        p["invocations"] = [(H2 if signer is O2 else H).sign(inv)]
        p["effects"] = [signer.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "resource": executed_res}})]
    add("high-impact effect outside authority, recorded only by the actor", ("violated", "I2"), lambda p, I, H, O, X:
        admit(p, O, "agent:assistant-1"))
    add("high-impact effect outside authority, recorded only by a key of the actor's own operator", ("violated", "I2"), lambda p, I, H, O, X:
        admit(p, O2, "proxy:egress"))
    add("the actor's own record says something else was executed", ("unresolved", "I10"), lambda p, I, H, O, X:
        admit(p, O, "agent:assistant-1", executed_res="repo:app/src/other.ts", declared_res="repo:app/src/auth.ts"))
    add("high-impact effect within authority, recorded only by the actor", ("unresolved", "I10"), lambda p, I, H, O, X:
        admit(p, O, "agent:assistant-1", executed_res="repo:app/src/auth.ts", declared_res="repo:app/src/auth.ts"))
    add("high-impact call reported not executed only by a key of the host's own operator", ("unresolved", "I10"), lambda p, I, H, O, X: (
        high_impact(p), bound(p, I, H, O), p.update(effects=[]),
        p.update(invocations=[H2.sign(p["invocations"][0], v=2)]),
        stmt(p, O, disposition="not_executed", count=0, observed_by="proxy:egress", signer=O2)))
    # spec 12.4: a key marked revoked, or used outside its nbf-exp interval, signs nothing (reported by Andrii, Radiolaria,
    # on openid-aiim, 24 Nov 2026: both verifiers accepted a revoked issuer or observer key)
    IR, OR = Signer("issuer-revoked", ["issuer"]), Signer("observer-revoked", ["observer"])
    OW = Signer("observer-windowed", ["observer"])
    keys[IR.kid] = {**IR.public(), "revoked": True}
    keys[OR.kid] = {**OR.public(), "revoked": True}
    keys[OW.kid] = {**OW.public(), "nbf": 5, "exp": 11}

    def resign_chain(p, issuer):
        p["mandates"] = [issuer.sign(p["mandates"][0])]
        p["delegations"] = [issuer.sign(p["delegations"][0])]
    add("mandate signed by a revoked issuer key", ("unresolved", "I7"), lambda p, I, H, O, X: resign_chain(p, IR))
    add("receipt signed by a revoked observer key", ("unresolved", "I7"), lambda p, I, H, O, X:
        p.update(effects=[OR.sign(p["effects"][0])]))
    add("receipt signed at the observer key's expiry", ("unresolved", "I7"), lambda p, I, H, O, X:
        p.update(effects=[OW.sign(p["effects"][0])]))
    add("receipt signed within the observer key's validity interval", ("preserved", "-"), lambda p, I, H, O, X:
        p.update(effects=[OW.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "t": 10}})]))
    add("receipt signed before the observer key's nbf", ("unresolved", "I7"), lambda p, I, H, O, X:
        p.update(invocations=[H.sign({**p["invocations"][0], "t": 2})],
                 effects=[OW.sign({**p["effects"][0], "executed": {**p["effects"][0]["executed"], "t": 3}})]))
    # the host's claim answers only "did anything execute?"; an invocation under revoked authority stays violated
    add("deny on a fail-closed host does not clear an invocation under revoked authority", ("violated", "I6"), lambda p, I, H, O, X: (
        p.update(revocations=[I.sign({"kind": "revocation", "target": "m-1", "t": 5})]), p.update(effects=[]),
        p.update(decisions=[decision(H, "cd-15d", enforcement=closed_deny)])))

    def shared_noop(p, I, H, O, observed_by):
        bound(p, I, H, O)
        p["invocations"] = [H.sign({**p["invocations"][0], "actor": "agent:assistant-1",
                                    "declared": {**p["invocations"][0]["declared"], "effect": "write_shared"}}, v=2)]
        p["effects"] = []
        stmt(p, O, disposition="not_executed", count=0, observed_by=observed_by)
    add("write_shared call reported not executed only by the actor", ("unresolved", "I10"), lambda p, I, H, O, X:
        shared_noop(p, I, H, O, "agent:assistant-1"))
    add("two objects with the same id", ("unresolved", "I7"), lambda p, I, H, O, X: (
        p["effects"].append(O.sign({**p["effects"][0], "invocation": "i-1"}))))

    # 7. Operation approvals (spec 5.10, v0.3). From Takao Sato's VATE case 1 (openid/authzen#795): one admission
    # covers an operation that writes two files, and a retry of the operation must not be able to spend it again.
    def op(p, I, H, O, n_effects=2, n_listed=None, same_body=False, retry=False, extra=None):
        v03(p, I, H, O)
        inv0 = p["invocations"][0]
        part = lambda k: {**p["effects"][0]["executed"], "x-part": "1" if same_body else str(k + 1)}
        bodies = [part(k) for k in range(max(n_effects, n_listed or 0))]
        digests = [approval_digest(b) for b in bodies[: n_effects if n_listed is None else n_listed]]
        ap = {"id": "ap-op", "kind": "approval", "effect_digests": digests, "presence": "webauthn", "expiry": 50}
        p["approvals"] = [I.sign({**ap, **(extra or {})}, v=2)]
        calls = [("i-1", 10)] + ([("i-2", 20)] if retry else [])
        p["invocations"] = [H.sign({**inv0, "id": i, "t": t, "approval_ref": "ap-op"}, v=2) for i, t in calls]
        p["effects"] = [O.sign({"id": f"e-{i[2:]}-{k + 1}", "kind": "effect", "invocation": i, "observed_by": "hook:host",
                                "assurance": "L1", "executed": {**bodies[k], "t": t + 1 + k}}, v=2)
                        for i, t in calls for k in range(n_effects)]
    add("one approval for a two-effect operation", ("preserved", "-"), lambda p, I, H, O, X: op(p, I, H, O))
    add("operation approval, an approved effect not executed", ("preserved", "-"), lambda p, I, H, O, X:
        op(p, I, H, O, n_effects=1, n_listed=2))
    add("operation approval listing one body twice, executed twice", ("preserved", "-"), lambda p, I, H, O, X:
        op(p, I, H, O, same_body=True, n_listed=2))
    add("operation approval spent again by a retried invocation", ("violated", "I8"), lambda p, I, H, O, X:
        op(p, I, H, O, retry=True))
    add("effect outside the operation approval", ("violated", "I8"), lambda p, I, H, O, X:
        op(p, I, H, O, n_listed=1))
    add("operation approval covers a body once, executed twice", ("violated", "I8"), lambda p, I, H, O, X:
        op(p, I, H, O, same_body=True, n_listed=1))
    add("operation approval that also has effect_digest", ("unresolved", "I7"), lambda p, I, H, O, X:
        op(p, I, H, O, extra={"effect_digest": "a" * 64}))
    add("operation approval with an empty list", ("unresolved", "I7"), lambda p, I, H, O, X:
        op(p, I, H, O, extra={"effect_digests": []}))
    add("operation approval expired before the second effect", ("violated", "I8"), lambda p, I, H, O, X:
        op(p, I, H, O, extra={"expiry": 11}))
    add("approval with neither effect_digest nor effect_digests", ("unresolved", "I7"), lambda p, I, H, O, X: (
        v03(p, I, H, O), p.update(approvals=[I.sign({"id": "ap-x", "kind": "approval", "presence": "webauthn"}, v=2)],
                                  invocations=[H.sign({**p["invocations"][0], "approval_ref": "ap-x"}, v=2)])))

    # 8. Grants (spec 5.3, v0.3): authority as a union of (actions x resources) products. Raised by comparing AMEP with
    # the Delegation Receipt Protocol's (operation, resource) pairs, which one product cannot express without widening.
    G = [{"actions": ["fs.read"], "resources": ["repo:app/docs/*"]}, {"actions": ["fs.write"], "resources": ["repo:app/src/*"]}]

    def grants(p, I, H, O, mandate=None, deleg=None, resource=None, versioned=True):
        if versioned:
            v03(p, I, H, O)
        sign = (lambda o: I.sign(o, v=2)) if versioned else I.sign
        def with_authority(claims, auth):
            c = {k: v for k, v in claims.items() if k not in ("actions", "resources")} if "grants" in auth and "keep" not in auth else dict(claims)
            c.update({k: v for k, v in auth.items() if k != "keep"})
            return c
        if mandate is not None:
            p["mandates"] = [sign({**p["mandates"][0], "claims": with_authority(p["mandates"][0]["claims"], mandate)})]
        if deleg is not None:
            p["delegations"] = [sign({**p["delegations"][0], "claims": with_authority(p["delegations"][0]["claims"], deleg)})]
        if resource:
            inv = p["invocations"][0]
            p["invocations"] = [H.sign({**inv, "declared": {**inv["declared"], "resource": resource}}, v=2)]
            eff = p["effects"][0]
            p["effects"] = [O.sign({**eff, "executed": {**eff["executed"], "resource": resource}}, v=2)]
    add("grants: an effect within one of the mandate's grants", ("preserved", "-"), lambda p, I, H, O, X:
        grants(p, I, H, O, mandate={"grants": G}))
    add("grants: action from one grant, resource from another", ("violated", "I2"), lambda p, I, H, O, X:
        grants(p, I, H, O, mandate={"grants": G}, deleg={"grants": G}, resource="repo:app/docs/readme.md"))
    add("grants: delegation wider than every mandate grant", ("violated", "I1"), lambda p, I, H, O, X:
        grants(p, I, H, O, mandate={"grants": G}, deleg={"grants": [{"actions": ["fs.write"], "resources": ["repo:app/*"]}]}))
    add("grants: delegation grants within a plain mandate", ("preserved", "-"), lambda p, I, H, O, X:
        grants(p, I, H, O, deleg={"grants": [{"actions": ["fs.write"], "resources": ["repo:app/src/*"]},
                                            {"actions": ["fs.read"], "resources": ["repo:app/docs/*"]}]}))
    add("grants beside actions and resources", ("unresolved", "I7"), lambda p, I, H, O, X:
        grants(p, I, H, O, mandate={"grants": G, "keep": True}))
    add("grants: an empty list", ("unresolved", "I7"), lambda p, I, H, O, X:
        grants(p, I, H, O, mandate={"grants": []}))
    add("unversioned packet with grants", ("unresolved", "I7"), lambda p, I, H, O, X:
        grants(p, I, H, O, mandate={"grants": [{"actions": ["fs.read"], "resources": ["repo:app/docs/*"]}], "keep": True}, versioned=False))

    # 8b. A call whose effects aren't known in advance (spec 5.8, declared.scope, v0.3.3). Found while importing Kilo Code
    # sessions (interop/kilo): an allowed `npm install` writes files the call never named, so with an exact declaration
    # every write read as a departure blamed on the server, whether or not it was within the grant.
    def command(p, I, H, O, writes, scope=None, versioned=True, effect="write_local"):
        inv = {**p["invocations"][0], "declared": {"action": "process.exec", "resource": "cmd:npm install", "effect": "write_local",
               "scope": scope if scope is not None else {"actions": ["fs.write"], "resources": ["repo:app/*"]}}}
        effs = [{**p["effects"][0], "id": f"e-{n + 1}", "executed": {"action": "fs.write", "resource": r, "effect": effect, "released": [], "t": 11 + n}}
                for n, r in enumerate(writes)]
        if versioned:
            p["invocations"], p["effects"] = [inv], effs
            v03(p, I, H, O)
        else:
            p["invocations"], p["effects"] = [H.sign(inv)], [O.sign(e) for e in effs]
    add("command writes within its declared scope and the grant", ("preserved", "-"), lambda p, I, H, O, X:
        command(p, I, H, O, ["repo:app/src/a.ts", "repo:app/src/b.ts"]))
    add("command write within its declared scope but outside the grant", ("violated", "I2"), lambda p, I, H, O, X:
        command(p, I, H, O, ["repo:app/src/a.ts", "repo:app/Makefile"]))
    add("command write outside its declared scope", ("violated", "I2"), lambda p, I, H, O, X:
        command(p, I, H, O, ["repo:app/src/a.ts", "repo:app/Makefile"], scope={"actions": ["fs.write"], "resources": ["repo:app/src/*"]}))
    add("command effect above its declared class", ("violated", "I2"), lambda p, I, H, O, X:
        command(p, I, H, O, ["repo:app/src/a.ts"], effect="write_shared"))
    add("declared scope in an unversioned packet", ("unresolved", "I7"), lambda p, I, H, O, X:
        command(p, I, H, O, ["repo:app/src/a.ts"], versioned=False))
    add("declared scope with an empty list", ("unresolved", "I7"), lambda p, I, H, O, X:
        command(p, I, H, O, ["repo:app/src/a.ts"], scope={"actions": ["fs.write"], "resources": []}))

    # 8c. Purpose at the effect (spec 5.8, v0.3.6), stafordtituss/amep#14, found by delegation-control-bench (DEL-04):
    # purpose was checked along the chain but not on what ran. A call may now declare the purpose it acts for, and a
    # receipt may state it. AMEP checks a stated purpose; an undeclared one stays unchecked, as before.
    def purpose(p, I, H, O, declared=None, executed=None, versioned=True):
        p.update(mandates=[{**p["mandates"][0], "claims": claims_of(p, "mandates", purpose="bugfix")}],
                 delegations=[{**p["delegations"][0], "claims": claims_of(p, "delegations", purpose="bugfix")}])
        inv = {**p["invocations"][0], "declared": {**p["invocations"][0]["declared"], **({"purpose": declared} if declared is not None else {})}}
        eff = {**p["effects"][0], "executed": {**p["effects"][0]["executed"], **({"purpose": executed} if executed is not None else {})}}
        p["invocations"], p["effects"] = [inv], [eff]
        if versioned:
            v03(p, I, H, O)
        else:
            p.update(mandates=[I.sign(p["mandates"][0])], delegations=[I.sign(p["delegations"][0])],
                     invocations=[H.sign(inv)], effects=[O.sign(eff)])
    add("effect for the purpose the mandate states", ("preserved", "-"), lambda p, I, H, O, X: purpose(p, I, H, O, "bugfix"))
    add("effect for a purpose the mandate doesn't state", ("violated", "I2"), lambda p, I, H, O, X: purpose(p, I, H, O, "release"))
    add("receipt states another purpose than the call declared", ("violated", "I2"), lambda p, I, H, O, X:
        purpose(p, I, H, O, "bugfix", executed="release"))
    add("purpose not declared is not checked", ("preserved", "-"), lambda p, I, H, O, X: purpose(p, I, H, O))
    add("declared purpose in an unversioned packet", ("unresolved", "I7"), lambda p, I, H, O, X:
        purpose(p, I, H, O, "release", versioned=False))
    # Purpose made checkable without trusting the agent's word (spec 5.8.3): by its consequences, through data rules
    # and lineage, and by taking the purpose from the principal's own intent rather than from the agent.
    def purpose_downstream(p, I, H, O):
        read_then_send(p, I, H, O)    # reads confidential plan.md, then posts derived data to an external recipient
        for kind in ("mandates", "delegations"):
            p[kind] = [{**p[kind][0], "claims": {**p[kind][0]["claims"], "purpose": "summarization"}}]
        p["invocations"] = [{**i, "declared": {**i["declared"], "purpose": "summarization"}} for i in p["invocations"]]
        v03(p, I, H, O)
    add("correct purpose declared, derived data sent outside it", ("violated", "I5"), lambda p, I, H, O, X: purpose_downstream(p, I, H, O))

    def purpose_from_intent(p, I, H, O, declared):
        p["intents"] = [I.sign({"id": "n-p", "kind": "intent", "claims": {
            "actions": ["fs.write"], "resources": ["repo:app/src/*"], "data": ["source->internal"], "ceiling": "write_local",
            "exp": 90, "purpose": "bugfix"}}, v=2)]
        p["invocations"] = [{**p["invocations"][0], "intent_ref": "n-p",
                             "declared": {**p["invocations"][0]["declared"], "purpose": declared}}]
        v03(p, I, H, O)
    add("purpose from the principal's intent, call within it", ("preserved", "-"), lambda p, I, H, O, X:
        purpose_from_intent(p, I, H, O, "bugfix"))
    add("purpose from the principal's intent, call outside it", ("violated", "I2"), lambda p, I, H, O, X:
        purpose_from_intent(p, I, H, O, "release"))

    # 9. Holds for unknown outcomes (spec 7.6 rule 6, v0.3). From the cross-institution example of
    # finos/ai-governance-framework#421: "a slice with an unknown outcome stays counted until reconciliation shows it was
    # booked or not booked". An earlier call (i-0, reserve 250.00 EUR) had no outcome; verifier state holds it.
    from amep_protocol.core import digest   # noqa: E402
    HKEY = "m-1|iso4217:EUR|2592000|0"

    def held_case(p, state, held_amount="250.00", earlier=None, reserve=None, approved=False):
        """earlier: None (i-0 only in state), "not_executed" or "executed" (i-0 is in this packet with that outcome)."""
        claims = {"actions": ["payments.send"], "resources": ["payee:*"], "ceiling": "financial", "exp": 100,
                  "limits": [{"unit": "iso4217:EUR", "per_period": "500.00", "period": MONTH}]}
        p.clear()
        p["amep_version"] = "0.3"
        p["mandates"] = [I.sign({"id": "m-1", "kind": "mandate", "principal": "user:alice", "claims": claims}, v=2)]
        p["interpretations"] = [H.sign({"id": "a-1", "kind": "interpretation", "source": "curated", "adapter": "bank_api", "version": "v3"}, v=2)]
        decl = {"action": "payments.send", "resource": "payee:city-utility", "effect": "financial"}
        i0 = H.sign({"id": "i-0", "kind": "invocation", "authority_ref": "m-1", "interpretation_ref": "a-1",
                     "actor": "agent:payments-assistant", "t": 5, "declared": decl,
                     "reserve": {"amount": "250.00", "unit": "iso4217:EUR"}}, v=2)
        i1 = {"id": "i-1", "kind": "invocation", "authority_ref": "m-1", "interpretation_ref": "a-1",
              "actor": "agent:payments-assistant", "t": 19, "declared": decl}
        if reserve is not None:
            i1["reserve"] = reserve
        body1 = {**decl, "released": [], "t": 20, "value": {"amount": "100.00", "unit": "iso4217:EUR"}}
        if approved:   # the principal approved this payment over the limit (I8), so the hold doesn't block it
            p["approvals"] = [I.sign({"id": "ap-1", "kind": "approval", "effect_digest": approval_digest(body1),
                                      "presence": "webauthn", "expiry": 90}, v=2)]
            i1["approval_ref"] = "ap-1"
        i1 = H.sign(i1, v=2)
        pay1 = B.sign({"id": "e-1", "kind": "effect", "invocation": "i-1", "observed_by": "service:bank.example", "assurance": "L3",
                       "executed": body1}, v=2)
        p["invocations"], p["effects"] = [i1], [pay1]
        if earlier == "executed":
            p["invocations"] = [i0, i1]
            p["effects"] = [B.sign({"id": "e-0", "kind": "effect", "invocation": "i-0", "observed_by": "service:bank.example",
                                    "assurance": "L3", "invocation_digest": digest(i0),
                                    "executed": {**decl, "released": [], "t": 6, "value": {"amount": "250.00", "unit": "iso4217:EUR"}}}, v=2), pay1]
        elif earlier == "not_executed":
            p["invocations"] = [i0, i1]
            p["call_statements"] = [B.sign({"id": "c-0", "kind": "call_statement", "invocation": "i-0", "observed_by": "service:bank.example",
                                            "disposition": "not_executed", "effect_count": 0, "t": 8, "invocation_digest": digest(i0)}, v=2)]
        state.update({"period_totals": {HKEY: "200.00"}, "spent": {}, "approvals_used": {},
                      "held": {digest(i0): {"invocation": "i-0", "amounts": {HKEY: held_amount}}}})

    def held(name, expect, **kw):
        st = {}
        add(name, expect, lambda p, *a: held_case(p, st, **kw), state=st)

    held("held call within the period limit", ("preserved", "-"), held_amount="150.00")
    held("earlier call with an unknown outcome holds the period limit", ("unresolved", "I7"))
    held("held call without a reserve leaves the period total unbounded", ("unresolved", "I7"), held_amount=None)
    held("held call later reported not executed releases its hold", ("preserved", "-"), earlier="not_executed")
    held("held call later shown executed counts toward the limit", ("violated", "I2"), earlier="executed")
    held("reserve with a numeric amount", ("unresolved", "I7"), held_amount="150.00", reserve={"amount": 100, "unit": "iso4217:EUR"})
    held("approved payment is not blocked by a held call", ("preserved", "-"), held_amount=None, approved=True)

    # 10. Held approvals (spec 5.10, v0.3). From Takao Sato's VATE case 2, accepted work interrupted (openid/authzen#795):
    # an earlier call (i-0) cited approval ap-1 and its outcome is unknown, so verifier state holds ap-1 for it. A second
    # call under the same single-use approval must not come out preserved until i-0's outcome is known.
    def appr_case(p, state, earlier=None, other_body=False, bad_state=False):
        """earlier: None (i-0 only in state), "not_executed" or "executed" (i-0 is in this packet with that outcome)."""
        for kind in ("mandates", "delegations", "interpretations"):
            p[kind] = [I.sign({k: v for k, v in o.items() if k != "proof"}, v=2) if kind != "interpretations"
                       else H.sign({k: v for k, v in o.items() if k != "proof"}, v=2) for o in p[kind]]
        p["amep_version"] = "0.3"
        body = {"action": "fs.write", "resource": "repo:app/src/auth.ts", "effect": "write_local", "released": [], "t": 11}
        p["approvals"] = [I.sign({"id": "ap-1", "kind": "approval", "effect_digest": approval_digest(body),
                                  "presence": "webauthn", "expiry": 50}, v=2)]
        decl = {"action": "fs.write", "resource": "repo:app/src/auth.ts", "effect": "write_local"}
        i0 = H.sign({"id": "i-0", "kind": "invocation", "authority_ref": "d-1", "interpretation_ref": "a-1", "t": 5,
                     "declared": decl, "approval_ref": "ap-1"}, v=2)
        res1 = "repo:app/src/session.ts" if other_body else "repo:app/src/auth.ts"
        i1 = H.sign({"id": "i-1", "kind": "invocation", "authority_ref": "d-1", "interpretation_ref": "a-1", "t": 10,
                     "declared": {**decl, "resource": res1}, "approval_ref": "ap-1"}, v=2)
        e1 = O.sign({"id": "e-1", "kind": "effect", "invocation": "i-1", "observed_by": "hook:host", "assurance": "L1",
                     "invocation_digest": digest(i1), "executed": {**body, "resource": res1}}, v=2)
        p["invocations"], p["effects"] = [i1], [e1]
        if earlier == "executed":
            p["invocations"] = [i0, i1]
            p["effects"] = [O.sign({"id": "e-0", "kind": "effect", "invocation": "i-0", "observed_by": "hook:host", "assurance": "L1",
                                    "invocation_digest": digest(i0), "executed": {**body, "t": 6}}, v=2), e1]
        elif earlier == "not_executed":
            p["invocations"] = [i0, i1]
            p["call_statements"] = [O.sign({"id": "c-0", "kind": "call_statement", "invocation": "i-0", "observed_by": "hook:host",
                                            "disposition": "not_executed", "effect_count": 0, "t": 8, "invocation_digest": digest(i0)}, v=2)]
        hold = {"invocation": "i-0"} if bad_state else {"invocation": "i-0", "digest": digest(i0)}
        state.update({"approvals_used": {}, "spent": {}, "approvals_held": {"ap-1": hold}})

    def held_appr(name, expect, **kw):
        st = {}
        add(name, expect, lambda p, *a: appr_case(p, st, **kw), state=st)

    held_appr("approval held for an earlier call with an unknown outcome", ("unresolved", "I7"))
    held_appr("held approval released when the earlier call is shown not executed", ("preserved", "-"), earlier="not_executed")
    held_appr("held approval: the earlier call is shown executed, so the second use is a double use", ("violated", "I8"), earlier="executed")
    held_appr("a held approval does not hide an effect the approval doesn't cover", ("violated", "I8"), other_body=True)
    held_appr("malformed approval hold in verifier state", ("unresolved", "I7"), bad_state=True)

    # 11. Operation identity (spec 5.8.1, v0.3.2). From Andrii's review (Radiolaria) on openid-aiim, 24 Nov 2026: an
    # attempt (i-0) whose outcome is unknown, then a retry (i-1) of the same logical operation. Without an operation
    # identifier, a retry under fresh authorization started clean, and a double execution went unnoticed.
    def op_case(p, state, kind):
        for k in ("mandates", "delegations"):
            p[k] = [I.sign({x: v for x, v in o.items() if x != "proof"}, v=2) for o in p[k]]
        p["interpretations"] = [H.sign({x: v for x, v in o.items() if x != "proof"}, v=2) for o in p["interpretations"]]
        p["amep_version"] = "0.3"
        decl = {"action": "fs.write", "resource": "repo:app/src/auth.ts", "effect": "write_local"}
        body = {**decl, "released": [], "t": 11}
        i0 = H.sign({"id": "i-0", "kind": "invocation", "authority_ref": "d-1", "interpretation_ref": "a-1", "t": 5,
                     "declared": decl, "operation": "op-7f3a"}, v=2)
        auth = "d-1"
        if kind == "fresh_mandate":   # the retry runs under a fresh grant from the same issuer
            m2 = {x: v for x, v in p["mandates"][0].items() if x != "proof"}
            p["mandates"].append(I.sign({**m2, "id": "m-2"}, v=2))
            auth = "m-2"
        i1 = H.sign({"id": "i-1", "kind": "invocation", "authority_ref": auth, "interpretation_ref": "a-1", "t": 10,
                     "declared": decl, "operation": "op-9c21" if kind == "independent" else "op-7f3a"}, v=2)
        e1 = O.sign({"id": "e-1", "kind": "effect", "invocation": "i-1", "observed_by": "hook:host", "assurance": "L1",
                     "invocation_digest": digest(i1), "executed": body}, v=2)
        p["invocations"], p["effects"] = [i1], [e1]
        hold = {"operations_held": {"op-7f3a": {"invocation": "i-0", "digest": digest(i0)}}}
        if kind == "twice":
            p["invocations"] = [i0, i1]
            p["effects"] = [O.sign({"id": "e-0", "kind": "effect", "invocation": "i-0", "observed_by": "hook:host", "assurance": "L1",
                                    "invocation_digest": digest(i0), "executed": {**body, "t": 6}}, v=2), e1]
            return
        if kind == "released":
            p["invocations"] = [i0, i1]
            p["call_statements"] = [O.sign({"id": "c-0", "kind": "call_statement", "invocation": "i-0", "observed_by": "hook:host",
                                            "disposition": "not_executed", "effect_count": 0, "t": 8, "invocation_digest": digest(i0)}, v=2)]
        state.update(hold)

    def operation(name, expect, kind):
        st = {}
        add(name, expect, lambda p, *a: op_case(p, st, kind), state=st)

    operation("retry of an operation whose first attempt has an unknown outcome", ("unresolved", "I7"), "held")
    operation("retry under a fresh mandate is still held for the first attempt", ("unresolved", "I7"), "fresh_mandate")
    operation("one operation executed twice", ("violated", "I2"), "twice")
    operation("retry after the first attempt is shown not executed", ("preserved", "-"), "released")
    operation("an independent operation proceeds while another is held", ("preserved", "-"), "independent")

    # 12. Audience binding (spec 5.3, v0.3.2). From stafordtituss/amep#16 (delegation-control-bench, scenario VC-03): a
    # presentation bound to one service, replayed to another, with action and resource in scope. Without audiences in
    # the claims, the effect was preserved.
    def aud_case(p, kind):
        rs = lambda o: {x: v for x, v in o.items() if x != "proof"}
        m, d = rs(p["mandates"][0]), rs(p["delegations"][0])
        m["claims"] = {**m["claims"], "audiences": ["tool:reports-api"]}
        d["claims"] = {**d["claims"], "audiences": ["tool:*"] if kind == "widened" else ["tool:reports-api"]}
        p["mandates"], p["delegations"] = [I.sign(m, v=2)], [I.sign(d, v=2)]
        p["interpretations"] = [H.sign(rs(p["interpretations"][0]), v=2)]
        if kind != "unversioned":
            p["amep_version"] = "0.3"
        inv = H.sign(rs(p["invocations"][0]), v=2)
        x = dict(p["effects"][0]["executed"])
        if kind != "missing":
            x["audience"] = "tool:analytics-api" if kind == "replayed" else "tool:reports-api"
        p["invocations"] = [inv]
        p["effects"] = [O.sign({**rs(p["effects"][0]), "executed": x, "invocation_digest": digest(inv)}, v=2)]

    add("effect sent to the audience the claims name", ("preserved", "-"), lambda p, *a: aud_case(p, "match"))
    add("presentation replayed to another audience", ("violated", "I2"), lambda p, *a: aud_case(p, "replayed"))
    add("receipt does not record the audience the claims are bound to", ("unresolved", "I7"), lambda p, *a: aud_case(p, "missing"))
    add("delegation widens its parent's audiences", ("violated", "I1"), lambda p, *a: aud_case(p, "widened"))
    add("audiences in an unversioned packet", ("unresolved", "I7"), lambda p, *a: aud_case(p, "unversioned"))
    return keys, V


def check_dir(d: str) -> int:
    keys = json.load(open(os.path.join(d, "keys.json")))
    n = ok = 0
    for sub in ("positive", "must-reject"):
        for f in sorted(os.listdir(os.path.join(d, sub))):
            if not f.endswith(".json"):
                continue
            v = json.load(open(os.path.join(d, sub, f)))
            if "packet_text" in v:
                r = verdict(evaluate_text(v["packet_text"], keys, state=v.get("state")))
            else:
                r = verdict(evaluate(v["packet"], keys, state=v.get("state")))
            n += 1
            if (r.outcome, r.invariant) == (v["expect"]["outcome"], v["expect"]["invariant"]) and \
                    ("within_window" not in v["expect"] or r.within_window == v["expect"]["within_window"]):
                ok += 1
            else:
                print(f"FAIL {sub}/{f}: got {r.outcome}/{r.invariant} ({r.reason})")
    print(f"python verifier agrees with expected outcomes on {ok}/{n} vectors (from disk)")
    return 0 if ok == n else 1


def sequences():
    """Cross-packet sequences (spec 5.8.1, 10.7): verifier state is carried from one packet to the next, and each step
    states both its verdict and the operation state it leaves. From Andrii Akhtanin's review (Radiolaria) on the OpenID
    AIIM list, 25 Nov 2026: evidence that is rejected must neither release a hold nor record an operation as done."""
    from amep_protocol.core import digest
    I, H, O, X = Signer("issuer-1", ["issuer", "approver"]), Signer("host-1", ["host"]), Signer("observer-1", ["observer"]), Signer("attacker")
    decl = {"action": "fs.write", "resource": "repo:app/src/auth.ts", "effect": "write_local"}

    def chain():
        p = base(I, H, O)
        for k in ("mandates", "delegations"):
            p[k] = [I.sign({x: v for x, v in o.items() if x != "proof"}, v=2) for o in p[k]]
        p["interpretations"] = [H.sign({x: v for x, v in o.items() if x != "proof"}, v=2) for o in p["interpretations"]]
        p["amep_version"] = "0.3"
        p["effects"] = []
        return p
    i0 = H.sign({"id": "i-0", "kind": "invocation", "authority_ref": "d-1", "interpretation_ref": "a-1", "t": 5,
                 "declared": decl, "operation": "op-7f3a"}, v=2)

    def first():
        p = chain()
        p["invocations"] = [i0]
        return p

    def again(evidence):
        p = chain()
        p["invocations"] = [i0]
        if evidence == "statement":
            p["call_statements"] = [O.sign({"id": "c-0", "kind": "call_statement", "invocation": "i-0", "observed_by": "hook:host",
                                            "disposition": "not_executed", "effect_count": 0, "t": 8, "invocation_digest": digest(i0)}, v=2)]
        elif evidence == "bad_statement":   # signed by a key the verifier doesn't know
            p["call_statements"] = [X.sign({"id": "c-0", "kind": "call_statement", "invocation": "i-0", "observed_by": "hook:host",
                                            "disposition": "not_executed", "effect_count": 0, "t": 8, "invocation_digest": digest(i0)}, v=2)]
        else:
            signer = O if evidence == "receipt" else X
            p["effects"] = [signer.sign({"id": "e-0", "kind": "effect", "invocation": "i-0", "observed_by": "hook:host", "assurance": "L1",
                                         "invocation_digest": digest(i0), "executed": {**decl, "released": [], "t": 6}}, v=2)]
        return p

    def retry(operation="op-7f3a", fresh=True):
        p = chain()
        auth = "d-1"
        if fresh:   # the retry runs under a fresh grant from the same issuer
            m2 = {x: v for x, v in p["mandates"][0].items() if x != "proof"}
            p["mandates"].append(I.sign({**m2, "id": "m-2"}, v=2))
            auth = "m-2"
        i1 = H.sign({"id": "i-1", "kind": "invocation", "authority_ref": auth, "interpretation_ref": "a-1", "t": 10,
                     "declared": decl, "operation": operation}, v=2)
        p["invocations"] = [i1]
        p["effects"] = [O.sign({"id": "e-1", "kind": "effect", "invocation": "i-1", "observed_by": "hook:host", "assurance": "L1",
                                "invocation_digest": digest(i1), "executed": {**decl, "released": [], "t": 11}}, v=2)]
        return p

    held = {"op-7f3a": "i-0"}
    S = [
        ("an unverifiable not_executed statement does not release the hold", [
            (first(), ("unresolved", "I7"), held, {}),
            (again("bad_statement"), ("unresolved", "I7"), held, {}),
            # the retry is still held; its own verified receipt shows it took effect, so that fact is kept
            (retry(), ("unresolved", "I7"), held, {"op-7f3a": "i-1"})]),
        ("an unverifiable receipt does not record the operation as done", [
            (first(), ("unresolved", "I7"), held, {}),
            (again("bad_receipt"), ("unresolved", "I7"), held, {}),
            (retry(), ("unresolved", "I7"), held, {"op-7f3a": "i-1"}),
            # a verified receipt for the first attempt now arrives: both attempts took effect
            (again("receipt"), ("violated", "I2"), {}, {"op-7f3a": "i-1"})]),
        ("control: a verified not_executed statement releases the hold", [
            (first(), ("unresolved", "I7"), held, {}),
            (again("statement"), ("preserved", "-"), {}, {}),
            (retry(), ("preserved", "-"), {}, {"op-7f3a": "i-1"})]),
        ("control: a verified receipt records the operation as done", [
            (first(), ("unresolved", "I7"), held, {}),
            (again("receipt"), ("preserved", "-"), {}, {"op-7f3a": "i-0"}),
            (retry(), ("violated", "I2"), {}, {"op-7f3a": "i-0"})]),
        ("control: an independent operation proceeds while another is held", [
            (first(), ("unresolved", "I7"), held, {}),
            (retry("op-9c21", fresh=False), ("preserved", "-"), held, {"op-9c21": "i-1"})]),
    ]
    # carried approval use (spec 5.10): an approval used in one packet stays used in the next. From Andrii Akhtanin's
    # review: the approval-use accounting needs a carried-state test, not only single-packet vectors.
    def approved(inv_id, t):
        p = base(I, H, O)
        body = {**p["effects"][0]["executed"], "t": t + 1}
        ap = I.sign({"id": "ap-1", "kind": "approval", "effect_digest": approval_digest(body), "presence": "webauthn"})
        inv = H.sign({**{k: v for k, v in p["invocations"][0].items() if k != "proof"}, "id": inv_id, "t": t, "approval_ref": "ap-1"})
        eff = O.sign({**{k: v for k, v in p["effects"][0].items() if k != "proof"}, "id": f"e-{inv_id}", "invocation": inv_id, "executed": body})
        p.update(invocations=[inv], effects=[eff], approvals=[ap])
        return p
    S.append(("a single-use approval used in one packet is still used in the next", [
        (approved("i-1", 10), ("preserved", "-"), {}, {}, {"ap-1": "i-1"}),
        (approved("i-2", 20), ("violated", "I8"), {}, {}, {"ap-1": "i-1"})]))
    # restoration of a violated call's approval use (spec 5.10, "facts are counted completely; blame is charged once").
    # From Andrii Akhtanin's rerun of 0.3.0 on the OpenID AIIM list (26 November): no sequence showed a later packet
    # resolving an earlier call's violation, after which its use of the approval must be counted again.
    #   1. i-1 uses ap-1, but a second receipt shows it executed something other than it declared: violated (I2). Its
    #      use of ap-1 is not counted, since the violation is already charged to it.
    #   2. i-2 uses ap-1. It is judged on what it could see: preserved, and the use is i-2's.
    #   3. i-1 is presented again without the contradicting receipt, so its violation is no longer shown. Its use of
    #      ap-1 comes back into the count, and the double use is charged to i-1 (I8), not to nobody.
    def restoring(inv_id, t, extra_receipt=False):
        p = approved(inv_id, t)
        if extra_receipt:
            e = {k: v for k, v in p["effects"][0].items() if k != "proof"}
            p["effects"].append(O.sign({**e, "id": f"e-{inv_id}-b", "executed": {**e["executed"], "resource": "repo:app/src/secrets.ts", "t": t + 2}}))
        return p
    S.append(("a violated call's approval use comes back into the count when its violation is resolved", [
        (restoring("i-1", 10, extra_receipt=True), ("violated", "I2"), {}, {}, {}),
        (approved("i-2", 20), ("preserved", "-"), {}, {}, {"ap-1": "i-2"}),
        (restoring("i-1", 10), ("violated", "I8"), {}, {}, {"ap-1": "i-2"})]))
    keys = {s.kid: s.public() for s in (I, H, O)}
    out = []
    for name, steps in S:
        out.append({"name": name, "steps": [
            {"packet": p, "expect": {"outcome": o, "invariant": inv},
             "state_after": {"operations_held": st[0], "operations_done": st[1], **({"approvals_used": st[2]} if len(st) > 2 else {})}}
            for p, (o, inv), *st in steps]})
    return keys, out


def run_sequence(seq, keys):
    """Replays one sequence, carrying state; returns a list of failures (empty when every step matches)."""
    state, fails = {}, []
    for n, step in enumerate(seq["steps"]):
        r = verdict(evaluate(step["packet"], keys, state=state))
        got = {k: {o: h["invocation"] for o, h in state.get(k, {}).items()} for k in ("operations_held", "operations_done")}
        if "approvals_used" in step["state_after"]:
            got["approvals_used"] = {a: u[0] for a, u in state.get("approvals_used", {}).items()}
        if (r.outcome, r.invariant) != (step["expect"]["outcome"], step["expect"]["invariant"]) or got != step["state_after"]:
            fails.append(f"{seq['name']}, step {n + 1}: got {r.outcome}/{r.invariant} {got} ({r.reason})")
    return fails


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
    for name, expect, packet, state in V:
        exp_out, exp_inv = expect[:2]
        doc = {"name": name, "expect": {"outcome": exp_out, "invariant": exp_inv}}
        if len(expect) > 2:   # spec 5.12.1: the verdict's within_window member, or null where it must be absent
            doc["expect"]["within_window"] = expect[2]
        if "__text__" in packet:
            doc["packet_text"] = packet["__text__"]
        else:
            doc["packet"] = packet
        if state is not None:
            doc["state"] = json.loads(json.dumps(state))   # stored before evaluation mutates it
        r = verdict(evaluate_text(packet["__text__"], keys, state=state) if "__text__" in packet
                    else evaluate(packet, keys, state=state))
        slug = "".join(ch if ch.isalnum() else "-" for ch in name.lower()).strip("-")
        folder = "positive" if exp_out == "preserved" else "must-reject"
        json.dump(doc, open(f"{out_dir}/{folder}/{slug}.json", "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        ok = (r.outcome, r.invariant) == (exp_out, exp_inv) and (len(expect) < 3 or r.within_window == expect[2])
        passed += ok
        if not ok:
            print(f"FAIL  {name:45} -> {r.outcome:10} {r.invariant:3} {r.reason}   (expected {exp_out}/{exp_inv})")
    skeys, seqs = sequences()
    os.makedirs(f"{out_dir}/sequences", exist_ok=True)
    doc = {"note": "Cross-packet sequences: replay the steps in order, carrying verifier state; each step gives its verdict "
                   "and the operations held and done after it (operation -> invocation id).", "keys": skeys, "sequences": seqs}
    json.dump(doc, open(f"{out_dir}/sequences/operation-state.json", "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    sfails = [f for q in seqs for f in run_sequence(q, skeys)]
    for f in sfails:
        print("FAIL  " + f)
    print(f"{passed}/{len(V)} vectors pass (in memory); {len(seqs) - len({f.split(', step')[0] for f in sfails})}/{len(seqs)} sequences")
    passed -= len(sfails)
    sys.exit(0 if passed == len(V) else 1)
