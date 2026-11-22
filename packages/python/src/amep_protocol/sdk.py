"""AMEP producer SDK: keys, signing, and builders for every AMEP object (spec/amep-v0.2.md, section 5).

Builders return plain dicts that follow the spec's field names, check enumerated values, and leave out
members that are None. Sign each object with a Key that holds a role permitted for its kind (spec 12.5).

    from amep_protocol import sdk
    issuer = sdk.Key.generate("issuer-1", ["issuer", "approver"])
    m = issuer.sign(sdk.mandate("m-1", "user:alice", sdk.claims(["fs.*"], ["repo:app/*"], "write_local", exp=1767229200)))
"""
from __future__ import annotations

import os
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .core import CEILING, DISPOSITIONS, SIGNER_ROLES, approval_digest, canon, digest, signing_input

ROLES = ("issuer", "host", "observer", "approver")
ASSURANCE = ("L0", "L1", "L2", "L3")
SOURCES = ("curated", "customer", "provider_hint", "judge", "none")
PRESENCE = ("webauthn", "chat_user", "host_ui", "none")
MODES = ("observe", "allow", "mediate", "step_up", "hold", "deny", "quarantine")
PHASES = ("pre_execution", "post_execution", "simulation")
OUTCOMES = ("preserved", "violated", "unresolved")


def _one_of(name, value, allowed):
    if value not in allowed:
        raise ValueError(f"{name} must be one of {', '.join(allowed)}; got {value!r}")
    return value


def _clean(d: dict) -> dict:
    return {k: v for k, v in d.items() if v is not None}


# ---------------- keys and signing (spec 12) ----------------
class Key:
    """An Ed25519 signing key with an AMEP key id and roles."""

    def __init__(self, kid: str, roles, private_key: Ed25519PrivateKey):
        for r in roles:
            _one_of("role", r, ROLES)
        self.kid, self.roles, self._key = kid, list(roles), private_key

    @classmethod
    def generate(cls, kid: str, roles) -> "Key":
        return cls(kid, roles, Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem: bytes, kid: str, roles) -> "Key":
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("AMEP keys must be Ed25519")
        return cls(kid, roles, key)

    def to_pem(self) -> bytes:
        return self._key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption())

    def save(self, path: str) -> None:
        """Write the private key as PKCS#8 PEM, readable only by the current user."""
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "wb") as f:
            f.write(self.to_pem())

    def public_entry(self) -> dict:
        """This key's entry for a key set (spec 12.4)."""
        raw = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"kid": self.kid, "alg": "Ed25519", "x": raw.hex(), "roles": list(self.roles)}

    def sign(self, obj: dict, v: int = 1) -> dict:
        """Return a copy of obj with a proof. v=1 signs the JCS form (AMEP v0.2); v=2 signs the domain-separated
        input of spec 12.2 (AMEP v0.3). Refuses kinds this key's roles may not sign."""
        kind = obj.get("kind")
        if kind in SIGNER_ROLES and not set(self.roles) & SIGNER_ROLES[kind]:
            raise ValueError(f"key {self.kid} (roles {self.roles}) may not sign a {kind}; "
                             f"needs one of {sorted(SIGNER_ROLES[kind])}")
        body = {k: x for k, x in obj.items() if k != "proof"}
        if v == 2:
            proof = {"kid": self.kid, "alg": "Ed25519", "v": 2}
            return {**body, "proof": {**proof, "sig": self._key.sign(signing_input({**body, "proof": proof})).hex()}}
        return {**body, "proof": {"kid": self.kid, "alg": "Ed25519", "sig": self._key.sign(canon(body)).hex()}}


def keyset(*keys: Key) -> dict:
    """A key set mapping kid to public entry, as served at /.well-known/amep-keys.json."""
    return {k.kid: k.public_entry() for k in keys}


# ---------------- builders (spec 5) ----------------
def claims(actions, resources, ceiling, exp, *, data=None, nbf=None, purpose=None, deny_actions=None,
           deny_resources=None, depth=None, budget=None) -> dict:
    _one_of("ceiling", ceiling, CEILING)
    return _clean({"actions": list(actions), "resources": list(resources), "ceiling": ceiling, "exp": exp,
                   "data": list(data) if data is not None else None, "nbf": nbf, "purpose": purpose,
                   "deny_actions": list(deny_actions) if deny_actions is not None else None,
                   "deny_resources": list(deny_resources) if deny_resources is not None else None,
                   "depth": depth, "budget": budget})


def mandate(id, principal, claims, *, issuer=None, subject_agent=None, status_ref=None, token=None) -> dict:
    return _clean({"id": id, "kind": "mandate", "principal": principal, "issuer": issuer,
                   "subject_agent": subject_agent, "claims": claims,
                   "revocation": {"status_ref": status_ref} if status_ref else None, "token": token})


def delegation(id, parent, claims, *, delegate=None, token=None) -> dict:
    return _clean({"id": id, "kind": "delegation", "parent": parent, "delegate": delegate, "claims": claims,
                   "token": token})


def intent(id, claims, *, prompt_ref=None, derivation=None) -> dict:
    if derivation is not None:
        _one_of("derivation", derivation, ("template", "judge", "confirmed"))
    return _clean({"id": id, "kind": "intent", "prompt_ref": prompt_ref, "claims": claims, "derivation": derivation})


def interpretation(id, adapter, version, *, source="curated", integrity_hash=None) -> dict:
    _one_of("source", source, SOURCES)
    return _clean({"id": id, "kind": "interpretation", "source": source, "adapter": adapter, "version": version,
                   "integrity_hash": integrity_hash})


def effect_body(action, resource, effect, t, *, released=None, reversible=None, accessed=None,
                recipient=None, value=None) -> dict:
    """The executed-effect body (spec 5.9), also used for invocation.mediated and approvals."""
    _one_of("effect", effect, CEILING)
    return _clean({"action": action, "resource": resource, "effect": effect,
                   "released": list(released) if released is not None else [], "reversible": reversible,
                   "accessed": list(accessed) if accessed is not None else None, "recipient": recipient,
                   "value": value, "t": t})


def value(amount: str, unit: str, *, period_spent: str | None = None) -> dict:
    """A quantity (spec 5.9.2): amounts are exact decimal strings, for example value("1200.00", "iso4217:EUR")."""
    if not isinstance(amount, str):
        raise ValueError('amount must be a decimal string, for example "1200.00"')
    return _clean({"amount": amount, "unit": unit, "period_spent": period_spent})


def invocation(id, authority_ref, interpretation_ref, t, action, resource, effect, *, actor=None,
               intent_ref=None, approval_ref=None, mediated=None, influenced_by=None, principal_confirmed=None,
               derived_from=None, budget_spent=None, correlation=None, args_digest=None) -> dict:
    _one_of("effect", effect, CEILING)
    if CEILING.index(effect) >= CEILING.index("write_shared") and not actor:
        raise ValueError("actor is required for effects of class write_shared and above (spec 5.8, I10)")
    return _clean({"id": id, "kind": "invocation", "authority_ref": authority_ref,
                   "interpretation_ref": interpretation_ref, "intent_ref": intent_ref, "approval_ref": approval_ref,
                   "t": t, "actor": actor, "declared": {"action": action, "resource": resource, "effect": effect},
                   "mediated": mediated, "influenced_by": influenced_by, "principal_confirmed": principal_confirmed,
                   "derived_from": derived_from, "budget_spent": budget_spent, "correlation": correlation,
                   "args_digest": args_digest})


def effect(id, invocation, observed_by, assurance, executed, *, backend_receipt=None, invocation_digest=None) -> dict:
    _one_of("assurance", assurance, ASSURANCE)
    return _clean({"id": id, "kind": "effect", "invocation": invocation, "observed_by": observed_by,
                   "assurance": assurance, "executed": executed, "backend_receipt": backend_receipt,
                   "invocation_digest": invocation_digest})


def call_statement(id, invocation, observed_by, disposition, effect_count, t, *, invocation_digest=None,
                   args_digest=None) -> dict:
    """The observer's signed account of one tool call (spec 5.14)."""
    _one_of("disposition", disposition, DISPOSITIONS)
    if disposition == "not_executed" and effect_count != 0:
        raise ValueError("a not_executed call has no effects")
    return _clean({"id": id, "kind": "call_statement", "invocation": invocation, "observed_by": observed_by,
                   "disposition": disposition, "effect_count": effect_count, "t": t,
                   "invocation_digest": invocation_digest, "args_digest": args_digest})


def args_digest(arguments) -> str:
    """SHA-256 of the JCS form of a tool call's arguments (spec 5.14), as sent by the host or received by the server."""
    return digest(arguments if arguments is not None else {})


def approval(id, body, presence, *, expiry=None, nbf=None, approver=None, resource_version=None,
             consumed=None) -> dict:
    """An approval bound to an effect body; the digest is computed without the body's t (spec 5.10)."""
    _one_of("presence", presence, PRESENCE)
    return _clean({"id": id, "kind": "approval", "effect_digest": approval_digest(body), "presence": presence,
                   "approver": approver, "resource_version": resource_version, "nbf": nbf, "expiry": expiry,
                   "consumed": consumed})


def finding(id, source_locator, content_hash, integrity_label, *, span=None, hidden_mechanism=None,
            requested=None) -> dict:
    _one_of("integrity_label", integrity_label, ("trusted", "untrusted"))
    return _clean({"id": id, "kind": "finding", "source_locator": source_locator, "content_hash": content_hash,
                   "span": span, "hidden_mechanism": hidden_mechanism, "integrity_label": integrity_label,
                   "requested": requested})


def revocation(target, t, *, reason=None, id=None) -> dict:
    return _clean({"id": id, "kind": "revocation", "target": target, "t": t, "reason": reason})


def status(target, as_of, *, revoked_at=None, id=None) -> dict:
    return _clean({"id": id, "kind": "status", "target": target, "as_of": as_of, "revoked_at": revoked_at})


def enforcement(pep, fail_mode, *, host_supports=None, encoded_as=None, applied=None) -> dict:
    _one_of("fail_mode", fail_mode, ("closed", "open", "unknown"))
    if applied is not None:
        _one_of("applied", applied, ("confirmed", "not_observed", "contradicted"))
    return _clean({"pep": pep, "fail_mode": fail_mode, "host_supports": host_supports, "encoded_as": encoded_as,
                   "applied": applied})


def decision(invocation, outcome, mode, phase, *, id=None, invariant=None, reason=None, quarantined=None,
             safe_alternatives=None, evidence_refs=None, enforcement=None) -> dict:
    _one_of("outcome", outcome, OUTCOMES)
    _one_of("mode", mode, MODES)
    _one_of("phase", phase, PHASES)
    return _clean({"id": id, "kind": "decision", "invocation": invocation, "outcome": outcome,
                   "invariant": invariant, "mode": mode, "phase": phase, "quarantined": quarantined,
                   "reason": reason, "safe_alternatives": safe_alternatives, "evidence_refs": evidence_refs,
                   "enforcement": enforcement})


_PACKET_MEMBERS = ("mandates", "delegations", "intents", "interpretations", "invocations", "effects", "approvals",
                   "revocations", "statuses", "findings", "decisions")


def packet(*objects, pinned_adapters=None, amep_version="0.2") -> dict:
    """Group objects into a packet (spec 5.2) by kind, keeping their order."""
    member = {"mandate": "mandates", "delegation": "delegations", "intent": "intents",
              "interpretation": "interpretations", "invocation": "invocations", "effect": "effects",
              "approval": "approvals", "revocation": "revocations", "status": "statuses", "finding": "findings",
              "decision": "decisions", "call_statement": "call_statements"}
    out: dict = {"amep_version": amep_version}
    for o in objects:
        m = member.get(o.get("kind"))
        if not m:
            raise ValueError(f"unknown object kind {o.get('kind')!r}")
        out.setdefault(m, []).append(o)
    if pinned_adapters:
        out["pinned_adapters"] = dict(pinned_adapters)
    return out
