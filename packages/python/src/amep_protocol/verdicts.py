"""Verdict records (spec 10.8, v0.3): a portable, signable statement of what a verifier concluded about a packet.

A verdict record names the exact packet bytes and key set that were evaluated, and for every result its outcome,
deciding invariant, blame and evidence gaps (spec 10.5.1). Reasons are free text and differ between implementations,
so they are not part of the record. The record is deterministic: two conforming verifiers produce the same bytes.

It is carried as an in-toto Statement v1 with predicate type PREDICATE_TYPE, and signed in a DSSE envelope, so that
in-toto and Sigstore tooling can store and check AMEP verdicts.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .core import canon, ed25519_strict_ok, parse_strict, verdict

PREDICATE_TYPE = "https://github.com/stafordtituss/amep/verdict/v0.3"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"


def _result(r) -> dict:
    return {"id": r.invocation, "outcome": r.outcome, "invariant": r.invariant, "blame": r.blame, "gaps": list(r.gaps)}


def verdict_record(packet_bytes: bytes, keys: dict, results: list, verifier: dict | None = None) -> dict:
    """The predicate: the packet (by SHA-256 of the exact bytes evaluated), the key set (by SHA-256 of its JCS form),
    the packet verdict and every result. `verifier` ({"name", "version"}) is optional and informative."""
    v = verdict(results)
    rec = {
        "packet": {"sha256": hashlib.sha256(packet_bytes).hexdigest()},
        "keyset": {"sha256": hashlib.sha256(canon(keys)).hexdigest()},
        "verdict": {"outcome": v.outcome, "invariant": v.invariant, "blame": v.blame, "gaps": list(v.gaps)},
        "results": [_result(r) for r in results],
    }
    if verifier:
        rec["verifier"] = dict(verifier)
    return rec


def statement(packet_bytes: bytes, keys: dict, results: list, verifier: dict | None = None) -> dict:
    """The in-toto Statement v1 whose subject is the evaluated packet."""
    rec = verdict_record(packet_bytes, keys, results, verifier)
    return {"_type": STATEMENT_TYPE,
            "subject": [{"name": "amep-packet", "digest": {"sha256": rec["packet"]["sha256"]}}],
            "predicateType": PREDICATE_TYPE, "predicate": rec}


def _pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE pre-authentication encoding: "DSSEv1" SP len(type) SP type SP len(body) SP body."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def sign_envelope(stmt: dict, signer, keyid: str) -> dict:
    """A DSSE envelope over the statement's JCS form. `signer` is an Ed25519 signing key object (it has .sign)."""
    payload = canon(stmt)
    sig = signer.sign(_pae(PAYLOAD_TYPE, payload))
    return {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(),
            "signatures": [{"keyid": keyid, "sig": base64.b64encode(sig).decode()}]}


def verify_envelope(env: dict, public_keys: dict) -> dict:
    """Check a DSSE envelope against {keyid: public key hex}; returns the statement. Raises ValueError otherwise.
    The same exact Ed25519 acceptance rule as for AMEP objects applies (spec 12.2)."""
    if env.get("payloadType") != PAYLOAD_TYPE:
        raise ValueError("not an in-toto payload")
    payload = base64.b64decode(env["payload"], validate=True)
    for s in env.get("signatures", []):
        x = public_keys.get(s.get("keyid"))
        if not x:
            continue
        sig = base64.b64decode(s["sig"], validate=True)
        pub = bytes.fromhex(x)
        if not ed25519_strict_ok(pub, sig):
            continue
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, _pae(PAYLOAD_TYPE, payload))
        except InvalidSignature:
            continue
        stmt = parse_strict(payload.decode("utf-8"))
        if stmt.get("_type") != STATEMENT_TYPE or stmt.get("predicateType") != PREDICATE_TYPE:
            raise ValueError("not an AMEP verdict statement")
        return stmt
    raise ValueError("no signature verifies with the given keys")
