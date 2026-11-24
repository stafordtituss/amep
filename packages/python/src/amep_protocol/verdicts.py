"""Verdict records (spec 10.8, v0.3): a portable, signable statement of what a verifier concluded about a packet.

A verdict record names the exact packet bytes and key set that were evaluated, and for every result its outcome,
deciding invariant, blame and evidence gaps (spec 10.5.1). Reasons are free text and differ between implementations,
so they are not part of the record. The record is deterministic: two conforming verifiers produce the same bytes.

It is carried as an in-toto Statement v1 with predicate type PREDICATE_TYPE, and signed in a DSSE envelope, so that
in-toto and Sigstore tooling can store and check AMEP verdicts.
"""
from __future__ import annotations

import base64
import datetime
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .core import canon, ed25519_strict_ok, parse_strict, verdict

PREDICATE_TYPE = "https://github.com/stafordtituss/amep/verdict/v0.3"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
SVR_TYPE = "https://in-toto.io/attestation/svr/v0.2"
SVR_PRESERVED = "AMEP_VERDICT_PRESERVED"
RULES_URI = "https://github.com/stafordtituss/amep/blob/main/spec/amep-v0.2.md"


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


def _check_subjects(subjects) -> list:
    """in-toto ResourceDescriptors for the artifacts a verdict admits: [{name, digest: {alg: hex}}], none empty."""
    if not isinstance(subjects, list) or not subjects:
        raise ValueError("subjects must be a non-empty list")
    out = []
    for s in subjects:
        d = s.get("digest") if isinstance(s, dict) else None
        if not isinstance(s, dict) or not isinstance(s.get("name"), str) or not isinstance(d, dict) or not d or \
                not all(isinstance(v, str) and v and all(c in "0123456789abcdef" for c in v) for v in d.values()):
            raise ValueError("each subject needs a name and a digest of lowercase hex values")
        out.append({"name": s["name"], "digest": dict(d)})
    return out


def statement(packet_bytes: bytes, keys: dict, results: list, verifier: dict | None = None, subjects: list | None = None) -> dict:
    """The in-toto Statement v1 for a verdict. Its subject is the artifact the evaluated actions produced, when the
    caller names one (a commit, a release, a payment), with the packet's digest in the predicate as an input;
    otherwise the evaluated packet itself. Pass subjects=[{"name": ..., "digest": {"sha256": hex}}] to name artifacts."""
    rec = verdict_record(packet_bytes, keys, results, verifier)
    subject = [{"name": "amep-packet", "digest": {"sha256": rec["packet"]["sha256"]}}] if subjects is None else _check_subjects(subjects)
    return {"_type": STATEMENT_TYPE, "subject": subject, "predicateType": PREDICATE_TYPE, "predicate": rec}


def svr_statement(packet_bytes: bytes, keys: dict, results: list, verifier_id: str, time_created: str | None = None) -> dict:
    """The same verdict as an in-toto Simple Verification Result (SVR v0.2), for policy engines that consume SVRs.

    An SVR lists the properties that passed. The only AMEP property is AMEP_VERDICT_PRESERVED, present when the packet
    verdict is preserved; a violated or unresolved packet gets an SVR with no properties, and the AMEP verdict record
    (statement()) carries the outcome, blame and gaps. The policies are the key set and the AMEP evaluation rules.
    Unlike the verdict record, an SVR is not deterministic: it names its verifier and the time of verification."""
    if time_created is None:
        time_created = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    from . import SPEC_VERSION
    passed = verdict(results).outcome == "preserved"
    return {"_type": STATEMENT_TYPE,
            "subject": [{"name": "amep-packet", "digest": {"sha256": hashlib.sha256(packet_bytes).hexdigest()}}],
            "predicateType": SVR_TYPE,
            "predicate": {
                "verifier": {"id": verifier_id, "policies": [
                    {"name": "amep-keyset", "digest": {"sha256": hashlib.sha256(canon(keys)).hexdigest()}},
                    {"name": f"amep-{SPEC_VERSION}", "uri": RULES_URI}]},
                "timeCreated": time_created,
                "properties": [SVR_PRESERVED] if passed else []}}


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


def verify_envelope(env: dict, public_keys: dict, predicate_types: tuple = (PREDICATE_TYPE,)) -> dict:
    """Check a DSSE envelope against {keyid: public key hex}; returns the statement. Raises ValueError otherwise.
    Only AMEP verdict statements are accepted unless `predicate_types` says otherwise, e.g. (PREDICATE_TYPE, SVR_TYPE).
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
        if stmt.get("_type") != STATEMENT_TYPE or stmt.get("predicateType") not in predicate_types:
            raise ValueError(f"predicate type {stmt.get('predicateType')!r} is not one of {list(predicate_types)}")
        return stmt
    raise ValueError("no signature verifies with the given keys")
