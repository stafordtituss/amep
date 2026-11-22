"""VATE case 1 (lost response, then recovery) as AMEP evidence.

The case is from Takao Sato's Verifiable Agent Trust Envelope reference vectors for openid/authzen#795:
reference/authzen-receipt-vectors/cases/01-lost-response-recovery/with-unknown-observation, at commit c7533ad.
A runtime submits one operation that creates two files. The provider completes it, but the response is lost, so
the caller records that the outcome is unknown. Later, the provider's record shows the attempt completed. The
caller's unknown observation stays in the history; the policy enforcement point holds the same logical effect
(does not run it again) in both phases.

In AMEP:
  1-pending      The caller holds its own signed invocation and nothing from the provider. Evaluated now, the
                 packet is unresolved: the evidence the outcome needs (the provider's call statement and receipts)
                 is listed as a gap. Unknown is never read as "not executed".
  2-recovered    The caller has recovered the provider's signed call statement (completed, two effects) and two
                 receipts, all bound to the original invocation by its digest: preserved. The packet is a strict
                 superset of 1-pending; nothing in it was replaced.
  3-retried      What the hold prevents: the caller instead retried with a new invocation and the provider ran the
                 operation again. The mandate allows the operation, so each execution is within authority and the
                 packet is preserved. AMEP makes the double execution visible (two completed call statements with
                 the same args_digest) but does not decide it: holding the same logical effect is an idempotency
                 property of the enforcement point, which VATE's PEP comparison covers and AMEP does not.

Where AMEP differs: an AMEP approval binds the digest of exactly one executed effect, and an invocation cites at
most one approval, so VATE's single admission covering a two-file operation has no one-approval equivalent.

Each evaluation's conclusion is kept as a signed verdict record (spec 10.8) by the caller's verifier key, so
the pending "unresolved" stays in the history next to the later "preserved", each naming the packet it read.

Run from the repository root:  python3 -I interop/authzen-receipts/vate-01-lost-response/generate.py
Keys are deterministic TEST keys; never use them for anything else.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..", "..")
sys.path.insert(0, os.path.join(ROOT, "verifier", "python"))
sys.path.insert(0, os.path.join(ROOT, "packages", "python", "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from amep_verifier import Signer  # noqa: E402
from amep_protocol.core import canon, digest, evaluate_text, verdict  # noqa: E402
from amep_protocol.verdicts import sign_envelope, statement, verify_envelope  # noqa: E402

VATE = ("https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/c7533ad70c20e71b7912cdf708f33220e49c1f00/"
        "reference/authzen-receipt-vectors/cases/01-lost-response-recovery/with-unknown-observation")
RESOURCE = "store:handoff/resource-6d36e653fa774434a64b99885539fb3b"   # the case's target resource, shortened
FILES = [("first.txt", "c6d0b56bb7dcde279c493625746cf72dd968d0b68b38724658dac44479f36d84", 19),
         ("second.txt", "d1844cecf2c9f8e459d882b6be79bbd1ba9e95ce649e140609c9ebf3ac0f0b32", 20)]
OPERATION = {"action": "demo.create_file_set", "operation_key": "operation-one",
             "files": [{"name": "first.txt", "text": "first local effect\n"},
                       {"name": "second.txt", "text": "second local effect\n"}]}
ARGS_DIGEST = hashlib.sha256(canon(OPERATION)).hexdigest()


def build():
    I = Signer("owner", ["issuer"])                  # the local owner: issues the mandate
    H = Signer("runtime-a", ["host"])                # the caller's runtime: signs what it asked for
    O = Signer("provider-local", ["observer"])       # the provider: signs what it executed
    keys = {s.kid: s.public() for s in (I, H, O)}

    def body(name, sha, size):
        return {"action": "demo.create_file_set", "resource": RESOURCE, "effect": "write_local", "released": [],
                "t": 11, "x-file": {"name": name, "sha256": sha, "size": size}}

    file_set = [body(*f) for f in FILES]
    mandate = I.sign({"id": "m-1", "kind": "mandate", "principal": "urn:vate:demo:local-owner",
                      "claims": {"actions": ["demo.create_file_set"], "resources": ["store:handoff/*"],
                                 "ceiling": "write_local", "exp": 100}}, v=2)
    adapter = H.sign({"id": "a-1", "kind": "interpretation", "source": "curated", "adapter": "vate-demo-file-set",
                      "version": "v1"}, v=2)

    def invocation(n, t):
        return H.sign({"id": f"i-{n}", "kind": "invocation", "authority_ref": "m-1", "interpretation_ref": "a-1",
                       "actor": "urn:vate:demo:requester", "t": t,
                       "declared": {"action": "demo.create_file_set", "resource": RESOURCE, "effect": "write_local"},
                       "args_digest": ARGS_DIGEST}, v=2)

    def provider_evidence(inv, n):
        d = digest(inv)
        receipts = [O.sign({"id": f"e-{n}-{k + 1}", "kind": "effect", "invocation": inv["id"],
                            "observed_by": "provider-local", "assurance": "L3", "executed": b,
                            "invocation_digest": d}, v=2) for k, b in enumerate(file_set)]
        st = O.sign({"id": f"c-{n}", "kind": "call_statement", "invocation": inv["id"], "observed_by": "provider-local",
                     "disposition": "completed", "effect_count": len(receipts), "t": 12, "invocation_digest": d,
                     "args_digest": ARGS_DIGEST}, v=2)
        return receipts, st

    i1 = invocation(1, 10)
    r1, c1 = provider_evidence(i1, 1)
    base = {"amep_version": "0.3", "mandates": [mandate], "delegations": [], "interpretations": [adapter]}
    pending = {**base, "invocations": [i1], "effects": []}
    recovered = {**base, "invocations": [i1], "effects": r1, "call_statements": [c1]}
    i2 = invocation(2, 20)
    r2, c2 = provider_evidence(i2, 2)
    retried = {**base, "invocations": [i1, i2], "effects": r1 + r2, "call_statements": [c1, c2]}
    return keys, [
        ("1-pending", "The response was lost: the caller holds only its own signed invocation", pending),
        ("2-recovered", "The provider's signed statement and receipts for the original invocation are recovered", recovered),
        ("3-retried", "Instead of holding, the caller retried with a new invocation; the provider ran it again", retried),
    ]


def main():
    keys, cases = build()
    caller_verifier = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"amep-test-vector-key-v1:caller-verifier").digest())
    pub = caller_verifier.public_key().public_bytes_raw().hex()
    with open(os.path.join(HERE, "keys.json"), "w") as fh:
        json.dump(keys, fh, indent=1)
    with open(os.path.join(HERE, "verifier-key.json"), "w") as fh:
        json.dump({"caller-verifier": pub}, fh, indent=1)
    expected = {"1-pending": ("unresolved", "I7"), "2-recovered": ("preserved", "-"), "3-retried": ("preserved", "-")}
    texts = {}
    for name, title, packet in cases:
        text = json.dumps(packet, indent=1, ensure_ascii=False) + "\n"
        texts[name] = packet
        with open(os.path.join(HERE, f"{name}.packet.json"), "w", encoding="utf-8") as fh:
            fh.write(text)
        res = evaluate_text(text, keys)
        v = verdict(res)
        assert (v.outcome, v.invariant) == expected[name], (name, v.outcome, v.invariant, v.reason)
        env = sign_envelope(statement(text.encode("utf-8"), keys, res, {"name": "amep-protocol", "role": "caller verifier"}),
                            caller_verifier, "caller-verifier")
        assert verify_envelope(env, {"caller-verifier": pub})["predicate"]["verdict"]["outcome"] == v.outcome
        with open(os.path.join(HERE, f"{name}.verdict.dsse.json"), "w") as fh:
            json.dump(env, fh, indent=1)
        detail = v.blame if v.outcome == "violated" else ", ".join(f"{g['need']} {g['ref']}" for g in v.gaps)
        print(f"{name:12} {v.outcome:10} {v.invariant:3} {detail or ''}  ({title})")
    # nothing in the pending packet is replaced by recovery: every object in it appears unchanged in 2-recovered
    for kind, objs in texts["1-pending"].items():
        if isinstance(objs, list):
            assert all(o in texts["2-recovered"][kind] for o in objs), kind
    print("2-recovered contains every object of 1-pending unchanged")


if __name__ == "__main__":
    main()
