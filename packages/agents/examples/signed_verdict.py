"""How-to: publish what you concluded, as a signed in-toto attestation.

A verdict record (spec 10.8) names the exact packet it evaluated, by digest, and every result. Signed in a DSSE
envelope, it can sit next to a release, a deployment or a payment, and anyone with the packet can re-run it.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from amep_protocol import evaluate  # noqa: E402
from amep_protocol.verdicts import sign_envelope, statement, verify_envelope  # noqa: E402
from _setup import KEYS, new_recorder, update_ticket  # noqa: E402


def main():
    rec = new_recorder()
    rec.declare("call-1", "update_ticket", {"ticket_id": "4821", "status": "closed"})
    rec.observe("call-1", update_ticket("4821", "closed"))
    packet_bytes = json.dumps(rec.packet()).encode()

    results = evaluate(json.loads(packet_bytes), KEYS)
    verifier_key = Ed25519PrivateKey.generate()     # the key of whoever checks, e.g. your CI or an auditor
    env = sign_envelope(statement(packet_bytes, KEYS, results, {"name": "amep-protocol", "role": "ci"}),
                        verifier_key, "ci-verifier")

    pub = verifier_key.public_key().public_bytes_raw().hex()
    stmt = verify_envelope(env, {"ci-verifier": pub})
    print(json.dumps(stmt["predicate"]["verdict"]))
    return stmt


if __name__ == "__main__":
    main()
