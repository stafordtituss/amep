"""VATE case 2 (accepted work interrupted) as AMEP evidence.

The case is from Takao Sato's Verifiable Agent Trust Envelope reference vectors for openid/authzen#795:
reference/authzen-receipt-vectors/cases/02-accepted-interrupted, variants zero-effects and partial-effects, at commit
093194d. The owner admitted one operation that writes two files. runtime-a's attempt was accepted, then interrupted.
In zero-effects the provider holds neither file; in partial-effects it holds first.txt only. VATE keeps both
unresolved, and expects the enforcement point to hold the same logical effect, including after a handoff to runtime-b.

The admission is carried as an AMEP operation approval (spec 5.10) over the digests of both file effects.

zero-effects:
  z1-interrupted         runtime-a's signed invocation, nothing from the provider: unresolved (receipt).
  z2-handoff-rerun       runtime-b re-runs the operation under the same admission while runtime-a's outcome is unknown:
                         runtime-b's call is unresolved, gap held_outcome naming runtime-a's call (spec 5.10, held
                         approvals). This case is why AMEP holds approvals: before, runtime-b's call came out preserved.
  z3-not-executed        What would settle it on the provider's word: the provider signs not_executed for runtime-a's
                         call. AMEP accepts the signed statement: preserved, "nothing executed". VATE asks for more
                         (confirmed nonexecution and exclusion of the old worker, case 3).
  z4-late-write          The provider signed not_executed, then a receipt for that call appears: violated (I11), blame
                         server. The statement is accountable, not a proof of exclusion.

partial-effects:
  p1-interrupted         One signed receipt (first.txt), no call statement: preserved. The write that happened was within
                         authority; AMEP does not say the operation finished.
  p2-promised-two        The provider's statement says completed, 2 effects, and one receipt is present: unresolved
                         (receipt). Only the provider's statement makes the incompleteness visible.
  p3-handoff-rerun       runtime-b re-runs both files under the same admission after runtime-a's write: violated (I8),
                         the admission is spent twice.

Each evaluation's conclusion is kept as a signed verdict record (spec 10.8) by the caller's verifier key.

Run from the repository root:  python3 -I interop/authzen-receipts/vate-02-accepted-interrupted/generate.py
Keys are deterministic TEST keys; never use them for anything else.
"""
from __future__ import annotations

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
from amep_protocol.core import approval_digest, canon, digest, evaluate_text, verdict  # noqa: E402
from amep_protocol.verdicts import sign_envelope, statement, verify_envelope  # noqa: E402

# the case's target resources, shortened as in case 1
RESOURCE = {"zero": "store:handoff/resource-af03f2d1e49345349f850645ed510d52",
            "partial": "store:handoff/resource-3b4427e6b8a74b308b28114ffe7cd6b2"}
FILES = [("first.txt", "c6d0b56bb7dcde279c493625746cf72dd968d0b68b38724658dac44479f36d84", 19),
         ("second.txt", "d1844cecf2c9f8e459d882b6be79bbd1ba9e95ce649e140609c9ebf3ac0f0b32", 20)]
OPERATION = {"action": "demo.create_file_set", "operation_key": "operation-one",
             "files": [{"name": "first.txt", "text": "first local effect\n"},
                       {"name": "second.txt", "text": "second local effect\n"}]}
ARGS_DIGEST = hashlib.sha256(canon(OPERATION)).hexdigest()


def build():
    I = Signer("owner", ["issuer", "approver"])      # the local owner: issues the mandate and admits the operation
    A = Signer("runtime-a", ["host"])                # the first runtime
    B = Signer("runtime-b", ["host"])                # the runtime the work is handed off to
    O = Signer("provider-local", ["observer"])       # the provider: signs what it executed, or that nothing ran
    keys = {s.kid: s.public() for s in (I, A, B, O)}
    mandate = I.sign({"id": "m-1", "kind": "mandate", "principal": "urn:vate:demo:local-owner",
                      "claims": {"actions": ["demo.create_file_set"], "resources": ["store:handoff/*"],
                                 "ceiling": "write_local", "exp": 100}}, v=2)
    adapter = A.sign({"id": "a-1", "kind": "interpretation", "source": "curated", "adapter": "vate-demo-file-set",
                      "version": "v1"}, v=2)

    def variant(which):
        res = RESOURCE[which]
        files = [{"action": "demo.create_file_set", "resource": res, "effect": "write_local", "released": [], "t": 11,
                  "x-file": {"name": n, "sha256": s, "size": z}} for n, s, z in FILES]
        admission = I.sign({"id": "ap-1", "kind": "approval", "effect_digests": [approval_digest(b) for b in files],
                            "presence": "host_ui", "expiry": 50}, v=2)

        def invocation(n, signer, actor, t):
            return signer.sign({"id": f"i-{n}", "kind": "invocation", "authority_ref": "m-1", "interpretation_ref": "a-1",
                                "actor": actor, "t": t, "approval_ref": "ap-1",
                                "declared": {"action": "demo.create_file_set", "resource": res, "effect": "write_local"},
                                "args_digest": ARGS_DIGEST}, v=2)

        def receipt(inv, k, t=11):
            return O.sign({"id": f"e-{inv['id'][2:]}-{k + 1}", "kind": "effect", "invocation": inv["id"],
                           "observed_by": "provider-local", "assurance": "L3", "executed": {**files[k], "t": t},
                           "invocation_digest": digest(inv)}, v=2)

        def call_statement(inv, disposition, count, t=12):
            return O.sign({"id": f"c-{inv['id'][2:]}", "kind": "call_statement", "invocation": inv["id"],
                           "observed_by": "provider-local", "disposition": disposition, "effect_count": count, "t": t,
                           "invocation_digest": digest(inv), "args_digest": ARGS_DIGEST}, v=2)

        i1 = invocation(1, A, "urn:vate:demo:runtime-a", 10)
        i2 = invocation(2, B, "urn:vate:demo:runtime-b", 20)
        base = {"amep_version": "0.3", "mandates": [mandate], "delegations": [], "interpretations": [adapter],
                "approvals": [admission]}
        return i1, i2, base, receipt, call_statement

    z1, z2, zb, zr, zc = variant("zero")
    p1, p2, pb, pr, pc = variant("partial")
    return keys, [
        ("z1-interrupted", "zero-effects: runtime-a's attempt was accepted and interrupted; nothing from the provider",
         {**zb, "invocations": [z1], "effects": []}),
        ("z2-handoff-rerun", "zero-effects: runtime-b re-runs the operation under the same admission",
         {**zb, "invocations": [z1, z2], "effects": [zr(z2, 0, 21), zr(z2, 1, 21)]}),
        ("z3-not-executed", "zero-effects: the provider signs not_executed for runtime-a's call",
         {**zb, "invocations": [z1], "effects": [], "call_statements": [zc(z1, "not_executed", 0)]}),
        ("z4-late-write", "zero-effects: after not_executed, a receipt for runtime-a's call appears",
         {**zb, "invocations": [z1], "effects": [zr(z1, 0)], "call_statements": [zc(z1, "not_executed", 0)]}),
        ("p1-interrupted", "partial-effects: one signed receipt (first.txt), no call statement",
         {**pb, "invocations": [p1], "effects": [pr(p1, 0)]}),
        ("p2-promised-two", "partial-effects: the provider's statement says completed, 2 effects; one receipt is present",
         {**pb, "invocations": [p1], "effects": [pr(p1, 0)], "call_statements": [pc(p1, "completed", 2)]}),
        ("p3-handoff-rerun", "partial-effects: runtime-b re-runs both files under the same admission",
         {**pb, "invocations": [p1, p2], "effects": [pr(p1, 0), pr(p2, 0, 21), pr(p2, 1, 21)]}),
    ]


# packet verdict, and each invocation's own result (outcome, invariant, blame, gaps)
EXPECTED = {
    "z1-interrupted": (("unresolved", "I7"), {"i-1": ("unresolved", "I7", None, [{"need": "receipt", "ref": "i-1"}])}),
    "z2-handoff-rerun": (("unresolved", "I7"), {"i-1": ("unresolved", "I7", None, [{"need": "receipt", "ref": "i-1"}]),
                                                "i-2": ("unresolved", "I7", None, [{"need": "held_outcome", "ref": "i-1"}])}),
    "z3-not-executed": (("preserved", "-"), {"i-1": ("preserved", "-", None, [])}),
    "z4-late-write": (("violated", "I11"), {"i-1": ("violated", "I11", "server", [])}),
    "p1-interrupted": (("preserved", "-"), {"i-1": ("preserved", "-", None, [])}),
    "p2-promised-two": (("unresolved", "I7"), {"i-1": ("unresolved", "I7", None, [{"need": "receipt", "ref": "i-1"}])}),
    "p3-handoff-rerun": (("violated", "I8"), {"i-1": ("preserved", "-", None, []), "i-2": ("violated", "I8", "agent", [])}),
}


def main():
    keys, cases = build()
    caller_verifier = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"amep-test-vector-key-v1:caller-verifier").digest())
    pub = caller_verifier.public_key().public_bytes_raw().hex()
    with open(os.path.join(HERE, "keys.json"), "w") as fh:
        json.dump(keys, fh, indent=1)
    with open(os.path.join(HERE, "verifier-key.json"), "w") as fh:
        json.dump({"caller-verifier": pub}, fh, indent=1)
    for name, title, packet in cases:
        text = json.dumps(packet, indent=1, ensure_ascii=False) + "\n"
        with open(os.path.join(HERE, f"{name}.packet.json"), "w", encoding="utf-8") as fh:
            fh.write(text)
        res = evaluate_text(text, keys)
        v = verdict(res)
        want, per = EXPECTED[name]
        assert (v.outcome, v.invariant) == want, (name, v.outcome, v.invariant, v.reason)
        got = {r.invocation: (r.outcome, r.invariant, r.blame, r.gaps) for r in res}
        assert got == per, (name, got)
        env = sign_envelope(statement(text.encode("utf-8"), keys, res, {"name": "amep-protocol", "role": "caller verifier"}),
                            caller_verifier, "caller-verifier")
        assert verify_envelope(env, {"caller-verifier": pub})["predicate"]["verdict"]["outcome"] == v.outcome
        with open(os.path.join(HERE, f"{name}.verdict.dsse.json"), "w") as fh:
            json.dump(env, fh, indent=1)
        each = "; ".join(f"{i} {o} {inv}{' ' + b if b else ''}{' ' + ','.join(g['need'] + ' ' + g['ref'] for g in gs) if gs else ''}"
                         for i, (o, inv, b, gs) in got.items())
        print(f"{name:18} {v.outcome:10} {v.invariant:3}  [{each}]  ({title})")


if __name__ == "__main__":
    main()
