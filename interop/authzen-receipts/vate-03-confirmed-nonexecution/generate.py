"""VATE case 3 (confirmed nonexecution and handoff) as AMEP evidence.

The case is from Takao Sato's Verifiable Agent Trust Envelope reference vectors for openid/authzen#795:
reference/authzen-receipt-vectors/cases/03-confirmed-nonexecution-handoff, variants fenced-handoff and live-worker, at
commit 3e9c262. The owner admits one operation that writes two files; runtime-a gets the first ticket.

fenced-handoff: the provider confirms that runtime-a's attempt did not execute and fences it (a new generation), so a
handoff to runtime-b may continue. runtime-a's late submit is denied (old_generation); runtime-b completes the work.
live-worker: runtime-a is still live, so the handoff is refused (busy); runtime-a then completes the work itself.

The admission is carried as an AMEP operation approval (spec 5.10) over the digests of both file effects, as in
cases 1 and 2.

fenced-handoff:
  f1-pending          runtime-a's signed invocation, nothing from the provider: unresolved (receipt).
  f2-fenced           the provider signs not_executed for runtime-a's call: preserved, "nothing executed". The hold on
                      the admission is released, so a continuation is admissible.
  f3-completed        as f2, then runtime-b runs the operation under the same admission and the provider signs both
                      writes: both calls preserved. The admission is used once.
  f4-late-write       (not in VATE) as f3, but runtime-a's late write lands as well: violated (I11), blame server. The
                      provider's signed statement is contradicted. runtime-b's call stays preserved: it relied on that
                      statement, so the double write is the provider's to answer for, not runtime-b's. VATE prevents
                      this (old_generation); AMEP detects it after the fact and names who is accountable.

live-worker:
  l1-pending          as f1: unresolved (receipt).
  l2-busy-rerun       (not in VATE) runtime-b runs under the same admission while runtime-a's outcome is unknown:
                      runtime-b's call is unresolved, gap held_outcome naming runtime-a's call. VATE refuses the
                      handoff (busy); AMEP holds the admission.
  l3-completed        runtime-a's two writes, signed by the provider: preserved.
  l4-rerun-after      (not in VATE) as l3, then runtime-b re-runs the operation: violated (I8).

Each evaluation's conclusion is kept as a signed verdict record (spec 10.8) by the caller's verifier key.

Run from the repository root:  python3 -I interop/authzen-receipts/vate-03-confirmed-nonexecution/generate.py
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

# the case's target resources, shortened as in cases 1 and 2
RESOURCE = {"fenced": "store:handoff/resource-15a9c5a3837040d79faf6a4c7a408d24",
            "live": "store:handoff/resource-f49e33be1b7c4be29d6313bee0c27763"}
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

        def receipt(inv, k, t):
            return O.sign({"id": f"e-{inv['id'][2:]}-{k + 1}", "kind": "effect", "invocation": inv["id"],
                           "observed_by": "provider-local", "assurance": "L3", "executed": {**files[k], "t": t},
                           "invocation_digest": digest(inv)}, v=2)

        def not_executed(inv, t=12):
            return O.sign({"id": f"c-{inv['id'][2:]}", "kind": "call_statement", "invocation": inv["id"],
                           "observed_by": "provider-local", "disposition": "not_executed", "effect_count": 0, "t": t,
                           "invocation_digest": digest(inv), "args_digest": ARGS_DIGEST}, v=2)

        a = invocation(1, A, "urn:vate:demo:runtime-a", 10)
        b = invocation(2, B, "urn:vate:demo:runtime-b", 20)
        base = {"amep_version": "0.3", "mandates": [mandate], "delegations": [], "interpretations": [adapter],
                "approvals": [admission]}
        return a, b, base, receipt, not_executed

    fa, fb, fbase, fr, fn = variant("fenced")
    la, lb, lbase, lr, _ = variant("live")
    return keys, [
        ("f1-pending", "fenced-handoff, pending: runtime-a holds the ticket; nothing from the provider",
         {**fbase, "invocations": [fa], "effects": []}),
        ("f2-fenced", "fenced-handoff, fenced: the provider signs not_executed for runtime-a's call",
         {**fbase, "invocations": [fa], "effects": [], "call_statements": [fn(fa)]}),
        ("f3-completed", "fenced-handoff, completed: runtime-b completes under the same admission",
         {**fbase, "invocations": [fa, fb], "effects": [fr(fb, 0, 21), fr(fb, 1, 21)], "call_statements": [fn(fa)]}),
        ("f4-late-write", "not in VATE: as f3, and runtime-a's late write lands as well",
         {**fbase, "invocations": [fa, fb], "effects": [fr(fa, 0, 22), fr(fb, 0, 21), fr(fb, 1, 21)],
          "call_statements": [fn(fa)]}),
        ("l1-pending", "live-worker, pending: runtime-a holds the ticket; nothing from the provider",
         {**lbase, "invocations": [la], "effects": []}),
        ("l2-busy-rerun", "not in VATE: runtime-b runs while runtime-a's outcome is unknown",
         {**lbase, "invocations": [la, lb], "effects": [lr(lb, 0, 21), lr(lb, 1, 21)]}),
        ("l3-completed", "live-worker, completed: runtime-a's two writes, signed by the provider",
         {**lbase, "invocations": [la], "effects": [lr(la, 0, 11), lr(la, 1, 11)]}),
        ("l4-rerun-after", "not in VATE: as l3, then runtime-b re-runs the operation",
         {**lbase, "invocations": [la, lb], "effects": [lr(la, 0, 11), lr(la, 1, 11), lr(lb, 0, 21), lr(lb, 1, 21)]}),
    ]


# packet verdict, and each invocation's own result (outcome, invariant, blame, gaps)
RECEIPT = [{"need": "receipt", "ref": "i-1"}]
EXPECTED = {
    "f1-pending": (("unresolved", "I7"), {"i-1": ("unresolved", "I7", None, RECEIPT)}),
    "f2-fenced": (("preserved", "-"), {"i-1": ("preserved", "-", None, [])}),
    "f3-completed": (("preserved", "-"), {"i-1": ("preserved", "-", None, []), "i-2": ("preserved", "-", None, [])}),
    "f4-late-write": (("violated", "I11"), {"i-1": ("violated", "I11", "server", []), "i-2": ("preserved", "-", None, [])}),
    "l1-pending": (("unresolved", "I7"), {"i-1": ("unresolved", "I7", None, RECEIPT)}),
    "l2-busy-rerun": (("unresolved", "I7"), {"i-1": ("unresolved", "I7", None, RECEIPT),
                                             "i-2": ("unresolved", "I7", None, [{"need": "held_outcome", "ref": "i-1"}])}),
    "l3-completed": (("preserved", "-"), {"i-1": ("preserved", "-", None, [])}),
    "l4-rerun-after": (("violated", "I8"), {"i-1": ("preserved", "-", None, []), "i-2": ("violated", "I8", "agent", [])}),
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
        print(f"{name:16} {v.outcome:10} {v.invariant:3}  [{each}]  ({title})")


if __name__ == "__main__":
    main()
