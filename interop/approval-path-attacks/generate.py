"""Generate AMEP test vectors for approval-path attacks on agent step-up authorization.

Draft for review. The attack catalogue (AB1-AB12, substitution, replay, grant stretching) is from
S. V. Kodathala, P. Pollishetty and J. Cargill, "Approve What, Exactly? Effect Binding and Trusted
Rendering for Agent Step-Up Authorization", arXiv:2610.21063, 2026. The vectors ask a narrower
question than the paper: given only the evidence left behind (a signed approval, a signed
invocation and a signed receipt of what the payment system executed), can a third party show
after the fact that the attack happened? Attacks that cannot be shown from evidence are listed in
README.md instead of being forced into a vector.

Scenario:
  P  did:web:bank.example:customers:alice        the principal; her passkey key is the approver
  A  did:web:agents.example:payments-assistant   the agent that initiates payments for Alice
  B  service:payments.bank.example               the bank's payment system; it signs what it executed

Run from the repository root:
  python3 -I interop/approval-path-attacks/generate.py
Writes keys.json, positive/ and must-reject/ next to this file and checks every vector with the
AMEP reference verifier. Keys are deterministic TEST keys; never use them for anything else.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..")
sys.path.insert(0, os.path.join(ROOT, "verifier", "python"))
sys.path.insert(0, os.path.join(ROOT, "packages", "python", "src"))

from amep_verifier import Signer  # noqa: E402
from amep_protocol.core import approval_digest, evaluate, verdict  # noqa: E402

P_DID = "did:web:bank.example:customers:alice"
A_DID = "did:web:agents.example:payments-assistant"
B_ID = "service:payments.bank.example"
LANDLORD = "payee:landlord-ltd"
UTILITY = "payee:city-utility"
ATTACKER = "payee:attacker-co"
PAPER = "arXiv:2610.21063"

RENT = {"amount": "1200.00", "currency": "EUR", "memo": "November rent"}


def pay(resource, args, t=11, **extra):
    """The executed-effect body for one payment. Payment arguments travel in the x-args extension."""
    return {"action": "payments.send", "resource": resource, "effect": "financial", "released": [],
            "reversible": False, "t": t, "x-args": args, **extra}


def build():
    I = Signer("alice-passkey", ["issuer", "approver"])   # Alice's key: issues her mandate and signs approvals
    H = Signer("agent-host", ["host"])                    # the agent runtime
    O = Signer("bank-payments", ["observer"])             # the bank's payment system
    X = Signer("attacker-passkey")                        # a key the attacker enrolled (AB7): no role in Alice's key set
    keys = {s.kid: s.public() for s in (I, H, O)}
    V = []

    def mandate(**kw):
        claims = {"actions": ["payments.send"], "resources": [LANDLORD, UTILITY],
                  "ceiling": "financial", "exp": 100, **kw}
        return I.sign({"id": "m-1", "kind": "mandate", "principal": P_DID, "claims": claims})

    def invocation(n, resource, t, approval=None):
        inv = {"id": f"i-{n}", "kind": "invocation", "authority_ref": "m-1", "interpretation_ref": "a-1",
               "actor": A_DID, "t": t,
               "declared": {"action": "payments.send", "resource": resource, "effect": "financial"}}
        if approval:
            inv["approval_ref"] = approval
        return H.sign(inv)

    def receipt(n, body):
        return O.sign({"id": f"e-{n}", "kind": "effect", "invocation": f"i-{n}", "observed_by": B_ID,
                       "assurance": "L3", "executed": body})

    def approval(aid, approved_body, signer=None, **kw):
        return (signer or I).sign({"id": aid, "kind": "approval", "effect_digest": approval_digest(approved_body),
                                   "presence": "webauthn", "expiry": 50, **kw})

    def packet(payments, approvals=(), m=None):
        """payments: list of (declared resource, executed body, approval id or None)."""
        p = {"mandates": [m or mandate()],
             "interpretations": [H.sign({"id": "a-1", "kind": "interpretation", "source": "curated",
                                         "adapter": "bank_payments_api", "version": "v2"})],
             "invocations": [], "effects": [], "approvals": list(approvals)}
        for n, (declared, body, aid) in enumerate(payments, 1):
            p["invocations"].append(invocation(n, declared, 10 * n, aid))
            p["effects"].append(receipt(n, {**body, "t": 10 * n + 1}))
        if not p["approvals"]:
            del p["approvals"]
        return p

    def add(slug, attack, question, expect, p, note=""):
        V.append({"name": slug, "attack": attack, "source": PAPER, "question": question,
                  "expect": {"outcome": expect[0], "invariant": expect[1]}, "note": note, "packet": p})

    rent = pay(LANDLORD, RENT)

    # ---------------- positive ----------------
    add("approved-payment-executed-as-approved", "baseline (P2 binding)",
        "Alice approves this exact payment, and the bank executes exactly that.", ("preserved", "-"),
        packet([(LANDLORD, rent, "ap-1")], [approval("ap-1", rent)]))
    add("two-payments-two-approvals", "baseline (P3 single use)",
        "Two payments, each with its own approval, each used once.", ("preserved", "-"),
        packet([(LANDLORD, rent, "ap-1"), (UTILITY, pay(UTILITY, {"amount": "84.10", "currency": "EUR"}), "ap-2")],
               [approval("ap-1", rent), approval("ap-2", pay(UTILITY, {"amount": "84.10", "currency": "EUR"}))]))
    add("small-payment-within-budget-needs-no-approval", "baseline for AB12",
        "One payment within the mandate's risk budget; no approval is required.", ("preserved", "-"),
        packet([(UTILITY, pay(UTILITY, {"amount": "84.10", "currency": "EUR"}), None)], m=mandate(budget=100)))
    add("signed-body-with-both-amounts-is-preserved", "AB1 (boundary)",
        "Alice's key signed a body that really contains both amounts. The evidence binds what was signed; whether "
        "the card showed both amounts is outside what evidence can show.", ("preserved", "-"),
        packet([(LANDLORD, pay(LANDLORD, {"amounts": ["5000.00", "-4950.00"], "currency": "EUR"}), "ap-1")],
               [approval("ap-1", pay(LANDLORD, {"amounts": ["5000.00", "-4950.00"], "currency": "EUR"}))]),
        note="Shows the limit of after-the-fact evidence: if the signed bytes contain the attack, the approval is genuine. "
             "Detection then depends on trusted rendering (the paper's H3), not on the evidence.")

    # ---------------- must reject: binding (substitution) ----------------
    add("post-approval-substitution", "AB10, substitution",
        "Arguments change between approval and execution: Alice approved 1,200 EUR, the bank executed 12,000 EUR.",
        ("violated", "I8"),
        packet([(LANDLORD, pay(LANDLORD, {**RENT, "amount": "12000.00"}), "ap-1")], [approval("ap-1", rent)]))
    add("amount-cancellation", "AB1",
        "Alice approved a net 50 EUR; the executed body carries +5,000 and -4,950.", ("violated", "I8"),
        packet([(LANDLORD, pay(LANDLORD, {"amounts": ["5000.00", "-4950.00"], "currency": "EUR"}), "ap-1")],
               [approval("ap-1", pay(LANDLORD, {"amount": "50.00", "currency": "EUR"}))]))
    add("decoy-field-recipient", "AB2",
        "The approved body names the landlord; the executed body adds a second beneficiary under an innocuous key.",
        ("violated", "I8"),
        packet([(LANDLORD, pay(LANDLORD, {**RENT, "reference": ATTACKER}), "ap-1")], [approval("ap-1", rent)]))
    add("decoy-recipient-executed", "AB2, substitution",
        "The agent declared and Alice approved a payment to the landlord; the bank's receipt shows the attacker was paid.",
        ("violated", "I2"),
        packet([(LANDLORD, pay(ATTACKER, RENT), "ap-1")], [approval("ap-1", rent)]),
        note="Caught by I2 (declared differs from executed) before the approval check is reached.")
    add("hidden-text-in-executed-argument", "AB4",
        "The executed memo contains a right-to-left override and padding that the approved body did not.",
        ("violated", "I8"),
        packet([(LANDLORD, pay(LANDLORD, {**RENT, "memo": "November rent‮" + "⠀" * 40 + "+ fee to attacker-co"}), "ap-1")],
               [approval("ap-1", rent)]),
        note="Only the case where the hidden text was added after approval. If Alice's key signed the hidden text, "
             "see AB4 under 'Not detectable from evidence' in README.md.")

    # ---------------- must reject: grant stretching ----------------
    add("standing-grant-to-new-payee", "AB3, grant stretching",
        "A standing grant covers the landlord and the utility; the agent pays a new payee under it.", ("violated", "I2"),
        packet([(ATTACKER, pay(ATTACKER, RENT), None)]))
    add("approval-reused-for-larger-amount", "AB3, grant stretching",
        "An approval for 1,200 EUR is presented for a 1,900 EUR payment to the same payee.", ("violated", "I8"),
        packet([(LANDLORD, pay(LANDLORD, {**RENT, "amount": "1900.00"}), "ap-1")], [approval("ap-1", rent)]))

    # ---------------- must reject: single use (replay) ----------------
    add("approval-replayed-in-same-run", "replay (P3)",
        "One approval is cited by two payments with identical bodies: one response, two executions.", ("violated", "I8"),
        packet([(LANDLORD, rent, "ap-1"), (LANDLORD, rent, "ap-1")], [approval("ap-1", rent)]))
    add("approval-marked-consumed", "replay (P3)",
        "The approval record is already marked consumed when it is presented.", ("violated", "I8"),
        packet([(LANDLORD, rent, "ap-1")], [approval("ap-1", rent, consumed=True)]))
    add("approval-used-after-expiry", "replay (P3)",
        "The approval expired before the payment executed.", ("violated", "I8"),
        packet([(LANDLORD, rent, "ap-1")], [approval("ap-1", rent, expiry=5)]))

    # ---------------- must reject: who approved ----------------
    add("approval-signed-by-enrolled-attacker-key", "AB7",
        "The attacker enrolled its own passkey and approved its own call. The key holds no approver role in Alice's key set.",
        ("unresolved", "I7"),
        packet([(LANDLORD, rent, "ap-1")], [approval("ap-1", rent, signer=X)]),
        note="Unresolved, not violated: the evidence cannot show who controls the unknown key, only that no "
             "authorised approver signed. Detection depends on the verifier's key set being enrolled honestly.")

    # ---------------- must reject: threshold splitting ----------------
    add("payment-split-under-threshold", "AB12",
        "One large payment is split into two that each look small. The mandate's risk budget (100) is exceeded by the "
        "second, which carries no approval.", ("violated", "I2"),
        packet([(LANDLORD, pay(LANDLORD, {**RENT, "amount": "600.00", "memo": "rent part 1"}), None),
                (LANDLORD, pay(LANDLORD, {**RENT, "amount": "600.00", "memo": "rent part 2"}), None)],
               m=mandate(budget=100)),
        note="AMEP budgets count effect cost units (here 60 per irreversible payment), not currency. A monetary "
             "threshold would need a profile; see README.md.")
    return keys, V


def main():
    keys, V = build()
    for sub in ("positive", "must-reject"):
        os.makedirs(os.path.join(HERE, sub), exist_ok=True)
        for f in os.listdir(os.path.join(HERE, sub)):
            if f.endswith(".json"):
                os.remove(os.path.join(HERE, sub, f))
    with open(os.path.join(HERE, "keys.json"), "w") as fh:
        json.dump(keys, fh, indent=1)
    ok = 0
    for v in V:
        r = verdict(evaluate(json.loads(json.dumps(v["packet"])), keys))
        good = (r.outcome, r.invariant) == (v["expect"]["outcome"], v["expect"]["invariant"])
        ok += good
        if not good:
            print(f"FAIL {v['name']}: got {r.outcome}/{r.invariant} ({r.reason}), expected {v['expect']}")
        sub = "positive" if v["expect"]["outcome"] == "preserved" else "must-reject"
        with open(os.path.join(HERE, sub, v["name"] + ".json"), "w", encoding="utf-8") as fh:
            json.dump(v, fh, indent=1, ensure_ascii=False)
    print(f"{ok}/{len(V)} vectors match their expected outcome")
    return 0 if ok == len(V) else 1


if __name__ == "__main__":
    sys.exit(main())
