"""The family-office example of finos/ai-governance-framework#421 as AMEP evidence.

A client authorizes a family-office agent to invest up to USD 10,000,000. The agent splits the work between two
institutions and delegates each leg. The question in #421: do the final actions, taken together, still fall within
what the client authorized, including when the plan changes or a response is lost?

Each phase is one evidence packet. The institutions sign what they booked (receipts and call statements); the
family office's orchestrator signs what it delegated and dispatched; the client signs the mandate. AMEP's verdict is
computed from those records, not from the orchestrator's own count.

Phases (expected verdicts are asserted as the files are written):
  1-within-mandate        legs of 6M and 4M, both booked                                 preserved
  2-over-partitioned      slices of 6M and 6M (each narrower than 10M); 6M + 5M booked   violated I2
  3-leg-outside-mandate   the plan changes: a leg is delegated to an institution the
                          client never authorized                                        violated I1 (delegator)
  4-lost-response         leg A booked; leg B's 4M instruction sent, no response yet     unresolved I7 (receipt)
  5-retried-after-loss    as 4, and the agent retried leg B, which booked               unresolved I7 (receipt)
  6-reconciled-booked     institution B's record shows the first instruction booked too  violated I2
  7-reconciled-not-booked institution B signs that the first instruction never booked    preserved

Run from the repository root:  python3 -I interop/finos-aigf/case-421-family-office/generate.py
It writes the packets, their verifier state, keys.json and verdicts.json, and fails if any verdict is not the expected
one. All keys are deterministic test keys.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..", "..")
sys.path.insert(0, os.path.join(ROOT, "verifier", "python"))
sys.path.insert(0, os.path.join(ROOT, "packages", "python", "src"))

from amep_verifier import Signer  # noqa: E402
from amep_protocol.core import digest, evaluate, verdict  # noqa: E402

USD, PERIOD = "iso4217:USD", 1000      # one window covers the mandate's whole validity (nbf 0, exp 1000)
ROOT_CAP, LEG_A, LEG_B = "10000000.00", "6000000.00", "4000000.00"
INST = {"a": "inst:bank-a.example", "b": "inst:bank-b.example", "c": "inst:broker-c.example"}


def build():
    client = Signer("client-7", ["issuer"])                   # the client: signs the mandate
    office = Signer("family-office-orchestrator", ["host"])   # the family office: signs delegations and instructions
    obs = {k: Signer(v, ["observer"]) for k, v in INST.items()}  # each institution: signs what it booked
    keys = {s.kid: s.public() for s in (client, office, *obs.values())}

    mandate = client.sign({"id": "m-1", "kind": "mandate", "principal": "client:7",
                           "claims": {"actions": ["trade.book"], "resources": [f"{INST['a']}/*", f"{INST['b']}/*"],
                                      "ceiling": "financial", "nbf": 0, "exp": PERIOD,
                                      "limits": [{"unit": USD, "per_period": ROOT_CAP, "period": PERIOD}]}}, v=2)
    adapter = office.sign({"id": "a-1", "kind": "interpretation", "source": "curated", "adapter": "booking-api",
                           "version": "v1"}, v=2)

    def leg(name, inst, cap):
        """A delegation of one slice to the agent working at one institution; that institution counts its spend."""
        return office.sign({"id": f"d-{name}", "kind": "delegation", "parent": "m-1",
                            "claims": {"actions": ["trade.book"], "resources": [f"{INST[inst]}/*"], "ceiling": "financial",
                                       "nbf": 0, "exp": PERIOD, "depth": 0,
                                       "limits": [{"unit": USD, "per_period": cap, "period": PERIOD,
                                                   "counted_by": INST[inst]}]}}, v=2)

    def instruction(n, under, inst, t):
        return office.sign({"id": f"i-{n}", "kind": "invocation", "authority_ref": under, "interpretation_ref": "a-1",
                            "actor": f"agent:leg-{inst}", "t": t,
                            "declared": {"action": "trade.book", "resource": f"{INST[inst]}/portfolio/client-7",
                                         "effect": "financial"}}, v=2)

    def booked(inv, inst, amount, spent):
        """The institution's signed booking record, bound to the instruction it executed, and its own leg total."""
        d = digest(inv)
        receipt = obs[inst].sign({"id": f"e-{inv['id'][2:]}", "kind": "effect", "invocation": inv["id"],
                                  "observed_by": INST[inst], "assurance": "L3", "invocation_digest": d,
                                  "executed": {"action": "trade.book", "resource": inv["declared"]["resource"],
                                               "effect": "financial", "released": [], "t": inv["t"] + 1,
                                               "value": {"amount": amount, "unit": USD,
                                                         "period_spent": {str(PERIOD): spent}}}}, v=2)
        st = obs[inst].sign({"id": f"c-{inv['id'][2:]}", "kind": "call_statement", "invocation": inv["id"],
                             "observed_by": INST[inst], "disposition": "completed", "effect_count": 1,
                             "t": inv["t"] + 2, "invocation_digest": d}, v=2)
        return [receipt], [st]

    def never_booked(inv, inst):
        st = obs[inst].sign({"id": f"c-{inv['id'][2:]}", "kind": "call_statement", "invocation": inv["id"],
                             "observed_by": INST[inst], "disposition": "not_executed", "effect_count": 0,
                             "t": inv["t"] + 50, "invocation_digest": digest(inv)}, v=2)
        return [], [st]

    def packet(delegations, invocations, parts):
        effects = [e for r, _ in parts for e in r]
        statements = [s for _, s in parts for s in s]
        return {"amep_version": "0.3", "mandates": [mandate], "delegations": delegations, "interpretations": [adapter],
                "invocations": invocations, "effects": effects, "call_statements": statements}

    dA, dB = leg("a", "a", LEG_A), leg("b", "b", LEG_B)
    iA, iB = instruction("a1", "d-a", "a", 10), instruction("b1", "d-b", "b", 20)
    bookedA, bookedB = booked(iA, "a", LEG_A, LEG_A), booked(iB, "b", LEG_B, LEG_B)

    # 2: each slice is narrower than the mandate on its own, but the slices add up to more than it
    dB6 = leg("b", "b", "6000000.00")
    p2B = booked(iB, "b", "5000000.00", "5000000.00")

    # 3: the plan changes, and a leg is delegated to an institution the client never named
    dC = leg("c", "c", LEG_B)
    iC = instruction("c1", "d-c", "c", 20)

    # 4 to 7: leg B's first instruction gets no response; the agent retries it
    iB2 = instruction("b2", "d-b", "b", 40)
    retryB = booked(iB2, "b", LEG_B, LEG_B)                    # institution B's total, counting only the retry
    bothB = booked(iB, "b", LEG_B, LEG_B)                      # the first instruction did book, at t 21
    retryB_after = booked(iB2, "b", LEG_B, "8000000.00")       # so B's own total after the retry is 8M

    phases = [
        ("1-within-mandate", "Legs of 6M at bank A and 4M at bank B, both booked",
         packet([dA, dB], [iA, iB], [bookedA, bookedB]), ("preserved", "-")),
        ("2-over-partitioned", "Slices of 6M and 6M, each narrower than 10M; bookings of 6M and 5M exceed the mandate",
         packet([dA, dB6], [iA, iB], [bookedA, p2B]), ("violated", "I2")),
        ("3-leg-outside-mandate", "The plan changes: a 4M leg is delegated to a broker the client never authorized",
         packet([dA, dC], [iA, iC], [bookedA, booked(iC, "c", LEG_B, LEG_B)]), ("violated", "I1")),
        ("4-lost-response", "Leg A booked; leg B's 4M instruction was sent and no response came back",
         packet([dA, dB], [iA, iB], [bookedA]), ("unresolved", "I7")),
        ("5-retried-after-loss", "As 4, and the agent retried leg B, which booked",
         packet([dA, dB], [iA, iB, iB2], [bookedA, retryB]), ("unresolved", "I7")),
        ("6-reconciled-booked", "Reconciliation: bank B's records show the first instruction booked too (14M in all)",
         packet([dA, dB], [iA, iB, iB2], [bookedA, bothB, retryB_after]), ("violated", "I2")),
        ("7-reconciled-not-booked", "Reconciliation: bank B signs that the first instruction never booked (10M in all)",
         packet([dA, dB], [iA, iB, iB2], [bookedA, never_booked(iB, "b"), retryB]), ("preserved", "-")),
    ]
    return keys, phases


def state():
    """The client's verifier holds every leg from the start of the window: nothing was spent before this packet."""
    return {"period_totals": {f"m-1|{USD}|{PERIOD}|0": "0.00"}}


def main():
    keys, phases = build()
    with open(os.path.join(HERE, "keys.json"), "w") as fh:
        json.dump(keys, fh, indent=1)
        fh.write("\n")
    with open(os.path.join(HERE, "state.json"), "w") as fh:
        json.dump(state(), fh, indent=1)
        fh.write("\n")
    summary = []
    for name, title, p, expected in phases:
        text = json.dumps(p, indent=1) + "\n"
        with open(os.path.join(HERE, f"{name}.packet.json"), "w") as fh:
            fh.write(text)
        results = evaluate(json.loads(text), keys, state=state())
        v = verdict(results)
        assert (v.outcome, v.invariant) == expected, (name, v.outcome, v.invariant, v.reason)
        summary.append({"phase": name, "title": title, "outcome": v.outcome, "invariant": v.invariant, "blame": v.blame,
                        "gaps": v.gaps, "reason": v.reason})
        detail = v.blame if v.outcome == "violated" else ", ".join(f"{g['need']} {g['ref']}" for g in v.gaps)
        print(f"{name:24} {v.outcome:10} {v.invariant:3} {detail or '':22} {v.reason or ''}")
    with open(os.path.join(HERE, "verdicts.json"), "w") as fh:
        json.dump(summary, fh, indent=1)
        fh.write("\n")


if __name__ == "__main__":
    main()
