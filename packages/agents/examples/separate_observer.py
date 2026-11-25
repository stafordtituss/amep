"""How-to: keep the observer key away from the agent.

For a high-impact call (write_shared or above), AMEP counts a receipt only if it was signed by a party other than the
agent's host (invariant I10), and, where the key set names operators, by another operator. So the receipt should be
signed where the tool runs, not where the agent runs. This example splits the two sides:

- the agent's host signs the invocation, with only the host key;
- the tool runtime receives the call, does the work, and signs the receipt, with only its own key, bound to the exact
  invocation by digest.

It then shows the failure this prevents: the same receipt signed with the host's key is not evidence for the call.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from amep_protocol import evaluate, sdk, verdict  # noqa: E402
from amep_protocol.core import digest  # noqa: E402
from _setup import DELEGATION, EXP, ISSUER, MANDATE  # noqa: E402

HOST = sdk.Key.generate("agent-host", ["host", "observer"])       # the agent's runtime (could also sign as observer)
TOOL = sdk.Key.generate("ticket-service", ["observer"])           # the ticket service, run by another team


class TicketService:
    """The tool runtime. It holds its own key; the agent never sees it."""

    def __init__(self, key):
        self.key = key

    def handle(self, invocation, args):
        # ... perform the update, then sign what was done, bound to this exact invocation
        body = sdk.effect_body("tickets.update", f"tickets:issue/{args['ticket_id']}", "write_shared", 11, reversible=True)
        return self.key.sign(sdk.effect("e-1", invocation["id"], "service:tickets", "L2", body,
                                        invocation_digest=digest(invocation)))


def keyset():
    keys = sdk.keyset(ISSUER, HOST, TOOL)
    keys["agent-host"]["operator"] = "org:support-platform"      # who controls each key (spec 12.5)
    keys["ticket-service"]["operator"] = "org:ticketing"
    return keys


def main():
    interp = HOST.sign(sdk.interpretation("a-1", "tickets", "1"))
    inv = HOST.sign(sdk.invocation("i-1", "d-1", "a-1", 10, "tickets.update", "tickets:issue/4821", "write_shared",
                                   actor="agent:support-bot"))
    receipt = TicketService(TOOL).handle(inv, {"ticket_id": "4821"})
    good = verdict(evaluate(sdk.packet(MANDATE, DELEGATION, interp, inv, receipt), keyset()))

    # the same receipt, signed by the agent's own host key: the actor vouching for itself
    self_signed = HOST.sign({k: v for k, v in receipt.items() if k != "proof"})
    bad = verdict(evaluate(sdk.packet(MANDATE, DELEGATION, interp, inv, self_signed), keyset()))
    print(f"receipt from the ticket service: {good.outcome} {good.invariant}")
    print(f"receipt from the agent's host:   {bad.outcome} {bad.invariant}")
    return {"separate": (good.outcome, good.invariant), "self": (bad.outcome, bad.invariant)}


if __name__ == "__main__":
    main()
