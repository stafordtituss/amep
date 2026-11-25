"""What every example shares: a person's mandate, a delegation to the agent, and the tool descriptions.

Alice lets a support agent read and update tickets, and the delegation narrows that to tickets 48xx. In a real
deployment, the issuer key belongs to Alice's organization, the host key to the agent's runtime, and the observer key to
the tool runtime or a proxy. Here all three are generated in-process so the example runs on its own.
"""
from amep_protocol import sdk

from amep_agents import Effect, EvidenceRecorder

EXP = "2030-01-01T00:00:00Z"
ISSUER = sdk.Key.generate("issuer-1", ["issuer"])
HOST = sdk.Key.generate("host-1", ["host"])
OBSERVER = sdk.Key.generate("tool-runtime-1", ["observer"])
KEYS = sdk.keyset(ISSUER, HOST, OBSERVER)

MANDATE = ISSUER.sign(sdk.mandate("m-1", "user:alice", sdk.claims(
    ["tickets.read", "tickets.update"], ["tickets:issue/*"], "write_shared", EXP, depth=1)))
DELEGATION = ISSUER.sign(sdk.delegation("d-1", "m-1", sdk.claims(
    ["tickets.read", "tickets.update"], ["tickets:issue/48*"], "write_shared", EXP, depth=0)))


def interpret(tool, args):
    """What a call declares, in AMEP terms. Return None for tools you don't govern."""
    if tool == "get_ticket":
        return Effect("tickets.read", f"tickets:issue/{args['ticket_id']}", "read")
    if tool == "update_ticket":
        return Effect("tickets.update", f"tickets:issue/{args['ticket_id']}", "write_shared", reversible=True)
    return None


def executed(tool, args, output):
    """What the tool reports it actually did. Here, the ticket id in its output."""
    if tool == "update_ticket" and isinstance(output, dict) and "updated" in output:
        return Effect("tickets.update", f"tickets:issue/{output['updated']}", "write_shared", reversible=True)
    return interpret(tool, args)


def new_recorder(adapter="example"):
    return EvidenceRecorder(HOST, OBSERVER, "d-1", interpret, executed=executed, chain=[MANDATE, DELEGATION],
                            actor="agent:support-bot", adapter=adapter, adapter_version="1")


TICKETS = {"4821": "open", "4822": "open", "9999": "open"}


def get_ticket(ticket_id):
    return {"ticket": ticket_id, "status": TICKETS[ticket_id]}


def update_ticket(ticket_id, status):
    TICKETS[ticket_id] = status
    return {"updated": ticket_id, "status": status}
