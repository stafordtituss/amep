"""Shared scenario: a user lets an agent update tickets 48xx only; tools report which ticket they changed."""
from __future__ import annotations

from amep_protocol import sdk

from amep_agents import Effect, EvidenceRecorder

ISSUER = sdk.Key.generate("issuer-1", ["issuer"])
HOST = sdk.Key.generate("host-1", ["host"])
OBSERVER = sdk.Key.generate("tool-runtime-1", ["observer"])
KEYS = sdk.keyset(ISSUER, HOST, OBSERVER)
EXP = "2030-01-01T00:00:00Z"

MANDATE = ISSUER.sign(sdk.mandate("m-1", "user:alice", sdk.claims(
    ["tickets.read", "tickets.update"], ["tickets:issue/*"], "write_shared", EXP, depth=1)))
DELEGATION = ISSUER.sign(sdk.delegation("d-1", "m-1", sdk.claims(
    ["tickets.read", "tickets.update"], ["tickets:issue/48*"], "write_shared", EXP, depth=0)))


def interpret(tool: str, args: dict):
    if tool == "get_ticket":
        return Effect("tickets.read", f"tickets:issue/{args['ticket_id']}", "read")
    if tool == "update_ticket":
        return Effect("tickets.update", f"tickets:issue/{args['ticket_id']}", "write_shared", reversible=True)
    return None   # other tools are not governed


def executed(tool: str, args: dict, output):
    """The tool's own report of what it changed (here: the "updated" field of its output)."""
    if tool == "update_ticket" and isinstance(output, dict) and "updated" in output:
        return Effect("tickets.update", f"tickets:issue/{output['updated']}", "write_shared", reversible=True)
    return interpret(tool, args)


def recorder(adapter: str) -> EvidenceRecorder:
    return EvidenceRecorder(HOST, OBSERVER, "d-1", interpret, executed=executed, chain=[MANDATE, DELEGATION],
                            actor="agent:support-bot", adapter=adapter, adapter_version="test")


class Tickets:
    """A tiny ticket store. buggy=True writes to the wrong ticket, which the tool's own report exposes."""

    def __init__(self, buggy: bool = False):
        self.buggy, self.tickets = buggy, {"4821": "open", "4822": "open", "9999": "open"}

    def get(self, ticket_id: str) -> dict:
        return {"ticket": ticket_id, "status": self.tickets[ticket_id]}

    def update(self, ticket_id: str, status: str) -> dict:
        if ticket_id not in self.tickets:
            raise KeyError(f"no ticket {ticket_id}")
        target = "4822" if self.buggy else ticket_id
        self.tickets[target] = status
        return {"updated": target, "status": status}
