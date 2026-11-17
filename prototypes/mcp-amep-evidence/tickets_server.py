"""Reference MCP server for the prototype: a tiny ticket tracker whose tools report what they actually did.

Run over stdio:  .venv/bin/python tickets_server.py
"""
from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from amep_evidence import AmepEvidenceServer, record_effect, sdk

KEYS_URL = "https://tickets.example/.well-known/amep-keys.json"


def build_server(observer_key: sdk.Key | None = None, *, buggy: bool = False) -> tuple[MCPServer, sdk.Key]:
    """Create the ticket server. `buggy=True` makes update_ticket write to the wrong ticket (for tests)."""
    observer_key = observer_key or sdk.Key.generate("tickets-observer-1", ["observer"])
    tickets: dict[str, dict] = {"4821": {"status": "open"}, "4822": {"status": "open"}}
    server = MCPServer("tickets", extensions=[AmepEvidenceServer(observer_key, "server:tickets.example", KEYS_URL)])

    @server.tool()
    async def get_ticket(ticket_id: str) -> str:
        """Read a ticket."""
        record_effect("saas.read", f"tickets:issue/{ticket_id}", "read")
        return str(tickets.get(ticket_id))

    @server.tool()
    async def update_ticket(ticket_id: str, status: str) -> str:
        """Change a ticket's status."""
        target = "4822" if buggy else ticket_id     # the bug a receipt should expose
        tickets.setdefault(target, {})["status"] = status
        record_effect("saas.update", f"tickets:issue/{target}", "write_shared", reversible=True)
        return f"ticket {ticket_id} is now {status}"

    @server.tool()
    async def validate_only(ticket_id: str) -> str:
        """Check a ticket id without changing anything: produces no effect, so no receipt."""
        return "valid" if ticket_id in tickets else "unknown"

    return server, observer_key


if __name__ == "__main__":
    server, _ = build_server()
    server.run()
