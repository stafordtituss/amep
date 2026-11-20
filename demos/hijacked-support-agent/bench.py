"""Measure what the evidence costs: per-call latency with and without the AMEP gateway, verification time, size.

    python bench.py [N]     N tool calls per configuration (default 500)

Both configurations use the same help-desk tools over the same in-process MCP transport. The baseline is a server
without the evidence extension, called directly. The AMEP configuration signs an invocation, has the server sign a
receipt, and checks that receipt's signature at the gateway. The in-process transport has no network, so the
absolute overhead is the meaningful number, not the ratio.
"""
from __future__ import annotations

import asyncio
import json
import platform
import statistics
import sys
import time

from helpdesk import TICKET, EvidenceGateway, KEYS
from amep_evidence import AmepEvidenceClient
from amep_protocol import evaluate
from mcp import Client
from mcp.server.mcpserver import MCPServer

import helpdesk


def plain_server() -> MCPServer:
    tickets = {TICKET: {"status": "open"}}
    server = MCPServer("helpdesk-plain")

    @server.tool()
    async def update_ticket(ticket_id: str, status: str) -> str:
        tickets[ticket_id]["status"] = status
        return f"ticket {ticket_id} is now {status}"
    return server


def summary(xs: list[float]) -> dict:
    xs = sorted(xs)
    return {"median_ms": round(statistics.median(xs) * 1e3, 3), "p95_ms": round(xs[int(0.95 * (len(xs) - 1))] * 1e3, 3)}


async def bench(n: int) -> dict:
    args = {"ticket_id": TICKET, "status": "resolved"}
    base = []
    async with Client(plain_server()) as client:
        for _ in range(20):
            await client.call_tool("update_ticket", args)
        for _ in range(n):
            t = time.perf_counter(); await client.call_tool("update_ticket", args); base.append(time.perf_counter() - t)
    amep = []
    async with Client(helpdesk.build_server(injected=False), extensions=[AmepEvidenceClient()]) as client:
        gw = EvidenceGateway(client, scope="task")
        for _ in range(20):
            await gw.call("update_ticket", args)
        gw.invocations.clear(); gw.receipts.clear()
        for _ in range(n):
            t = time.perf_counter(); await gw.call("update_ticket", args); amep.append(time.perf_counter() - t)
        packet = gw.packet()
    assert len(gw.receipts) == n and not gw.rejected
    t = time.perf_counter(); results = evaluate(packet, KEYS); verify_s = time.perf_counter() - t
    assert all(r.outcome == "preserved" for r in results)
    per_call_bytes = (len(json.dumps(packet["invocations"], separators=(",", ":")))
                      + len(json.dumps(packet["effects"], separators=(",", ":")))) / n
    b, a = summary(base), summary(amep)
    return {"calls": n, "baseline": b, "amep": a,
            "overhead_median_ms": round(a["median_ms"] - b["median_ms"], 3),
            "verify_ms_per_call": round(verify_s * 1e3 / n, 3),
            "evidence_bytes_per_call": round(per_call_bytes),
            "machine": f"{platform.system()} {platform.machine()}, Python {platform.python_version()}"}


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    print(json.dumps(asyncio.run(bench(n)), indent=1))
