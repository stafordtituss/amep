"""Integration tests for the amep-evidence MCP extension prototype, on the official MCP Python SDK.

Run:  .venv/bin/python -m unittest -v test_prototype
Each test runs a real MCP session (in-process, or over stdio) and checks the evidence with the AMEP verifier.
"""
from __future__ import annotations

import os
import sys
import unittest

from mcp import Client, StdioServerParameters
from mcp.server.mcpserver import MCPServer

from amep_evidence import EXTENSION_ID, RECEIPT_KEY, AmepEvidenceClient, sdk
from gateway import Gateway
from tickets_server import build_server

HERE = os.path.dirname(os.path.abspath(__file__))
UPDATE = dict(action="saas.update", resource="tickets:issue/4821", effect="write_shared")


class EvidenceTest(unittest.IsolatedAsyncioTestCase):
    async def run_update(self, *, buggy=False, wants=True, tamper=False):
        server, key = build_server(buggy=buggy)
        async with Client(server, extensions=[AmepEvidenceClient(wants_receipts=wants)]) as client:
            gw = Gateway(client, sdk.keyset(key))
            if tamper:   # a man-in-the-middle rewrites the receipt after the server signed it
                original = client.call_tool

                async def tampering(*a, **kw):
                    r = await original(*a, **kw)
                    receipt = (r.meta or {}).get(RECEIPT_KEY)
                    if receipt:
                        receipt["executed"]["resource"] = "tickets:issue/9999"
                    return r
                client.call_tool = tampering
            result = await gw.call("update_ticket", {"ticket_id": "4821", "status": "closed"}, **UPDATE)
            return gw, result

    async def test_server_advertises_extension(self):
        server, _ = build_server()
        async with Client(server, extensions=[AmepEvidenceClient()]) as client:
            settings = client.server_capabilities.extensions[EXTENSION_ID]
        self.assertEqual(settings["revision"], "0.2")
        self.assertTrue(settings["effectReceipts"])

    async def test_honest_server_is_preserved(self):
        gw, result = await self.run_update()
        self.assertEqual(result.content[0].text, "ticket 4821 is now closed")   # result content unchanged
        self.assertEqual(len(gw.receipts), 1)
        v, _ = gw.evaluate()
        self.assertEqual((v.outcome, v.invariant), ("preserved", "-"))

    async def test_receipt_exposes_a_server_that_did_something_else(self):
        gw, _ = await self.run_update(buggy=True)
        v, _ = gw.evaluate()
        self.assertEqual((v.outcome, v.invariant), ("violated", "I2"))

    async def test_no_receipt_without_opt_in(self):
        gw, result = await self.run_update(wants=False)
        self.assertNotIn(RECEIPT_KEY, result.meta or {})
        v, _ = gw.evaluate()   # no independent evidence of the effect: never treated as permission
        self.assertEqual((v.outcome, v.invariant), ("unresolved", "I7"))

    async def test_tampered_receipt_is_rejected(self):
        gw, _ = await self.run_update(tamper=True)
        self.assertEqual((len(gw.receipts), len(gw.rejected)), (0, 1))
        v, _ = gw.evaluate()
        self.assertEqual((v.outcome, v.invariant), ("unresolved", "I7"))

    async def test_no_effect_means_no_receipt(self):
        server, key = build_server()
        async with Client(server, extensions=[AmepEvidenceClient()]) as client:
            result = await client.call_tool("validate_only", {"ticket_id": "4821"},
                                            meta={"io.github.stafordtituss/amep-invocation-id": "i-1"})
        self.assertNotIn(RECEIPT_KEY, result.meta or {})

    async def test_server_without_extension_degrades_gracefully(self):
        plain = MCPServer("plain")

        @plain.tool()
        async def ping() -> str:
            return "pong"
        async with Client(plain, extensions=[AmepEvidenceClient()]) as client:
            self.assertNotIn(EXTENSION_ID, client.server_capabilities.extensions or {})
            result = await client.call_tool("ping", {}, meta={"io.github.stafordtituss/amep-invocation-id": "i-1"})
        self.assertEqual(result.content[0].text, "pong")
        self.assertNotIn(RECEIPT_KEY, result.meta or {})

    async def test_over_stdio_transport(self):
        params = StdioServerParameters(command=sys.executable, args=[os.path.join(HERE, "tickets_server.py")], cwd=HERE)
        async with Client(params, extensions=[AmepEvidenceClient()]) as client:
            self.assertIn(EXTENSION_ID, client.server_capabilities.extensions)
            result = await client.call_tool("update_ticket", {"ticket_id": "4821", "status": "closed"},
                                            meta={"io.github.stafordtituss/amep-invocation-id": "i-1"})
        receipt = result.meta[RECEIPT_KEY]
        self.assertEqual((receipt["invocation"], receipt["executed"]["resource"]), ("i-1", "tickets:issue/4821"))
        self.assertEqual(receipt["proof"]["alg"], "Ed25519")


if __name__ == "__main__":
    unittest.main()
