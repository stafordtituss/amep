"""Tests for the AMEP verifier MCP server, over real MCP sessions (in process and over stdio).

Run from the repository root, with the MCP SDK installed:
  PYTHONPATH=packages/python/src:packages/mcp/src python -m unittest discover -s packages/mcp/tests -v
"""
from __future__ import annotations

import json
import os
import sys
import unittest

from mcp import Client, StdioServerParameters

from amep_mcp.server import build_server

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def data(result):
    """The tool's structured result."""
    if getattr(result, "is_error", False) or getattr(result, "isError", False):
        raise AssertionError(f"tool error: {result.content[0].text}")
    sc = getattr(result, "structured_content", None) or getattr(result, "structuredContent", None)
    if sc is None:
        sc = json.loads(result.content[0].text)
    return sc.get("result", sc) if isinstance(sc, dict) and set(sc) == {"result"} else sc


class ServerTest(unittest.IsolatedAsyncioTestCase):
    server = build_server()

    async def raw(self, tool, **args):
        """One in-process MCP session per call (sessions must open and close in the same task)."""
        async with Client(self.server) as client:
            return await client.call_tool(tool, args)

    async def call(self, tool, **args):
        return data(await self.raw(tool, **args))

    async def test_lists_its_tools(self):
        async with Client(self.server) as client:
            tools = {t.name for t in (await client.list_tools()).tools}
        self.assertEqual(tools, {"verify_packet", "explain_invariant", "list_vectors", "get_vector", "check_suite"})

    async def test_core_suite_conforms(self):
        r = await self.call("check_suite", suite="core")
        self.assertEqual((r["vectors"], r["agree"], r["failures"]), (272, 272, []))

    async def test_delegation_suite_conforms(self):
        r = await self.call("check_suite", suite="delegation")
        self.assertEqual((r["vectors"], r["agree"]), (20, 20))

    async def test_approval_path_suite_conforms(self):
        r = await self.call("check_suite", suite="approval-path")
        self.assertEqual((r["vectors"], r["agree"], r["failures"]), (16, 16, []))

    async def test_blame_and_gaps(self):
        v = await self.call("get_vector", name="arguments-rewritten-in-transit")
        r = await self.call("verify_packet", packet=v["packet"], keys=v["keys"])
        self.assertEqual((r["verdict"]["outcome"], r["verdict"]["blame"], r["verdict"]["gaps"]), ("violated", "transport", []))
        v = await self.call("get_vector", name="missing-effect-receipt")
        r = await self.call("verify_packet", packet=v["packet"], keys=v["keys"])
        self.assertIsNone(r["verdict"]["blame"])
        self.assertEqual([g["need"] for g in r["verdict"]["gaps"]], ["receipt"])

    async def test_packet_text_is_parsed_strictly(self):
        v = await self.call("get_vector", name="duplicate-member-name-in-a-signed-effect-body")
        self.assertIn("packet_text", v)
        r = await self.call("verify_packet", packet_text=v["packet_text"], keys=v["keys"])
        self.assertEqual((r["verdict"]["outcome"], r["verdict"]["invariant"]), ("unresolved", "I7"))
        # a duplicated member name, which an object would silently lose, makes packet_text unresolved
        ok = await self.call("get_vector", name="valid-preserved-flow")
        text = json.dumps(ok["packet"])
        dup = text.replace('"invocations": [', '"invocations": [], "invocations": [', 1)
        self.assertNotEqual(dup, text)
        r = await self.call("verify_packet", packet_text=dup, keys=ok["keys"])
        self.assertEqual(r["verdict"]["outcome"], "unresolved")
        r = await self.call("verify_packet", packet_text=text, keys=ok["keys"])
        self.assertEqual(r["verdict"]["outcome"], "preserved")
        # exactly one form of the packet
        r = await self.raw("verify_packet", keys=ok["keys"])
        self.assertTrue(getattr(r, "is_error", None) or getattr(r, "isError", None))
        r = await self.raw("verify_packet", keys=ok["keys"], packet=ok["packet"], packet_text=text)
        self.assertTrue(getattr(r, "is_error", None) or getattr(r, "isError", None))

    async def test_fetch_and_verify_a_vector(self):
        v = await self.call("get_vector", name="revoked-root-with-live-child")
        r = await self.call("verify_packet", packet=v["packet"], keys=v["keys"])
        self.assertEqual((r["verdict"]["outcome"], r["verdict"]["invariant"]), ("violated", "I6"))
        self.assertEqual(r["results"][0]["id"], "i-1")

    async def test_accepts_json_strings_and_key_lists(self):
        v = await self.call("get_vector", name="valid-preserved-flow")
        r = await self.call("verify_packet", packet_text=json.dumps(v["packet"]), keys=list(v["keys"].values()))
        self.assertEqual((r["verdict"]["outcome"], r["parsed_strictly"]), ("preserved", True))
        r = await self.call("verify_packet", packet=v["packet"], keys=json.dumps(v["keys"]))
        self.assertEqual((r["verdict"]["outcome"], r["parsed_strictly"]), ("preserved", False))

    async def test_missing_evidence_is_never_permission(self):
        v = await self.call("get_vector", name="missing-effect-receipt")
        r = await self.call("verify_packet", packet=v["packet"], keys=v["keys"])
        self.assertEqual((r["verdict"]["outcome"], r["verdict"]["invariant"]), ("unresolved", "I7"))

    async def test_state_carries_across_packets(self):
        v = await self.call("get_vector", name="approval-reused-across-packets")
        r = await self.call("verify_packet", packet=v["packet"], keys=v["keys"], state=v["state"])
        self.assertEqual((r["verdict"]["outcome"], r["verdict"]["invariant"]), ("violated", "I8"))

    async def test_deployment_protected_resources(self):
        v = await self.call("get_vector", name="valid-preserved-flow")
        r = await self.call("verify_packet", packet=v["packet"], keys=v["keys"],
                            protected_resources=["repo:app/src/auth.ts"])
        self.assertEqual((r["verdict"]["outcome"], r["verdict"]["invariant"]), ("violated", "I9"))

    async def test_explain_and_filter(self):
        e = await self.call("explain_invariant", invariant="i6")
        self.assertEqual((e["invariant"], e["name"]), ("I6", "Liveness"))
        self.assertIn("revoked-at-the-instant-of-the-action", e["example_vectors"])
        lv = await self.call("list_vectors", invariant="I10")
        self.assertTrue(lv["count"] >= 3 and all(x["expect"]["invariant"] == "I10" for x in lv["vectors"]))

    async def test_bad_input_is_a_tool_error(self):
        r = await self.raw("explain_invariant", invariant="I99")
        self.assertTrue(getattr(r, "is_error", None) or getattr(r, "isError", None))
        self.assertIn("unknown invariant", r.content[0].text)   # the model sees why, so it can correct itself
        r = await self.raw("verify_packet", packet_text="{not json", keys={})
        self.assertTrue(getattr(r, "is_error", None) or getattr(r, "isError", None))


class StdioTest(unittest.IsolatedAsyncioTestCase):
    async def test_over_stdio(self):
        env = {**os.environ, "PYTHONPATH": os.pathsep.join(
            [os.path.join(ROOT, "packages/python/src"), os.path.join(ROOT, "packages/mcp/src")])}
        params = StdioServerParameters(command=sys.executable, args=["-m", "amep_mcp"], env=env)
        async with Client(params) as client:
            r = data(await client.call_tool("check_suite", {"suite": "delegation"}))
        self.assertEqual(r["agree"], 20)


if __name__ == "__main__":
    unittest.main()
