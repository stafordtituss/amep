"""Prototype MCP gateway: the client half of `io.github.stafordtituss/amep-evidence`.

For each tool call it signs an AMEP Invocation (what the agent declared it would do, under which mandate), sends the
invocation id in the request's `_meta`, verifies any receipt the server returns against the server's published key,
and keeps everything as an AMEP packet that an independent verifier can evaluate.
"""
from __future__ import annotations

import time
from typing import Any

from mcp import Client

from amep_evidence import INVOCATION_ID_KEY, MANDATE_REF_KEY, RECEIPT_KEY, sdk
from amep_protocol import evaluate, verdict, verify_sig


class Gateway:
    def __init__(self, client: Client, server_keys: dict[str, dict], *, principal: str = "user:alice",
                 actor: str = "agent:assistant-1", adapter: str = "mcp:tickets"):
        now = int(time.time())
        self.client, self.actor = client, actor
        self.issuer = sdk.Key.generate("issuer-1", ["issuer", "approver"])
        self.host = sdk.Key.generate("gateway-host-1", ["host"])
        # The key set the verifier uses: this gateway's own keys plus the server's published observer key(s).
        self.keys = {**sdk.keyset(self.issuer, self.host), **server_keys}
        self.mandate = self.issuer.sign(sdk.mandate("m-1", principal, sdk.claims(
            ["saas.*"], ["tickets:issue/*"], "write_shared", exp=now + 3600)))
        self.interpretation = self.host.sign(sdk.interpretation("a-1", adapter, "v1"))
        self.invocations: list[dict[str, Any]] = []
        self.receipts: list[dict[str, Any]] = []
        self.rejected: list[dict[str, Any]] = []   # receipts that failed verification (kept for the record, not as evidence)
        self._n = 0

    async def call(self, tool: str, arguments: dict[str, Any], *, action: str, resource: str, effect: str):
        """Call a tool, declaring the effect the agent intends; return the tool result."""
        self._n += 1
        inv_id = f"i-{self._n}"
        self.invocations.append(self.host.sign(sdk.invocation(
            inv_id, "m-1", "a-1", int(time.time()), action, resource, effect, actor=self.actor)))
        result = await self.client.call_tool(tool, arguments, meta={INVOCATION_ID_KEY: inv_id, MANDATE_REF_KEY: "m-1"})
        raw = (result.meta or {}).get(RECEIPT_KEY)
        for receipt in raw if isinstance(raw, list) else [raw] if raw else []:
            # Client handling rule 1: never trust a receipt that does not verify against the server's keys.
            ok = isinstance(receipt, dict) and receipt.get("invocation") == inv_id and verify_sig(receipt, self.keys)
            (self.receipts if ok else self.rejected).append(receipt)
        return result

    def packet(self) -> dict[str, Any]:
        return sdk.packet(self.mandate, self.interpretation, *self.invocations, *self.receipts)

    def evaluate(self):
        """Evaluate the collected evidence with the AMEP reference verifier. Returns (verdict, results)."""
        results = evaluate(self.packet(), self.keys)
        return verdict(results), results
