"""Prototype of the MCP extension `io.github.stafordtituss/amep-evidence` on the official MCP Python SDK.

Server side: `AmepEvidenceServer` intercepts every `tools/call`. Tools report what they actually executed with
`record_effect(...)`; after the tool returns, the interceptor signs those effects as AMEP ExecutedEffectReceipts and
attaches them to the result's `_meta`, but only when the client asked for receipts and sent an invocation id.

Client side: `AmepEvidenceClient` advertises the extension with `wantsReceipts`.

See proposals/mcp-sep-amep-evidence.md (the SEP) and spec/bindings/mcp.md.
"""
from __future__ import annotations

import contextvars
import os
import sys
import time
from typing import Any

from mcp.client.extension import ClientExtension
from mcp.server.extension import Extension

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "packages", "python", "src"))
from amep_protocol import sdk  # noqa: E402

EXTENSION_ID = "io.github.stafordtituss/amep-evidence"
INVOCATION_ID_KEY = "io.github.stafordtituss/amep-invocation-id"
MANDATE_REF_KEY = "io.github.stafordtituss/amep-mandate-ref"
RECEIPT_KEY = "io.github.stafordtituss/amep-effect-receipt"
REVISION = "0.2"

# Effects recorded by the tool currently running. A list (not a value) so that appends made inside the tool are
# visible to the interceptor whichever context the SDK runs the tool in.
_effects: contextvars.ContextVar[list[dict[str, Any]] | None] = contextvars.ContextVar("amep_effects", default=None)


def record_effect(action: str, resource: str, effect: str, *, released: list[str] | None = None,
                  reversible: bool | None = None) -> None:
    """Called by a tool to report an effect it actually executed (AMEP spec 5.9)."""
    effects = _effects.get()
    if effects is not None:
        effects.append(sdk.effect_body(action, resource, effect, int(time.time()),
                                       released=released or [], reversible=reversible))


def _client_wants_receipts(ctx: Any) -> bool:
    """True when the client advertised the extension with wantsReceipts for this connection or request."""
    settings = None
    connection = getattr(ctx, "connection", None)
    caps = getattr(connection, "client_capabilities", None)
    if caps is not None and caps.extensions:
        settings = caps.extensions.get(EXTENSION_ID)
    meta = getattr(ctx, "meta", None)
    per_request = (_as_dict(meta).get("io.modelcontextprotocol/clientCapabilities") or {}).get("extensions") or {}
    if EXTENSION_ID in per_request:
        settings = per_request[EXTENSION_ID]
    return bool(isinstance(settings, dict) and settings.get("wantsReceipts"))


def _as_dict(meta: Any) -> dict[str, Any]:
    if meta is None:
        return {}
    if isinstance(meta, dict):
        return meta
    if hasattr(meta, "model_dump"):
        return meta.model_dump(by_alias=True, exclude_none=True)
    return dict(meta)


class AmepEvidenceServer(Extension):
    """Server half of the extension: advertises it, and signs receipts for tool calls."""

    identifier = EXTENSION_ID

    def __init__(self, observer_key: sdk.Key, observed_by: str, keys_url: str, *, assurance: str = "L3"):
        self.observer_key, self.observed_by, self.keys_url, self.assurance = observer_key, observed_by, keys_url, assurance
        self._counter = 0

    def settings(self) -> dict[str, Any]:
        return {"revision": REVISION, "effectReceipts": True, "keys": self.keys_url}

    async def intercept_tool_call(self, params, ctx, call_next):
        request_meta = _as_dict(getattr(params, "meta", None)) or _as_dict(getattr(ctx, "meta", None))
        invocation_id = request_meta.get(INVOCATION_ID_KEY)
        recorded: list[dict[str, Any]] = []
        token = _effects.set(recorded)
        try:
            result = await call_next(ctx)
        finally:
            _effects.reset(token)
        # Spec: receipts only when the client asked for them and sent an invocation id; never for no effect.
        if not (invocation_id and recorded and _client_wants_receipts(ctx)):
            return result
        receipts = []
        for body in recorded:
            self._counter += 1
            receipts.append(self.observer_key.sign(sdk.effect(
                f"{self.observed_by}:e-{self._counter}", invocation_id, self.observed_by, self.assurance, body)))
        payload = receipts[0] if len(receipts) == 1 else receipts
        return _with_meta(result, RECEIPT_KEY, payload)


def _with_meta(result: Any, key: str, value: Any) -> Any:
    """Return the tool result with `_meta[key] = value`, without changing its content."""
    if isinstance(result, dict):
        meta = dict(result.get("_meta") or {})
        meta[key] = value
        return {**result, "_meta": meta}
    meta = dict(getattr(result, "meta", None) or {})
    meta[key] = value
    return result.model_copy(update={"meta": meta})


class AmepEvidenceClient(ClientExtension):
    """Client half of the extension: advertises it with wantsReceipts."""

    identifier = EXTENSION_ID

    def __init__(self, wants_receipts: bool = True):
        self.wants_receipts = wants_receipts

    def settings(self) -> dict[str, Any]:
        return {"revision": REVISION, "wantsReceipts": self.wants_receipts}
