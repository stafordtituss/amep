"""Framework-neutral recorder: turns tool calls into signed AMEP evidence.

For each tool call an agent framework makes, the recorder emits
  - an Invocation (signed by the host key): what the agent declared it would do, mapped from the tool name and
    arguments by your `interpret` function;
  - an ExecutedEffectReceipt (signed by the observer key): what the tool reports it actually did, mapped from its
    output by your optional `executed` function (default: the declared effect).
A failed tool call gets no receipt: the effect is unknown, so the invocation evaluates to `unresolved`, never to
`preserved`. Tools you do not map (`interpret` returns None) are not governed and produce no evidence.

The framework adapters (amep_agents.openai_agents, amep_agents.langchain) only call `declare` and `observe`.
"""
from __future__ import annotations

import itertools
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from amep_protocol import sdk
from amep_protocol.core import evaluate, verdict


@dataclass(frozen=True)
class Effect:
    """A canonical action on a canonical resource, with its effect class (spec 5.8, 6.2)."""
    action: str
    resource: str
    effect: str = "read"          # read < write_local < write_shared < external_send < destructive < financial
    released: tuple[str, ...] = ()  # data flows released, e.g. ("confidential->external",)
    reversible: bool | None = None


Interpret = Callable[[str, dict], "Effect | None"]
Executed = Callable[[str, dict, Any], "Effect | None"]


@dataclass
class _Call:
    tool: str
    args: dict
    declared: Effect
    invocation: dict


@dataclass
class EvidenceRecorder:
    """Records AMEP evidence for one agent run (or a session of runs).

    host_key       signs the interpretation and invocations (role "host").
    observer_key   signs effect receipts (role "observer"). Use a key held by the tool runtime or a proxy, not by
                   the agent, so that high-impact effects are independently observed (I10).
    authority_ref  id of the mandate or delegation the agent acts under; include those signed objects in
                   `chain` so the packet is self-contained.
    interpret      maps (tool_name, args) to the Effect the call declares, or None for ungoverned tools.
    executed       maps (tool_name, args, output) to the Effect the tool reports it executed. Default: declared.
    """
    host_key: sdk.Key
    observer_key: sdk.Key
    authority_ref: str
    interpret: Interpret
    executed: Executed | None = None
    chain: Iterable[dict] = ()
    actor: str = "agent:assistant"
    observed_by: str = "hook:tool-runtime"
    adapter: str = "amep-agents"
    adapter_version: str = "0"
    clock: Callable[[], float] = time.time
    _calls: dict[str, _Call] = field(default_factory=dict, init=False, repr=False)
    _invocations: list[dict] = field(default_factory=list, init=False, repr=False)
    _effects: list[dict] = field(default_factory=list, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _seq: Any = field(default_factory=lambda: itertools.count(1), init=False, repr=False)

    def __post_init__(self):
        self.chain = list(self.chain)
        self._interp = self.host_key.sign(sdk.interpretation("a-1", self.adapter, self.adapter_version, source="customer"))

    def _now(self) -> int:
        return int(self.clock())

    def declare(self, call_id: str, tool: str, args: dict) -> dict | None:
        """Record the start of a tool call. Returns the signed invocation, or None if the tool is not governed."""
        eff = self.interpret(tool, args or {})
        if eff is None:
            return None
        with self._lock:
            n = next(self._seq)
            inv = self.host_key.sign(sdk.invocation(
                f"i-{n}", self.authority_ref, self._interp["id"], self._now(), eff.action, eff.resource, eff.effect,
                actor=self.actor))
            self._calls[call_id] = _Call(tool, args or {}, eff, inv)
            self._invocations.append(inv)
        return inv

    def observe(self, call_id: str, output: Any = None, *, error: BaseException | str | None = None) -> dict | None:
        """Record the end of a tool call. Returns the signed receipt, or None (no receipt for failed calls)."""
        with self._lock:
            call = self._calls.pop(call_id, None)
        if call is None or error is not None:
            return None
        eff = self.executed(call.tool, call.args, output) if self.executed else call.declared
        if eff is None:
            return None
        body = sdk.effect_body(eff.action, eff.resource, eff.effect, self._now(), released=list(eff.released),
                               reversible=eff.reversible)
        with self._lock:
            receipt = self.observer_key.sign(sdk.effect(
                "e-" + call.invocation["id"][2:], call.invocation["id"], self.observed_by, "L1", body))
            self._effects.append(receipt)
        return receipt

    def packet(self) -> dict:
        """All evidence so far, as an AMEP packet."""
        with self._lock:
            return sdk.packet(*self.chain, self._interp, *self._invocations, *self._effects)

    def evaluate(self, keys: dict, state: dict | None = None):
        """Evaluate the packet. Returns (packet verdict, per-invocation results)."""
        results = evaluate(self.packet(), keys, state=state)
        return verdict(results), results
