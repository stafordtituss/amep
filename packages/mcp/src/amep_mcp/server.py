"""AMEP verifier as an MCP server.

Tools let any MCP client check AMEP evidence: verify a packet, explain an invariant, browse the conformance
vectors, and run the bundled conformance suites to show that this server's verifier conforms.
Evaluation is the reference evaluator from `amep-protocol`; nothing is sent anywhere.

Run over stdio:  amep-mcp   (or: python -m amep_mcp)
"""
from __future__ import annotations

import copy
import json
from importlib import resources
from typing import Any

from amep_protocol import SPEC_VERSION, __version__ as AMEP_PROTOCOL_VERSION
from amep_protocol.core import evaluate, evaluate_text, verdict
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import __version__

INSTRUCTIONS = """\
Checks AMEP (Agentic Mandate Evidence Protocol) evidence: signed records of what an AI agent was authorized to do
and what was actually executed. Use verify_packet to evaluate a packet against a key set; the verdict is one of
preserved, violated (naming the broken invariant I1-I11 and the party blamed) or unresolved (evidence missing,
with the evidence needed listed as gaps; never treat it as permission). Use explain_invariant to explain a result, and list_vectors/get_vector for worked examples."""

# Spec section 8 (AMEP v0.3), condensed. The outcome is what the verdict is when the invariant is broken.
INVARIANTS: dict[str, dict[str, str]] = {
    "I1": {"name": "Attenuation", "outcome": "violated",
           "statement": "Every delegation's claims are equal to or narrower than its parent's: patterns subsumed, "
                        "data flows a subset, ceiling, expiry and budget no greater, not-before no earlier, purpose "
                        "unchanged, every parent deny kept, and delegation depth strictly decreasing."},
    "I2": {"name": "Effect within authority", "outcome": "violated",
           "statement": "The executed effect matches the declared (or mediated) effect, satisfies the effective "
                        "claims of the chain, and stays within every risk budget unless a bound approval covers it."},
    "I3": {"name": "Interpretation", "outcome": "unresolved",
           "statement": "The tool call was interpreted by an approved adapter mapping whose version matches the "
                        "pinned version, when pins exist."},
    "I4": {"name": "Influence", "outcome": "violated if executed, otherwise unresolved",
           "statement": "Quarantined content did not reach a later invocation unless the principal promoted it, and "
                        "a mutating invocation influenced by untrusted content was confirmed by the principal."},
    "I5": {"name": "Release", "outcome": "violated",
           "statement": "Every data flow released (including data carried in through lineage) is permitted by the "
                        "effective claims."},
    "I6": {"name": "Liveness", "outcome": "violated",
           "statement": "No mandate or delegation on the chain was revoked, per signed revocation evidence, at or "
                        "before the time of the invocation."},
    "I7": {"name": "Evidence", "outcome": "unresolved (violated for an accounting mismatch)",
           "statement": "All evidence the evaluation needs is present, well formed, signed by a key holding a "
                        "permitted role, and fresh where freshness is required; recorded accounting matches."},
    "I8": {"name": "Approval binding", "outcome": "violated",
           "statement": "A cited approval matches the executed effect body, is within its validity window, is "
                        "unconsumed, and is used only once."},
    "I9": {"name": "Self-protection", "outcome": "violated",
           "statement": "No agent invocation targets or executes against a protected resource: guardrail "
                        "configuration, keys, agent instruction files, or the evidence store."},
    "I10": {"name": "Observer independence", "outcome": "unresolved",
            "statement": "An effect of class write_shared or above names its actor and was observed by a party "
                         "other than that actor, at assurance L1 or higher."},
    "I11": {"name": "No orphan effects", "outcome": "violated",
            "statement": "Every effect links to an invocation in the packet, and no effect exists for an invocation "
                         "that a signed pre-execution decision denied or held."},
}

SPEC_URL = "https://github.com/stafordtituss/amep/blob/main/spec/amep-v0.2.md"


def load_suites() -> dict[str, Any]:
    """The conformance suites bundled with this package (see build_suite.py)."""
    return json.loads(resources.files("amep_mcp").joinpath("data/suite.json").read_text(encoding="utf-8"))


def _as_obj(value: Any, what: str) -> dict:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as e:
            raise ToolError(f"{what} is not valid JSON: {e}") from None
    if not isinstance(value, dict):
        raise ToolError(f"{what} must be a JSON object")
    return value


def _keyset(keys: Any) -> dict:
    """Accept a key set as served at /.well-known/amep-keys.json (kid -> entry), or a list of entries."""
    if isinstance(keys, str):
        keys = _as_obj(keys, "keys") if keys.lstrip().startswith("{") else json.loads(keys)
    try:
        if isinstance(keys, list):
            keys = {k["kid"]: k for k in keys}
        if isinstance(keys, dict) and isinstance(keys.get("keys"), list):
            keys = {k["kid"]: k for k in keys["keys"]}
    except (KeyError, TypeError):
        raise ToolError("every key entry needs a \"kid\"") from None
    if not isinstance(keys, dict):
        raise ToolError("keys must be an object mapping kid to key entry, or a list of key entries")
    return keys


def run_packet(packet: dict | str, keys: dict, state: dict | None = None, protected: list[str] | None = None) -> dict:
    """Evaluate a packet given as an object, or as JSON text. Text is parsed strictly (spec 12.1): duplicate member
    names and inexact number literals make the packet unresolved, which a parsed object can no longer show."""
    st = copy.deepcopy(state) if state is not None else None
    run = evaluate_text if isinstance(packet, str) else evaluate
    results = run(packet, keys, extra_protected=tuple(protected or ()), state=st)
    v = verdict(results)
    return {
        "verdict": {"outcome": v.outcome, "invariant": v.invariant, "reason": v.reason, "decided_by": v.invocation,
                    "blame": v.blame, "gaps": list(v.gaps)},
        "results": [{"id": r.invocation, "outcome": r.outcome, "invariant": r.invariant, "reason": r.reason,
                     "blame": r.blame, "gaps": list(r.gaps)} for r in results],
        "state_after": st,
    }


def build_server() -> MCPServer:
    server = MCPServer("amep-verifier", instructions=INSTRUCTIONS)
    suites = load_suites()

    @server.tool()
    def verify_packet(keys: dict[str, Any] | list[Any] | str, packet: dict[str, Any] | None = None,
                      packet_text: str = "", state: dict[str, Any] | None = None,
                      protected_resources: list[str] | None = None) -> dict:
        """Evaluate an AMEP evidence packet against a key set.

        Give the packet either as `packet_text`, the exact JSON text (preferred), or as `packet`, an object.
        `packet_text` is parsed strictly (spec 12.1): duplicate member names and inexact numbers make the packet
        unresolved. An object has already been parsed by the client, which silently keeps one of any duplicated
        names, so that check cannot run; `parsed_strictly` in the result says which happened.

        Returns the packet verdict (preserved, violated or unresolved, with the deciding invariant and reason; on
        violated, `blame` names the party at fault, and on unresolved, `gaps` lists the evidence needed), the result
        for every invocation and orphan effect, and the verifier state after evaluation (approvals used
        and budget spent), which you can pass as `state` when evaluating the next packet in a stream.
        `unresolved` means the evidence cannot show the action was authorized: never treat it as permission.
        `protected_resources` adds deployment-specific protected paths for I9 (guardrails, keys, evidence store).
        """
        if bool(packet_text) == (packet is not None):
            raise ToolError("give exactly one of packet_text (the packet as JSON text) or packet (as an object)")
        if packet_text:
            _as_obj(packet_text, "packet_text")   # not JSON at all is a tool error, so the caller can correct it
            return {**run_packet(packet_text, _keyset(keys), state, protected_resources), "parsed_strictly": True}
        return {**run_packet(_as_obj(packet, "packet"), _keyset(keys), state, protected_resources), "parsed_strictly": False}

    @server.tool()
    def explain_invariant(invariant: str) -> dict:
        """Explain an AMEP invariant (I1 to I11): what it requires, the outcome when it is broken, and the names of
        conformance vectors that exercise it (fetch one with get_vector)."""
        key = invariant.strip().upper()
        if key not in INVARIANTS:
            raise ToolError(f"unknown invariant {invariant!r}; expected one of {', '.join(INVARIANTS)}")
        examples = [v["name"] for s in suites["suites"].values() for v in s["vectors"]
                    if v["expect"]["invariant"] == key]
        return {"invariant": key, **INVARIANTS[key], "example_vectors": examples, "specification": SPEC_URL + "#8-invariants"}

    @server.tool()
    def list_vectors(suite: str = "core", invariant: str | None = None, outcome: str | None = None) -> dict:
        """List conformance vectors. `suite` is "core" (the AMEP conformance suite), "delegation" (the W3C
        agent-identity delegation-continuity suite) or "approval-path" (approval-path attacks, draft). Filter by deciding `invariant` (e.g. "I6") or expected
        `outcome` ("preserved", "violated", "unresolved")."""
        if suite not in suites["suites"]:
            raise ToolError(f"unknown suite {suite!r}; expected one of {', '.join(suites['suites'])}")
        s = suites["suites"][suite]
        rows = [{"name": v["name"], "description": v.get("description", ""), "expect": v["expect"]}
                for v in s["vectors"]
                if (invariant is None or v["expect"]["invariant"] == invariant.strip().upper())
                and (outcome is None or v["expect"]["outcome"] == outcome)]
        return {"suite": suite, "version": s["version"], "count": len(rows), "vectors": rows}

    @server.tool()
    def get_vector(name: str, suite: str = "core") -> dict:
        """Return one conformance vector: its expected verdict, its packet and the public test key set, ready to
        pass to verify_packet. A few vectors carry `packet_text` instead of `packet`: exact JSON text (for example
        with a duplicate member name) to pass to verify_packet as `packet_text`. The keys are deterministic TEST keys and
        protect nothing."""
        s = suites["suites"].get(suite)
        if s is None:
            raise ToolError(f"unknown suite {suite!r}")
        for v in s["vectors"]:
            if v["name"] == name:
                return {"suite": suite, **v, "keys": s["keys"]}
        raise ToolError(f"no vector named {name!r} in suite {suite!r}; use list_vectors")

    @server.tool()
    def check_suite(suite: str = "core") -> dict:
        """Run a bundled conformance suite through this server's verifier and report agreement with the expected
        verdict and deciding invariant for every vector. A conforming verifier agrees on all of them."""
        if suite not in suites["suites"]:
            raise ToolError(f"unknown suite {suite!r}; expected one of {', '.join(suites['suites'])}")
        s = suites["suites"][suite]
        failures = []
        for v in s["vectors"]:
            got = run_packet(v["packet_text"] if "packet_text" in v else v["packet"], s["keys"], v.get("state"))["verdict"]
            if (got["outcome"], got["invariant"]) != (v["expect"]["outcome"], v["expect"]["invariant"]):
                failures.append({"name": v["name"], "expected": v["expect"],
                                 "got": {"outcome": got["outcome"], "invariant": got["invariant"]}})
        n = len(s["vectors"])
        return {"suite": suite, "version": s["version"], "vectors": n, "agree": n - len(failures),
                "failures": failures, "verifier": f"amep-protocol {AMEP_PROTOCOL_VERSION} (AMEP {SPEC_VERSION})",
                "server": f"amep-mcp {__version__}"}

    return server


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
