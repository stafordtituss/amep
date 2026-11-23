"""AMEP: Agentic Mandate Evidence Protocol.

Verify AMEP evidence packets and produce signed AMEP objects.

    from amep_protocol import evaluate, verdict
    results = evaluate(packet, keys)          # one result per invocation (spec 10)
    print(verdict(results).outcome)           # preserved | violated | unresolved

    from amep_protocol import sdk             # keys, signing and object builders
"""
from . import sdk, verdicts
from .core import (Malformed, Result, approval_digest, canon, digest, evaluate, evaluate_text, is_guardrail,
                   parse_strict, signing_input, to_time, unsafe_number, verdict, verify_sig)

__version__ = "0.3.0a3"
SPEC_VERSION = "0.3.0-draft.1"

__all__ = ["Malformed", "Result", "approval_digest", "canon", "digest", "evaluate", "evaluate_text", "is_guardrail",
           "signing_input",
           "parse_strict", "sdk", "verdicts", "to_time", "unsafe_number", "verdict", "verify_sig", "__version__",
           "SPEC_VERSION"]
