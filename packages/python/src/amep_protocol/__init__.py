"""AMEP: Agentic Mandate Evidence Protocol.

Verify AMEP evidence packets and produce signed AMEP objects.

    from amep_protocol import evaluate, verdict
    results = evaluate(packet, keys)          # one result per invocation (spec 10)
    print(verdict(results).outcome)           # preserved | violated | unresolved

    from amep_protocol import sdk             # keys, signing and object builders
"""
from . import sdk
from .core import (Malformed, Result, approval_digest, canon, digest, evaluate, is_guardrail, to_time,
                   verdict, verify_sig)

__version__ = "0.2.0a6"
SPEC_VERSION = "0.2.0-draft.4"

__all__ = ["Malformed", "Result", "approval_digest", "canon", "digest", "evaluate", "is_guardrail", "sdk",
           "to_time", "verdict", "verify_sig", "__version__", "SPEC_VERSION"]
