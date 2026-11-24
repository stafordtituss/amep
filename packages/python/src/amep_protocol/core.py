"""AMEP evaluation core: RFC 8785 canonicalization, signature and signer-role checks, the claim algebra,
and the evaluation procedure of the AMEP specification (spec/amep-v0.2.md, section 10).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

CEILING = ["read", "write_local", "write_shared", "external_send", "destructive", "financial"]

# Protected Resource registry, spec 19.7. Deployments add their own guardrail config, keys and evidence
# store via evaluate(..., extra_protected=...) (spec 8.1).
GUARDRAIL_MARKERS = ("/.claude/", "/.codex/", "/.cursor/", "/.gemini/", "/.git/hooks/", "/.ssh/authorized_keys")
GUARDRAIL_NAMES = ("AGENTS.md", "CLAUDE.md", ".mcp.json", ".zshrc", ".bashrc")

# Signer roles, spec 12.5: a key may sign only the object kinds its roles allow.
SIGNER_ROLES = {
    "mandate": {"issuer"}, "revocation": {"issuer"}, "status": {"issuer"},
    "delegation": {"issuer", "host"}, "intent": {"issuer", "host"},
    "interpretation": {"host"}, "invocation": {"host"}, "decision": {"host"},
    "effect": {"observer"}, "approval": {"approver"}, "finding": {"host", "observer"},
    "call_statement": {"observer"},
}
DISPOSITIONS = ("completed", "not_executed", "failed_after_effects")

COST_BASE = {"read": 0, "write_local": 1, "write_shared": 3, "external_send": 5, "destructive": 10, "financial": 20}
DATA_MULT = {"public": 1, "internal": 1, "source": 1, "confidential": 2, "secret": 5, "phi": 5, "pci": 5}


class Malformed(ValueError):
    """The packet violates the data model; the affected invocation is unresolved (I7)."""


def is_guardrail(resource: str, extra=()) -> bool:
    """Resources are canonical; still match markers anywhere so ~/, $HOME and absolute forms are all caught."""
    r = "/" + resource.replace("~", "home", 1).lstrip("/")
    return any(m in r for m in (*GUARDRAIL_MARKERS, *extra)) or r.rsplit("/", 1)[-1] in GUARDRAIL_NAMES


# ---------------- time (spec 5.1.1) ----------------
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$")


def to_time(v) -> float:
    if isinstance(v, bool):
        raise Malformed("time must be a number or an RFC 3339 string")
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, str) and RFC3339.match(v):
        return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
    raise Malformed(f"malformed time {v!r}")


# ---------------- RFC 8785 canonical form (spec 12.1) ----------------
# I-JSON (RFC 7493): numbers beyond +/-(2^53 - 1) are not interoperable. Python keeps such integers exact while
# ECMAScript rounds them to a double, so two verifiers would canonicalize the same packet differently. Spec 12.1
# makes them malformed everywhere: canon() refuses to serialize them and evaluate() returns unresolved (I7).
MAX_SAFE_INT = 2 ** 53 - 1


def _jcs_number(v, strict: bool = True) -> str:
    if strict and abs(v) > MAX_SAFE_INT:
        raise Malformed(f"number {v!r} is outside the I-JSON range (|n| > 2^53-1)")
    if isinstance(v, int):
        return str(v)
    if v != v or v in (float("inf"), float("-inf")):
        raise Malformed("NaN and Infinity are not allowed")
    if v == 0:
        return "0"
    sign, r = ("-", repr(-v)) if v < 0 else ("", repr(v))   # repr = shortest round-trip digits, like ECMAScript
    mant, _, e = r.partition("e")
    ip, _, fp = mant.partition(".")
    digits, exp10 = (ip + fp).lstrip("0"), int(e or 0) - len(fp)
    while digits.endswith("0"):
        digits, exp10 = digits[:-1], exp10 + 1
    k, n = len(digits), len(digits) + exp10                  # value = 0.digits x 10^n
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        x = n - 1
        out = (digits if k == 1 else digits[0] + "." + digits[1:]) + "e" + ("+" if x >= 0 else "-") + str(abs(x))
    return sign + out


def _jcs(v, strict: bool = True) -> str:
    if v is None or isinstance(v, bool):
        return json.dumps(v)
    if isinstance(v, (int, float)):
        return _jcs_number(v, strict)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(_jcs(x, strict) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda s: s.encode("utf-16-be"))  # UTF-16 code-unit order
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _jcs(v[k], strict) for k in keys) + "}"
    raise Malformed(f"not JSON: {type(v).__name__}")


def canon(obj, strict: bool = True) -> bytes:
    """RFC 8785 form. strict=False skips the I-JSON range check; only test-vector generators should use it."""
    return _jcs(obj, strict).encode("utf-8")


def unsafe_number(v, path: str = "$"):
    """Path of the first number outside the I-JSON range (|n| > 2^53-1), or None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return path if abs(v) > MAX_SAFE_INT else None
    if isinstance(v, list):
        return next((p for i, x in enumerate(v) if (p := unsafe_number(x, f"{path}[{i}]"))), None)
    if isinstance(v, dict):
        return next((p for k, x in v.items() if (p := unsafe_number(x, f"{path}.{k}"))), None)
    return None


def _strict_float(s: str) -> float:
    f = float(s)
    if f != f or f in (float("inf"), float("-inf")) or Decimal(repr(f)) != Decimal(s):
        raise Malformed(f"number literal {s} is not exactly representable as an IEEE 754 double")
    return f


def _reject_constant(s: str):
    raise Malformed(f"{s} is not JSON")


def _unique_members(pairs):
    """I-JSON (RFC 7493 2.3): member names MUST be unique. Parsers disagree on duplicates (first wins, last wins,
    error), so a packet with `"amount":"10.00", "amount":"840000.00"` could verify as one value and be displayed as
    another. Spec 12.1 makes such text malformed."""
    out = {}
    for k, v in pairs:
        if k in out:
            raise Malformed(f"duplicate member name {k!r}")
        out[k] = v
    return out


def parse_strict(text: str):
    """Parse JSON text for evaluation (spec 12.1). A non-integer number literal must equal, as a decimal, the
    double it denotes, so two distinct literals can never share one canonical form or approval digest.
    Duplicate member names are rejected. Integers are kept exact and checked against the I-JSON range by evaluate()."""
    return json.loads(text, parse_float=_strict_float, parse_constant=_reject_constant, object_pairs_hook=_unique_members)


# ---------------- well-formedness (spec 12.1, v0.3) ----------------
# Bounds keep a hostile packet from exhausting a verifier; every verifier applies the same ones, so a packet is
# either malformed everywhere or nowhere. String sizes are counted in UTF-8 bytes, which all languages agree on.
MAX_DEPTH, MAX_ARRAY, MAX_STRING, MAX_NAME = 32, 4096, 8192, 256
_IDENT_FIELDS = ("action", "resource")


def _bad_char(s: str):
    for ch in s:
        c = ord(ch)
        if 0xD800 <= c <= 0xDFFF:
            return "a lone surrogate"
        if 0xFDD0 <= c <= 0xFDEF or (c & 0xFFFE) == 0xFFFE:
            return "a noncharacter"
    return None


def _ident_problem(s) -> str | None:
    """Canonical identifiers (spec 6.2, v0.3): already in NFC, and no control characters, so two identifiers that
    look the same always compare the same. The verifier never normalizes silently."""
    if not isinstance(s, str):
        return None
    if any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in s):
        return "a control character"
    if unicodedata.normalize("NFC", s) != s:
        return "a form that is not NFC"
    return None


def malformed_reason(v, path: str = "$", depth: int = 0):
    """Reason the packet is not well-formed I-JSON within AMEP's bounds, or None."""
    if depth > MAX_DEPTH:
        return f"nesting deeper than {MAX_DEPTH} at {path}"
    if isinstance(v, str):
        if len(v.encode("utf-8", "surrogatepass")) > MAX_STRING:
            return f"string longer than {MAX_STRING} bytes at {path}"
        bad = _bad_char(v)
        return f"{bad} at {path}" if bad else None
    if isinstance(v, list):
        if len(v) > MAX_ARRAY:
            return f"array longer than {MAX_ARRAY} at {path}"
        return next((r for i, x in enumerate(v) if (r := malformed_reason(x, f"{path}[{i}]", depth + 1))), None)
    if isinstance(v, dict):
        for k, x in v.items():
            if len(k.encode("utf-8", "surrogatepass")) > MAX_NAME:
                return f"member name longer than {MAX_NAME} bytes at {path}"
            bad = _bad_char(k)
            if bad:
                return f"{bad} in a member name at {path}"
            if k in _IDENT_FIELDS and (p := _ident_problem(x)):
                return f"identifier with {p} at {path}.{k}"
            if k in ("actions", "resources", "deny_actions", "deny_resources") and isinstance(x, list):
                if (p := next((q for q in map(_ident_problem, x) if q), None)):
                    return f"identifier pattern with {p} at {path}.{k}"
            r = malformed_reason(x, f"{path}.{k}", depth + 1)
            if r:
                return r
    return None


def digest(obj) -> str:
    return hashlib.sha256(canon(obj)).hexdigest()


def effect_identity(x: dict) -> dict:
    """The executed-effect body without what only the observer knows at execution: its time `t`, and the observer's
    own running totals `value.period_spent` (spec 5.10, 7.6). Approvals bind this, so they can be issued in advance."""
    out = {k: v for k, v in x.items() if k != "t"}
    if isinstance(out.get("value"), dict) and "period_spent" in out["value"]:
        out["value"] = {k: v for k, v in out["value"].items() if k != "period_spent"}
    return out


def approval_digest(x: dict) -> str:
    """Spec 5.10: approvals bind the executed-effect body without its time (and without observer totals)."""
    return digest(effect_identity(x))


# ---------------- signatures (spec 12.2) ----------------
# One exact Ed25519 acceptance rule (v0.3), applied before the library check, because libraries disagree on edge
# cases (Chalkias et al., "Taming the many EdDSAs", 2020). Measured: with OpenSSL 3.6 the identity public key
# accepts the signature (R = identity, S = 0) for EVERY message, while OpenSSL 4.1 rejects it, so two verifiers
# disagreed on the same packet. AMEP rejects:
#   - S >= L (malleable signatures);
#   - a public key A or commitment R whose encoding is non-canonical (y >= p) or a point of small order.
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_SMALL_ORDER_Y = frozenset({0, 1, _P - 1} | {int.from_bytes(bytes.fromhex(h), "little") for h in (
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")})


def _point_ok(b: bytes) -> bool:
    if len(b) != 32:
        return False
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    return y < _P and y not in _SMALL_ORDER_Y


def ed25519_strict_ok(pub: bytes, sig: bytes) -> bool:
    """The encoding checks of spec 12.2 (v0.3): canonical, non-small-order A and R, and S < L."""
    return len(sig) == 64 and _point_ok(pub) and _point_ok(sig[:32]) and int.from_bytes(sig[32:], "little") < _L


SIG_CONTEXT = b"AMEP-v0.3"
HEX64, HEX128 = re.compile(r"^[0-9a-f]{64}$"), re.compile(r"^[0-9a-f]{128}$")


def signing_input(obj: dict) -> bytes:
    """Spec 12.2. A version-2 proof signs a domain-separated input, so a signature made by the same key for
    another object kind, or for another system entirely, can never be presented as this AMEP object:
        "AMEP-v0.3" 0x00 kind 0x00 canon(object without proof)
    A proof without "v" (version 1, AMEP v0.2) signs canon(object without proof), exactly as before."""
    body = canon({k: v for k, v in obj.items() if k != "proof"})
    pv = (obj.get("proof") or {}).get("v")
    if pv == 2 and not isinstance(pv, bool):
        return SIG_CONTEXT + b"\x00" + str(obj.get("kind", "")).encode("utf-8") + b"\x00" + body
    return body


def verify_sig(obj, keys: dict, require_v2: bool = False) -> bool:
    if not isinstance(obj, dict):
        return False
    proof = obj.get("proof") or {}
    k = keys.get(proof.get("kid"))
    if not k or proof.get("alg") != "Ed25519" or k.get("alg") != "Ed25519":
        return False
    pv = proof.get("v", 1)
    if isinstance(pv, bool) or pv not in (1, 2) or (require_v2 and pv != 2):
        return False  # AMEP v0.3 packets must use domain-separated proofs (spec 16)
    if not isinstance(k.get("x"), str) or not HEX64.match(k["x"]) or not isinstance(proof.get("sig"), str) or not HEX128.match(proof["sig"]):
        return False  # spec 12.2: lowercase hex of exactly 32 and 64 bytes; no whitespace or other forms
    if not set(k.get("roles", [])) & SIGNER_ROLES.get(obj.get("kind"), set()):
        return False  # valid key, wrong role: e.g. a host key minting a mandate or approving its own action
    try:
        pub, sig = bytes.fromhex(k["x"]), bytes.fromhex(proof["sig"])
        if not ed25519_strict_ok(pub, sig):
            return False
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, signing_input(obj))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError, Malformed):
        return False


def sig_cause(obj, keys: dict) -> str:
    """Why a required signature was not accepted (spec 10.5.1, v0.3): for a signature gap's `cause`. Called only
    after verify_sig has refused the object; the order is fixed so that every verifier gives the same cause."""
    if not isinstance(obj, dict) or not isinstance(obj.get("proof"), dict):
        return "missing"
    kid = obj["proof"].get("kid")
    k = keys.get(kid) if isinstance(kid, str) else None
    if not isinstance(k, dict):
        return "unknown_key"
    roles = k.get("roles") if isinstance(k.get("roles"), list) else []
    if not set(r for r in roles if isinstance(r, str)) & SIGNER_ROLES.get(obj.get("kind"), set()):
        return "role"
    return "invalid"


# ---------------- claim algebra (spec 6.3, 7) ----------------
def pat_match(value: str, pattern: str) -> bool:
    return pattern == "*" or value == pattern or (pattern.endswith("*") and value.startswith(pattern[:-1]))


def subsumed(child_pats, parent_pats) -> bool:
    return all(any(p == "*" or c == p or (p.endswith("*") and c.rstrip("*").startswith(p[:-1])) for p in parent_pats)
               for c in child_pats)


# grants (spec 5.3, v0.3): authority as a union of (actions x resources) products instead of one product. Plain
# actions and resources are one grant. Used only in v0.3 packets; elsewhere the original single-product rules apply.
def _uses_grants(c: dict, v03: bool) -> bool:
    return v03 and "grants" in c


def grants_of(c: dict, v03: bool) -> list:
    return c["grants"] if _uses_grants(c, v03) else [{"actions": c["actions"], "resources": c["resources"]}]


def narrower(child: dict, parent: dict, v03: bool = False) -> tuple[bool, str]:
    if _uses_grants(child, v03) or _uses_grants(parent, v03):
        # every child grant must lie within one parent grant (sound: it never accepts a widening)
        pg = grants_of(parent, v03)
        if not all(any(subsumed(g["actions"], G["actions"]) and subsumed(g["resources"], G["resources"]) for G in pg)
                   for g in grants_of(child, v03)):
            return False, "grants widened"
    else:
        if not subsumed(child["actions"], parent["actions"]): return False, "actions widened"
        if not subsumed(child["resources"], parent["resources"]): return False, "resources widened"
    if not set(child.get("data", [])) <= set(parent.get("data", [])): return False, "data classes widened"
    if CEILING.index(child["ceiling"]) > CEILING.index(parent["ceiling"]): return False, "effect ceiling raised"
    if to_time(child["exp"]) > to_time(parent["exp"]): return False, "validity extended"
    if "nbf" in parent and ("nbf" not in child or to_time(child["nbf"]) < to_time(parent["nbf"])):
        return False, "validity extended (nbf)"
    if "purpose" in parent and child.get("purpose") != parent["purpose"]: return False, "purpose changed"
    # spec 7.1: denies only grow. Every parent deny must be covered by an equal-or-broader child deny.
    for key in ("deny_actions", "deny_resources"):
        if not all(subsumed([p], child.get(key, [])) for p in parent.get(key, [])):
            return False, f"{key} removed"
    if "budget" in parent and child.get("budget", parent["budget"]) > parent["budget"]: return False, "risk budget widened"
    # spec 7.2: absent depth on the parent = unbounded; depth 0 = no further delegation;
    # otherwise the child MUST carry a strictly smaller depth
    if "depth" in parent:
        if parent["depth"] == 0: return False, "parent may not be delegated (depth 0)"
        if "depth" not in child: return False, "delegation depth missing under a bounded parent"
        if child["depth"] >= parent["depth"]: return False, "delegation depth not decreasing"
    return True, ""


def meet(a: dict, b: dict, v03: bool = False) -> dict:
    if _uses_grants(a, v03) or _uses_grants(b, v03):
        pairs = [{"actions": [x for x in g["actions"] if subsumed([x], G["actions"])],
                  "resources": [x for x in g["resources"] if subsumed([x], G["resources"])]}
                 for g in grants_of(a, v03) for G in grants_of(b, v03)]
        m = {"grants": [p for p in pairs if p["actions"] and p["resources"]]}
    else:
        m = {"actions": [x for x in a["actions"] if subsumed([x], b["actions"])],
             "resources": [x for x in a["resources"] if subsumed([x], b["resources"])]}
    m |= {"data": sorted(set(a.get("data", [])) & set(b.get("data", []))),
         "ceiling": CEILING[min(CEILING.index(a["ceiling"]), CEILING.index(b["ceiling"]))],
         "exp": min(to_time(a["exp"]), to_time(b["exp"]))}
    nbfs = [to_time(c["nbf"]) for c in (a, b) if "nbf" in c]
    if nbfs: m["nbf"] = max(nbfs)
    if "purpose" in a or "purpose" in b: m["purpose"] = a.get("purpose", b.get("purpose"))
    for key in ("deny_actions", "deny_resources"):   # denies are unioned: no hop or intent can lift one
        if key in a or key in b: m[key] = sorted(set(a.get(key, [])) | set(b.get(key, [])))
    return m


def effect_ok(x: dict, c: dict, v03: bool = False) -> tuple[bool, str]:
    gs = grants_of(c, v03)
    act = [g for g in gs if any(pat_match(x["action"], p) for p in g["actions"])]
    if not act: return False, "action outside claims"
    if any(pat_match(x["action"], p) for p in c.get("deny_actions", [])): return False, "action denied"
    # with grants, the action and the resource must fall within the same grant
    if not any(any(pat_match(x["resource"], p) for p in g["resources"]) for g in act): return False, "resource outside claims"
    if any(pat_match(x["resource"], p) for p in c.get("deny_resources", [])): return False, "resource denied"
    if CEILING.index(x["effect"]) > CEILING.index(c["ceiling"]): return False, "effect above ceiling"
    for d in x.get("released", []):
        if d not in c.get("data", []): return False, f"released {d} not allowed"
    if to_time(x["t"]) > to_time(c["exp"]): return False, "after validity"
    if "nbf" in c and to_time(x["t"]) < to_time(c["nbf"]): return False, "before validity"
    return True, ""


def cost(x: dict) -> int:
    mult = max([DATA_MULT.get(d.split("->")[0], 1) for d in x.get("released", [])] or [1])
    rev = 1 if x["effect"] == "read" or (x.get("reversible") and x["effect"] != "external_send") else 3
    return COST_BASE[x["effect"]] * mult * rev


# ---------------- quantities and limits (spec 5.9, 7.6, v0.3) ----------------
# An executed effect may carry value = {amount, unit}: an exact decimal string and a unit such as "iso4217:EUR",
# a CAIP-19 asset id, "count:records" or "bytes". Claims may carry limits that cap it per call and per period.
# Amounts are compared as exact decimals (scaled integers), never as floats. Points (spec 9) still apply too.
AMOUNT = re.compile(r"^(0|[1-9][0-9]{0,38})(\.[0-9]{1,18})?$")
UNIT = re.compile(r"^[a-z][a-z0-9-]{0,31}:[!-~]{1,128}$")
_SCALE = 10 ** 18
MONEY_UNITS = ("iso4217:", "caip19:")
CLAIM_MEMBERS = {"actions", "resources", "grants", "data", "ceiling", "exp", "nbf", "purpose", "deny_actions", "deny_resources",
                 "depth", "budget", "limits"}
LIMIT_MEMBERS = {"unit", "per_effect", "per_call", "per_period", "period", "actions", "counted_by"}
INTEGER_AMOUNT = re.compile(r"^(0|[1-9][0-9]{0,38})$")
PERIOD_KEY = re.compile(r"^[1-9][0-9]{0,15}$")


def amount_units(s, unit: str | None = None) -> int:
    """'1200.50' -> 1200500000000000000000 (units of 10^-18). Rejects signs, exponents, leading zeros, > 18 decimals.
    Amounts in caip19: units are integers in the asset's smallest unit, as the chain records them (spec 5.9.2)."""
    if unit is not None and unit.startswith("caip19:") and not (isinstance(s, str) and INTEGER_AMOUNT.match(s)):
        raise Malformed(f"amount {s!r} in {unit} must be an integer in the asset's smallest unit")
    if not isinstance(s, str) or not AMOUNT.match(s):
        raise Malformed(f"malformed amount {s!r} (a decimal string such as \"1200.00\" is required)")
    if unit is not None and unit.startswith("caip19:") and not INTEGER_AMOUNT.match(s):
        raise Malformed(f"amount {s!r} in {unit} must be an integer in the asset's smallest unit")
    ip, _, fp = s.partition(".")
    return int(ip) * _SCALE + int((fp + "0" * 18)[:18])


def period_spent_of(v: dict, unit: str) -> dict:
    """value.period_spent: the observer's own totals, keyed by period length in seconds (spec 5.9.2). Each is
    {"from": <window start>, "total": <amount>}, or a bare amount, which names no window and so never counts as a limit's
    total (amep#10). Returns {period: (window start or None, amount)}."""
    ps = v.get("period_spent", {})
    if not isinstance(ps, dict) or not all(isinstance(k, str) and PERIOD_KEY.match(k) for k in ps):
        raise Malformed("period_spent must map period lengths in seconds to totals, for example {\"2592000\": {\"from\": 0, \"total\": \"300.00\"}}")
    out = {}
    for k, a in ps.items():
        if isinstance(a, dict):
            if set(a) != {"from", "total"}:
                raise Malformed("a period_spent total must be {from, total}")
            out[k] = (to_time(a["from"]), amount_units(a["total"], unit))
        else:
            out[k] = (None, amount_units(a, unit))
    return out


def _unit(u) -> str:
    if not isinstance(u, str) or not UNIT.match(u):
        raise Malformed(f"malformed unit {u!r}")
    return u


def is_extension_member(name: str) -> bool:
    """Spec 16: extension members start with x- or are reverse-DNS names. They never change an outcome."""
    return name.startswith("x-") or "." in name


def check_limits(lims) -> list:
    if not isinstance(lims, list) or not lims:
        raise Malformed("limits must be a non-empty array")
    for lim in lims:
        if not isinstance(lim, dict):
            raise Malformed("limit must be an object")
        unit = _unit(lim.get("unit"))
        for k in ("per_effect", "per_call"):
            if k in lim:
                amount_units(lim[k], unit)
        if ("per_period" in lim) != ("period" in lim):
            raise Malformed("per_period and period go together")
        if "counted_by" in lim and not (isinstance(lim["counted_by"], str) and lim["counted_by"]):
            raise Malformed("counted_by must name an observer")
        if "per_period" in lim:
            amount_units(lim["per_period"], unit)
            if isinstance(lim["period"], bool) or not isinstance(lim["period"], (int, float)) or lim["period"] != int(lim["period"]) or lim["period"] <= 0:
                raise Malformed("period must be a positive integer number of seconds")
        if "actions" in lim and not (isinstance(lim["actions"], list) and all(isinstance(p, str) for p in lim["actions"])):
            raise Malformed("limit actions must be an array of action patterns")
    return lims


def period_key(n: dict, lim: dict, unit: str, t) -> str:
    """The running-total key of one limit window (spec 7.6): one total per limit, so limits that differ only in their
    actions are separate caps (amep#10)."""
    anchor = to_time(n["claims"]["nbf"]) if "nbf" in n["claims"] else 0
    window = int((to_time(t) - anchor) // lim["period"])
    return f"{n['id']}|{unit}|{lim['period']}|{window}" + (f"|{','.join(sorted(lim['actions']))}" if "actions" in lim else "")


def window_start(n: dict, lim: dict, t) -> float:
    """Start time of the limit window that contains t (spec 7.6): windows of `period` seconds from the node's nbf, or 0."""
    anchor = to_time(n["claims"]["nbf"]) if "nbf" in n["claims"] else 0
    return anchor + int((to_time(t) - anchor) // lim["period"]) * lim["period"]


def check_reserve(r) -> dict:
    """An invocation's reserve (spec 5.8, v0.3): {amount, unit}, the most the call can move in the unit."""
    if not isinstance(r, dict) or set(r) != {"amount", "unit"}:
        raise Malformed("reserve must be an object with exactly amount and unit")
    amount_units(r["amount"], _unit(r["unit"]))
    return r


def held_of(state: dict) -> dict:
    """Verifier state's holds (spec 10.7, v0.3): invocation digest -> {invocation, amounts: {period key: amount | None}}."""
    h = state.get("held", {})
    if not isinstance(h, dict) or not all(
            isinstance(v, dict) and isinstance(v.get("invocation"), str) and isinstance(v.get("amounts"), dict)
            and all(a is None or (isinstance(a, str) and AMOUNT.match(a)) for a in v["amounts"].values()) for v in h.values()):
        raise Malformed("state.held must map invocation digests to {invocation, amounts}")
    return h


def approvals_held_of(state: dict) -> dict:
    """Verifier state's approval holds (spec 5.10, held approvals, v0.3): approval id -> {invocation, digest} of the earlier
    invocation that cited it and whose outcome is still unknown."""
    h = state.get("approvals_held", {})
    if not isinstance(h, dict) or not all(
            isinstance(k, str) and isinstance(v, dict) and set(v) == {"invocation", "digest"}
            and isinstance(v["invocation"], str) and isinstance(v["digest"], str) and HEX64.match(v["digest"])
            for k, v in h.items()):
        raise Malformed("state.approvals_held must map approval ids to {invocation, digest}")
    return h


def limit_applies(lim: dict, x: dict) -> bool:
    """A limit with `actions` applies to effects whose action matches; without, to every financial effect."""
    if "actions" in lim:
        return any(pat_match(x["action"], p) for p in lim["actions"])
    return x["effect"] == "financial"


def limits_narrower(child: dict, parent: dict):
    """I1 for limits: a child may add limits, but never raise one the parent sets for the same unit and period."""
    for pl in parent.get("limits", []):
        for cl in child.get("limits", []):
            if cl["unit"] != pl["unit"] or cl.get("actions") != pl.get("actions"):
                continue
            for k in ("per_effect", "per_call"):
                if k in pl and k in cl and amount_units(cl[k]) > amount_units(pl[k]):
                    return f"{k.replace('_', '-')} limit raised for {pl['unit']}"
            if "per_period" in pl and cl.get("period") == pl["period"] and "per_period" in cl and \
                    amount_units(cl["per_period"]) > amount_units(pl["per_period"]):
                return f"per-period limit raised for {pl['unit']}"
    return None


# ---------------- evaluation (spec 10) ----------------
@dataclass
class Result:
    invocation: str
    outcome: str
    invariant: str
    reason: str
    blame: str | None = None                    # violated: agent, host, delegator, transport or server (spec 10.5)
    gaps: list = field(default_factory=list)    # unresolved: [{"need": ..., "ref": ...}]


class Stop(Exception):
    def __init__(self, outcome, invariant, reason, blame=None, need=None, ref=None, cause=None):
        # spec 10.5 (v0.3): a violation names the party whose own signed record departs from authority; an
        # unresolved result names the one piece of evidence that would let the evaluation continue
        self.r = (outcome, invariant, reason, blame if outcome == "violated" else None,
                  [dict({"need": need, "ref": str(ref)}, **({"cause": cause} if cause else {}))]
                  if outcome == "unresolved" and need else [])


def _check(cond, outcome, invariant, reason, blame=None, need=None, ref=None, cause=None):
    if cond:
        raise Stop(outcome, invariant, reason, blame, need, ref, cause)


SUPPORTED_VERSIONS = (None, "0.2", "0.3")


def _all_unresolved(packet, reason):
    ids = [i.get("id", "?") if isinstance(i, dict) else "?" for i in packet.get("invocations", [])] or ["-"]
    return [Result(i, "unresolved", "I7", reason, gaps=[{"need": "well_formed_packet", "ref": "-"}]) for i in ids]


def evaluate(packet: dict, keys: dict, extra_protected=(), state: dict | None = None) -> list[Result]:
    """state (spec 10.6): carries approval use, risk-budget spending and per-period limit totals across packets.
    Read on entry, updated on exit."""
    if not isinstance(packet, dict):
        return [Result("-", "unresolved", "I7", "packet is not a JSON object", gaps=[{"need": "well_formed_packet", "ref": "-"}])]
    bad = unsafe_number(packet)
    if bad:   # spec 12.1: such a packet cannot be canonicalized the same way by every verifier
        return _all_unresolved(packet, f"number outside the I-JSON range at {bad}")
    bad = malformed_reason(packet)
    if bad:   # spec 12.1 (v0.3): not well-formed I-JSON within AMEP's bounds
        return _all_unresolved(packet, f"malformed packet: {bad}")
    version = packet.get("amep_version")
    if version not in SUPPORTED_VERSIONS:   # spec 16: never evaluate rules this verifier does not implement
        return _all_unresolved(packet, f"unsupported amep_version {version!r}")
    v03 = version == "0.3"
    vsig = lambda o: verify_sig(o, keys, require_v2=v03)   # noqa: E731
    # spec 10.5.1 (v0.3): the cause of the first refused signature among objects, for a signature gap
    first_cause = lambda os_: next((sig_cause(o, keys) for o in os_ if not vsig(o)), None)   # noqa: E731
    # Object ids are unique within a packet (spec 5.2, v0.3): two objects with one id would let a receipt or a
    # statement be read as evidence for the wrong one.
    seen_ids = set()
    for kind in ("mandates", "delegations", "intents", "interpretations", "invocations", "effects", "approvals",
                 "findings", "call_statements"):
        for o in packet.get(kind, []):
            if isinstance(o, dict) and "id" in o:
                if o["id"] in seen_ids:
                    return _all_unresolved(packet, f"malformed packet: duplicate object id {o['id']!r}")
                seen_ids.add(o["id"])
    objs = {o["id"]: o for kind in ("mandates", "delegations", "intents", "interpretations", "invocations",
                                    "effects", "approvals", "findings")
            for o in packet.get(kind, []) if isinstance(o, dict) and "id" in o}
    revocations, statuses = packet.get("revocations", []), packet.get("statuses", [])
    effects = packet.get("effects", [])
    state = {} if state is None else state
    spent: dict[str, int] = dict(state.get("spent", {}))
    totals: dict[str, int] = {k: amount_units(v) for k, v in state.get("period_totals", {}).items()}
    prior_windows = set(totals)
    # spec 7.6 rule 6 (v0.3): holds for earlier invocations whose outcome was unknown. A packet that contains a held
    # invocation decides it afresh, so its hold is set aside while this packet is evaluated, and never counted twice.
    try:
        held_in = held_of(state)
        appr_held_in = approvals_held_of(state)
    except Malformed as e:
        return _all_unresolved(packet, f"malformed verifier state: {e}")
    present = set()
    for i in packet.get("invocations", []):
        try:
            present.add(digest(i))
        except Exception:   # a malformed invocation is reported by its own evaluation
            pass
    # approval id -> (invocation id, body digest) of its first use, including uses in earlier packets
    approval_use: dict[str, tuple] = {k: tuple(v) for k, v in state.get("approvals_used", {}).items()}
    out: list[Result] = []
    invocations = packet.get("invocations", [])
    order = {i.get("id"): n for n, i in enumerate(invocations)}
    # spec 5.9.1 data lineage: data classes each invocation's output carries, through derived_from, earlier only
    taint: dict[str, set] = {}
    for n, i in enumerate(invocations):
        own = {d for e in effects if e.get("invocation") == i.get("id") for d in (e.get("executed") or {}).get("accessed", [])}
        for j in i.get("derived_from", []):
            if order.get(j, n) < n:
                own |= taint.get(j, set())
        taint[i.get("id")] = own
    decisions = [d for d in packet.get("decisions", []) if vsig(d)]
    # spec 5.13: a verified pre-execution quarantine withholds findings from every LATER invocation
    quarantined: dict[str, int] = {}
    for d in decisions:
        if d.get("mode") == "quarantine" and d.get("phase") == "pre_execution" and d.get("invocation") in order:
            for f in d.get("quarantined", []):
                quarantined[f] = min(quarantined.get(f, len(invocations)), order[d["invocation"]])
    def operator_of(o):
        # spec 12.5 (v0.3): a key may name the operator that controls it; two keys with the same operator are one party
        # for observer independence (I10), whatever identifiers their records use
        kid = (o.get("proof") or {}).get("kid") if isinstance(o, dict) else None
        k = keys.get(kid) if isinstance(kid, str) else None
        return k["operator"] if isinstance(k, dict) and isinstance(k.get("operator"), str) else None

    def same_operator(a, b):
        x = operator_of(a)
        return x is not None and x == operator_of(b)

    ctx = {"v03": v03, "totals": totals, "prior_windows": prior_windows, "same_operator": same_operator,
           "held": {d: h for d, h in held_in.items() if d not in present}, "new_held": {}, "first_cause": first_cause,
           # spec 5.10, held approvals (v0.3): approvals held for earlier invocations whose outcome is unknown; one held by an
           # invocation in this packet is set aside, since this packet decides that invocation afresh
           "appr_held": {a: h for a, h in appr_held_in.items() if h["digest"] not in present}}
    for n, inv in enumerate(invocations):
        rid = inv.get("id", "?")
        try:
            leaked = [f for f in inv.get("influenced_by", []) if f in quarantined and n > quarantined[f]]
            _check(bool(leaked) and not inv.get("principal_confirmed"), "violated", "I4", f"quarantined content reached the agent ({', '.join(leaked)})", blame="host")
            why = _evaluate_invocation(inv, packet, objs, vsig, revocations, statuses, effects, spent, approval_use, extra_protected, order, taint, ctx)
            out.append(Result(rid, "preserved", "-", why or "continuity preserved"))
        except Stop as s:
            out.append(Result(rid, *s.r))
        except (Malformed, KeyError, TypeError, ValueError, AttributeError) as e:
            out.append(Result(rid, "unresolved", "I7", f"malformed evidence: {e}", gaps=[{"need": "well_formed_evidence", "ref": str(rid)}]))

    # spec 10.3: decision reconciliation. Only PRE-execution decisions can be contradicted or confirm a block;
    # a post-execution decision is detection and a simulation is hypothetical (spec 5.13).
    eff_by_inv = {e.get("invocation") for e in effects}
    for d in decisions:
        if d.get("mode") not in ("deny", "hold") or d.get("phase") != "pre_execution":
            continue
        enf = d.get("enforcement", {})
        if d.get("invocation") in eff_by_inv:
            out = [r for r in out if r.invocation != d["invocation"]]
            out.append(Result(d["invocation"], "violated", "I11", "effect executed despite a deny/hold decision (enforcement contradicted)", blame="host"))
        elif enf.get("fail_mode") == "closed" or enf.get("applied") == "confirmed":
            # both fields are declared by the host that signed the deny, so they never settle "nothing executed": only a
            # not_executed statement from an observer does, which the call's own evaluation already honours. They change
            # nothing for read and write_local; for a high-impact call, the missing independent record is named (I10).
            inv = next((i for i in packet.get("invocations", []) if i.get("id") == d.get("invocation")), None)
            low = inv is not None and (inv.get("declared") or {}).get("effect") in ("read", "write_local")
            cur = next((r for r in out if r.invocation == d["invocation"]), None)
            if inv is not None and not low:
                if cur is not None and cur.outcome == "unresolved":
                    out = [r for r in out if r.invocation != d["invocation"]]
                    out.append(Result(d["invocation"], "unresolved", "I10",
                                      "denied, but only the host says it held; a high-impact call needs an independent not_executed statement",
                                      gaps=[{"need": "independent_observer", "ref": d["invocation"]}]))
    # spec 10.4: orphan effects
    inv_ids = {i.get("id") for i in packet.get("invocations", [])}
    for e in effects:
        if e.get("invocation") not in inv_ids:
            out.append(Result(e.get("id", "?"), "violated", "I11", "effect without any authorized invocation (bypass)", blame="host"))
    state["spent"] = spent
    state["approvals_used"] = {k: list(v) for k, v in approval_use.items()}
    if totals:
        state["period_totals"] = {k: _units_str(v) for k, v in totals.items()}
    if ctx["appr_held"] or "approvals_held" in state:
        state["approvals_held"] = ctx["appr_held"]
    held_out = {**ctx["held"], **ctx["new_held"]}
    if held_out or "held" in state:
        state["held"] = held_out
    return out


def evaluate_text(text: str, keys: dict, extra_protected=(), state: dict | None = None) -> list[Result]:
    """Evaluate a packet given as JSON text: parsed strictly (spec 12.1), so duplicate member names and inexact
    number literals make every invocation unresolved (I7)."""
    try:
        packet = parse_strict(text)
    except (Malformed, ValueError) as e:
        return [Result("-", "unresolved", "I7", f"malformed packet text: {e}", gaps=[{"need": "well_formed_packet", "ref": "-"}])]
    return evaluate(packet, keys, extra_protected, state)


def _units_str(u: int) -> str:
    ip, fp = divmod(u, _SCALE)
    fp_s = str(fp).rjust(18, "0").rstrip("0")
    return f"{ip}.{fp_s}" if fp_s else str(ip)


def _revocation_window(node) -> float:
    w = (node.get("revocation") or {}).get("window", 0)
    if isinstance(w, bool) or not isinstance(w, (int, float)) or w < 0:
        raise Malformed("revocation window must be a non-negative number of seconds")
    return w


def _check_limit(n, i, lim, x, v, unit, amt, obs, appr, call_sum, ctx):
    """One applicable limit of node n for one effect x (spec 7.6 rules 3 to 6). Raises Stop on the first failed check."""
    _check("per_effect" in lim and amt > amount_units(lim.get("per_effect", "0")) and not appr, "violated", "I2",
           f"amount {v['amount']} {unit} exceeds the per-effect limit {lim.get('per_effect')} of {n['id']}", blame="agent")
    call_sum[i] = call_sum.get(i, 0) + amt
    _check("per_call" in lim and call_sum[i] > amount_units(lim.get("per_call", "0")) and not appr, "violated", "I2",
           f"this call moves {_units_str(call_sum[i])} {unit}, over the per-call limit {lim.get('per_call')} of {n['id']}", blame="agent")
    if "per_period" not in lim:
        return
    key, start = period_key(n, lim, unit, x["t"]), window_start(n, lim, x["t"])
    total = ctx["totals"].get(key, 0) + amt
    # An observer's total is the principal's total only when that observer sees all of this node's spending in the unit
    # (the limit names it in counted_by, amep#10), and only for this limit's own window: the figure must say the window
    # starts where the limit's does (amep#10, vendrell46). Other figures never count.
    entry = period_spent_of(v, unit).get(str(int(lim["period"]))) if lim.get("counted_by") == obs else None
    counted = entry[1] if entry is not None and entry[0] is not None and entry[0] == start else None
    if counted is not None:
        _check(counted < total, "violated", "I7",
               f"{obs}'s period total {_units_str(counted)} {unit} is below the payments recorded for {n['id']}", blame="server")
        total = counted
    _check(total > amount_units(lim["per_period"]) and not appr, "violated", "I2",
           f"period total {_units_str(total)} {unit} exceeds the per-period limit {lim['per_period']} of {n['id']}", blame="agent")
    _check(counted is None and key not in ctx["prior_windows"], "unresolved", "I7",
           f"period total for {n['id']} cannot be established: no total from its counting observer for this window and no earlier state",
           need="period_total", ref=n['id'])
    # holds (spec 7.6 rule 6): an earlier call with an unknown outcome may already have spent part of this window. An
    # approval that passed I8 authorizes going over the limit for its effect, so holds don't block it.
    holds = [(h["invocation"], h["amounts"][key]) for h in ctx["held"].values() if key in h["amounts"]]
    if holds and not appr:
        unknown = [h for h, a in holds if a is None]
        _check(bool(unknown), "unresolved", "I7",
               f"the outcome of {unknown[0] if unknown else ''} is unknown, so the period total of {n['id']} cannot be bounded",
               need="held_outcome", ref=unknown[0] if unknown else "-")
        held_sum = sum(amount_units(a, unit) for _, a in holds)
        _check(total + held_sum > amount_units(lim["per_period"]), "unresolved", "I7",
               f"period total {_units_str(total)} {unit} plus {_units_str(held_sum)} held for {', '.join(h for h, _ in holds)} "
               f"would exceed the per-period limit {lim['per_period']} of {n['id']}", need="held_outcome", ref=holds[0][0])
    ctx["totals"][key] = total


def _evaluate_invocation(inv, packet, objs, vsig, revocations, statuses, effects, spent, approval_use, extra_protected, order, taint, ctx):
    rid, t_inv = inv["id"], to_time(inv["t"])
    first_cause = ctx["first_cause"]
    # 1. chain
    chain, node, seen = [], objs.get(inv.get("authority_ref")), set()
    while node and node["id"] not in seen:
        seen.add(node["id"]); chain.append(node); node = objs.get(node.get("parent"))
    chain.reverse()
    _check(not chain or chain[0].get("kind") != "mandate", "unresolved", "I7", "no root mandate", need="root_mandate", ref=inv.get("authority_ref") or "-")
    # 2. signatures (and signer roles) on everything the decision rests on
    interp = objs.get(inv.get("interpretation_ref"))
    needed = chain + [inv] + ([interp] if interp else [])
    intent = None
    if "intent_ref" in inv:
        intent = objs.get(inv["intent_ref"])
        _check(not intent or intent.get("kind") != "intent", "unresolved", "I7", "cited intent not found", need="intent", ref=inv.get("intent_ref") or "-")
        needed.append(intent)
    _check(any(not vsig(o) for o in needed), "unresolved", "I7", "missing or invalid signature, or signer lacks the role", need="signature", ref=rid,
           cause=first_cause(needed))
    _check(any(order.get(j, order[rid]) >= order[rid] for j in inv.get("derived_from", [])),
           "unresolved", "I7", "lineage reference not found among earlier invocations", need="lineage", ref=rid)
    # claim members (spec 16, v0.3): an unknown claim member may be a constraint this verifier cannot enforce, so
    # it is never ignored. Limits are validated wherever they appear.
    limited = [n for n in chain + ([intent] if intent else []) if "limits" in n["claims"]]
    for n in limited:
        check_limits(n["claims"]["limits"])
    if not ctx["v03"]:
        # grants are an AMEP 0.3 member. Ignored, as v0.2 ignores unknown members, they could widen authority the
        # producer meant to narrow, so an unversioned packet that uses them is malformed instead.
        for n in chain + ([intent] if intent else []):
            _check("grants" in n["claims"], "unresolved", "I7", f"{n['id']}: grants require amep_version 0.3",
                   need="well_formed_evidence", ref=n['id'])
    if ctx["v03"] and "reserve" in inv:
        try:
            check_reserve(inv["reserve"])
        except Malformed as e:
            _check(True, "unresolved", "I7", f"{rid}: {e}", need="reserve", ref=rid)
    if ctx["v03"]:
        for n in chain + ([intent] if intent else []):
            unknown = sorted(k for k in n["claims"] if k not in CLAIM_MEMBERS and not is_extension_member(k))
            _check(bool(unknown), "unresolved", "I7", f"{n['id']}: claim member not understood ({', '.join(unknown)})", need="verifier_support", ref=n['id'])
            if "grants" in n["claims"]:
                g = n["claims"]["grants"]
                ok = (isinstance(g, list) and g and "actions" not in n["claims"] and "resources" not in n["claims"]
                      and all(isinstance(e, dict) and set(e) == {"actions", "resources"} and all(
                          isinstance(e[k], list) and e[k] and all(isinstance(p, str) for p in e[k]) for k in ("actions", "resources"))
                          for e in g))
                _check(not ok, "unresolved", "I7", f"{n['id']}: grants must be a non-empty list of {{actions, resources}}, without actions or resources beside it",
                       need="well_formed_evidence", ref=n['id'])
            for lim in n["claims"].get("limits", []):
                unknown = sorted(k for k in lim if k not in LIMIT_MEMBERS and not is_extension_member(k))
                _check(bool(unknown), "unresolved", "I7", f"{n['id']}: limit member not understood ({', '.join(unknown)})", need="verifier_support", ref=n['id'])
    # 3-4. interpretation
    _check(not interp or interp.get("source") not in ("curated", "customer"), "unresolved", "I3", "no approved interpretation", need="interpretation", ref=inv.get("interpretation_ref") or "-")
    pinned = packet.get("pinned_adapters", {})
    _check(bool(pinned) and pinned.get(interp.get("adapter")) != interp.get("version"), "unresolved", "I3", "adapter revision not approved (pin mismatch)", need="interpretation_pin", ref=inv.get("interpretation_ref") or "-")
    # 5. attenuation
    for p, c in zip(chain, chain[1:]):
        ok, why = narrower(c["claims"], p["claims"], ctx["v03"])
        _check(not ok, "violated", "I1", f"{c['id']}: {why}", blame="delegator")
        why = limits_narrower(c["claims"], p["claims"])
        _check(bool(why), "violated", "I1", f"{c['id']}: {why}", blame="delegator")
    # 6. liveness at the invocation: signed revocations and signed status assertions (spec 5.12). A revocation
    # still inside the revoked node's declared propagation window is unresolved, not violated (spec 5.12.1, v0.3).
    ids = {n["id"] for n in chain}
    by_id = {n["id"]: n for n in chain}
    revs = [r for r in revocations if r.get("target") in ids]
    sts = [s for s in statuses if s.get("target") in ids and vsig(s)]
    revoked_at = [(to_time(r["t"]), r["target"], "ancestor revoked") for r in revs if vsig(r)] + \
                 [(to_time(s["revoked_at"]), s["target"], "status shows ancestor revoked") for s in sts if s.get("revoked_at") is not None]

    def liveness(t, what):
        for r_t, target, why in sorted(revoked_at):
            if r_t <= t:
                w = _revocation_window(by_id[target])
                _check(t < r_t + w, "unresolved", "I6", f"{why} {t - r_t:g}s before {what}, inside its {w:g}s propagation window", blame="agent", need="revocation_settled", ref=target)
                _check(True, "violated", "I6", f"{why} before {what}", blame="agent")

    def fresh_status(t, what):
        for n in chain:
            if (n.get("revocation") or {}).get("status_ref"):
                fresh = [s for s in sts if s["target"] == n["id"] and to_time(s["as_of"]) >= t]
                _check(not fresh, "unresolved", "I7", f"no signed revocation status for {n['id']} as of {what}", need="revocation_status", ref=n['id'])

    liveness(t_inv, "invocation")
    _check(any(not vsig(r) for r in revs), "unresolved", "I7", "unverifiable revocation on the chain", need="revocation_signature", ref=rid,
           cause=first_cause(revs))
    fresh_status(t_inv, "the invocation")
    # 7. self-protection on the declared target
    _check(is_guardrail(inv["declared"]["resource"], extra_protected), "violated", "I9", "targets guardrail/evidence store", blame="agent")
    # 8-9. influence: a finding counts as trusted only if it exists, is signed and is labelled trusted (spec 5.11)
    mine = [e for e in effects if e.get("invocation") == rid]
    untrusted = [f for f in inv.get("influenced_by", [])
                 if not (objs.get(f) and vsig(objs[f]) and objs[f].get("integrity_label") == "trusted")]
    _check(bool(untrusted) and inv["declared"]["effect"] != "read" and not inv.get("principal_confirmed"),
           "violated" if mine else "unresolved", "I4", "mutation shaped by untrusted content", blame="agent", need="principal_confirmation", ref=rid)
    # 10. call statements (spec 5.14, v0.3): the observer's signed account of the whole call. It binds the call to
    # this exact signed invocation and to the arguments the server received, says whether anything was executed,
    # and how many receipts to expect, so that "no receipt" is no longer ambiguous.
    inv_digest = digest(inv)
    stmts = [c for c in packet.get("call_statements", []) if isinstance(c, dict) and c.get("invocation") == rid]
    for c in stmts:
        _check(not vsig(c), "unresolved", "I7", "call statement unsigned or signer lacks the role", need="call_statement_signature", ref=c.get('id', '?'),
               cause=first_cause([c]))
        _check(c.get("disposition") not in DISPOSITIONS, "unresolved", "I7", "call statement with an unknown disposition", need="call_statement", ref=c.get('id', '?'))
        n_eff = c.get("effect_count")
        _check(isinstance(n_eff, bool) or not isinstance(n_eff, (int, float)) or n_eff != int(n_eff) or n_eff < 0,
               "unresolved", "I7", "call statement effect_count must be a non-negative integer", need="call_statement", ref=c.get('id', '?'))
        _check(c["disposition"] == "not_executed" and n_eff != 0, "unresolved", "I7", "call statement says not executed but counts effects", need="call_statement", ref=c.get('id', '?'))
        _check("invocation_digest" in c and c["invocation_digest"] != inv_digest, "unresolved", "I7",
               "call statement is bound to a different invocation (invocation_digest mismatch)", need="call_statement_binding", ref=c.get('id', '?'))
    not_executed = any(c["disposition"] == "not_executed" for c in stmts)
    sent_args = inv.get("args_digest")
    rewritten = [c for c in stmts if sent_args is not None and "args_digest" in c and c["args_digest"] != sent_args]
    _check(bool(rewritten) and not not_executed, "violated", "I2",
           "the arguments the server received differ from those the host signed (changed in transit)", blame="transport")
    _check(bool(rewritten), "unresolved", "I7", "the arguments were changed in transit; the server executed nothing", need="unaltered_call", ref=rid)
    _check(not_executed and bool(mine), "violated", "I11", "effect receipts contradict a signed not_executed statement", blame="server")
    if not mine and not_executed:
        # provably nothing was executed, so the call cannot have exceeded its authority; for a high-impact call the
        # statement must come from a party other than the actor (I10)
        hi = CEILING.index(inv["declared"]["effect"]) >= CEILING.index("write_shared")
        _check(hi and all(c.get("observed_by") == inv.get("actor") or ctx["same_operator"](c, inv) for c in stmts if c["disposition"] == "not_executed"),
               "unresolved", "I10", "high-impact call reported not executed only by the actor itself, or by a key of the host's own operator",
               need="independent_observer", ref=rid)
        # say why it is preserved: nothing ran, on the observer's signed word, not "within authority"
        who = ", ".join(sorted({str(c.get("observed_by")) for c in stmts if c["disposition"] == "not_executed"}))
        return f"nothing executed: {who} signed a not_executed call statement"
    # 11. effect receipts. With none and no not_executed statement, the call may still have moved value: hold its
    # reserve (or an unknown amount) against every period limit on its chain that applies to it (spec 7.6 rule 6).
    if not mine:
        reserve = inv.get("reserve") if ctx["v03"] else None
        amounts = {}
        for n in limited:
            for lim in n["claims"]["limits"]:
                if "per_period" in lim and limit_applies(lim, inv["declared"]):
                    same = reserve is not None and reserve["unit"] == lim["unit"]
                    amounts[period_key(n, lim, lim["unit"], inv["t"])] = reserve["amount"] if same else None
        if amounts:
            ctx["new_held"][inv_digest] = {"invocation": rid, "amounts": amounts}
        # spec 5.10, held approvals (v0.3): the call may have run under its approval, so the approval is held for it until its
        # outcome is known. From Takao Sato's VATE case 2 (accepted work interrupted): without the hold, a re-run under
        # the same single-use admission came out preserved, and only later evidence turned it into a double use.
        ref = inv.get("approval_ref")
        if isinstance(ref, str) and ref not in ctx["appr_held"]:
            ctx["appr_held"][ref] = {"invocation": rid, "digest": inv_digest}
    _check(not mine, "unresolved", "I7", "no executed-effect receipt", need="receipt", ref=rid)
    high_impact = CEILING.index(inv["declared"]["effect"]) >= CEILING.index("write_shared")
    eff_claims = chain[0]["claims"]
    for n in chain[1:]:
        eff_claims = meet(n["claims"], eff_claims, ctx["v03"])
    if intent:
        eff_claims = meet(intent["claims"], eff_claims, ctx["v03"])
    appr = objs.get(inv.get("approval_ref")) if "approval_ref" in inv else None
    # 11-15. every receipt for this invocation is checked (spec 10.2)
    by_observer: dict = {}   # observer -> effect identity digest -> its receipts, in packet order
    for e in mine:
        _check(not vsig(e), "unresolved", "I7", "effect receipt unsigned or signer lacks the role", need="receipt_signature", ref=e.get('id', '?'),
               cause=first_cause([e]))
        _check(not isinstance(e.get("observed_by"), str), "unresolved", "I7", f"receipt {e.get('id', '?')} names no observer", need="receipt_observer", ref=e.get('id', '?'))
        _check("invocation_digest" in e and e["invocation_digest"] != inv_digest, "unresolved", "I7",
               f"receipt {e.get('id', '?')} is bound to a different invocation (invocation_digest mismatch)", need="receipt_binding", ref=e.get('id', '?'))
        if high_impact:
            _check(not inv.get("actor"), "unresolved", "I10", "actor not recorded; observer independence cannot be shown", need="actor", ref=rid)
            _check(e.get("observed_by") == inv["actor"] or e.get("assurance") == "L0", "unresolved", "I10", "high-impact effect only self-reported", need="independent_observer", ref=e.get('id', '?'))
            _check(ctx["same_operator"](e, inv), "unresolved", "I10", "high-impact effect observed only by a key of the host's own operator",
                   need="independent_observer", ref=e.get('id', '?'))
        x = e["executed"]
        # liveness at each effect's own time (spec 8 I6, v0.3): authority must still be in force when the effect
        # occurs, not only when it was invoked. Proposed by Cliff Singletary on audit@ietf.org, 19 Nov 2026.
        liveness(to_time(x["t"]), f"effect {e.get('id', '?')}")
        fresh_status(to_time(x["t"]), f"effect {e.get('id', '?')}")
        if "mediated" in inv:
            _check(canon(x) != canon(inv["mediated"]), "violated", "I2", "executed differs from mediated effect", blame="server")
        else:
            _check((x["action"], x["resource"]) != (inv["declared"]["action"], inv["declared"]["resource"]), "violated", "I2", "declared != executed", blame="server")
        _check(is_guardrail(x["resource"], extra_protected), "violated", "I9", "executed effect targets guardrail/evidence store", blame="agent")
        ok, why = effect_ok(x, eff_claims, ctx["v03"])
        _check(not ok, "violated", "I5" if why.startswith("released") else "I2", why, blame="agent")
        # spec 5.9.1: data classes carried in through lineage (or read by this effect) reach the recipient too
        if "recipient" in x:
            inherited = set(x.get("accessed", []))
            for j in inv.get("derived_from", []):
                inherited |= taint.get(j, set())
            leaked = sorted(f"{d}->{x['recipient']}" for d in inherited if f"{d}->{x['recipient']}" not in eff_claims.get("data", []))
            _check(bool(leaked), "violated", "I5", f"derived data released: {', '.join(leaked)}", blame="agent")
        if "value" in x:   # validate wherever present, so a malformed amount is never silently ignored
            v = x["value"]
            _check(not isinstance(v, dict), "unresolved", "I7", "value must be an object", need="value", ref=e.get('id', '?'))
            _unit(v.get("unit")); amount_units(v.get("amount"), v["unit"]); period_spent_of(v, v["unit"])
        by_observer.setdefault(e.get("observed_by"), {}).setdefault(approval_digest(x), []).append(e)
    # spec 10.2 (v0.3): the same effect recorded by several observers counts once, but within one observer every receipt
    # is its own effect. An effect therefore occurs as often as the most any one observer recorded it, and is taken from
    # that observer's receipts. Raised by Carlos Vendrell Felici (stafordtituss/amep#10): two identical payments in one
    # call had counted as one.
    effects_of: list = []    # (executed body, identity digest, observer)
    for d in dict.fromkeys(dd for o in by_observer.values() for dd in o):
        obs = max(sorted(o for o in by_observer if d in by_observer[o]), key=lambda o: len(by_observer[o][d]))
        effects_of += [(e["executed"], d, obs) for e in by_observer[obs][d]]
    bodies = {d: x for x, d, _ in effects_of}
    # every receipt a statement promises must be present, and no more (spec 5.14)
    for c in stmts:
        k = sum(1 for e in mine if e.get("observed_by") == c.get("observed_by"))
        _check(k > c["effect_count"], "violated", "I7", f"{k} receipts from {c.get('observed_by')} but its call statement counts {c['effect_count']}", blame="server")
        _check(k < c["effect_count"], "unresolved", "I7", f"call statement promises {c['effect_count']} receipts from {c.get('observed_by')}, {k} present (lost or withheld)", need="receipt", ref=rid)
    if "approval_ref" in inv:
        _check(not appr or not vsig(appr), "unresolved", "I7", "approval missing, unsigned or not signed by an approver", need="approval", ref=inv.get("approval_ref") or "-")
        # An operation approval (spec 5.10, v0.3) lists the digests of the effects of one call instead of one digest.
        # From Takao Sato's VATE case 1 (openid/authzen#795): one admission covering an operation that writes two files.
        listed = appr.get("effect_digests") if "effect_digests" in appr else None
        if "effect_digests" in appr:
            _check("effect_digest" in appr or not isinstance(listed, list) or not listed
                   or not all(isinstance(x, str) and re.fullmatch(r"[0-9a-f]{64}", x) for x in listed),
                   "unresolved", "I7", "an operation approval needs a non-empty effect_digests list of digests, and no effect_digest",
                   need="approval", ref=appr.get("id", "?"))
            op_use = (rid, "set:" + hashlib.sha256(canon(sorted(listed))).hexdigest())
        else:   # neither form: malformed (spec 5.10), the same result in every verifier
            _check("effect_digest" not in appr, "unresolved", "I7", "approval has no effect_digest or effect_digests",
                   need="approval", ref=appr.get("id", "?"))
        for d, x in bodies.items():
            t_x = to_time(x["t"])
            n_exec = sum(1 for _, dd, _ in effects_of if dd == d)
            if listed is None:
                _check(appr["effect_digest"] != d, "violated", "I8", "approval not bound to the executed effect", blame="agent")
                _check(n_exec > 1, "violated", "I8", f"one approval, but the approved effect was executed {n_exec} times", blame="agent")
            else:
                n_ok = listed.count(d)
                _check(n_exec > n_ok, "violated", "I8", "the operation approval does not cover the executed effect" if n_ok == 0
                       else f"the operation approval covers this effect {n_ok} time(s), but it was executed {n_exec} times", blame="agent")
            _check(bool(appr.get("consumed")), "violated", "I8", "approval already consumed", blame="agent")
            _check("expiry" in appr and to_time(appr["expiry"]) < max(t_inv, t_x), "violated", "I8", "approval expired", blame="agent")
            _check("nbf" in appr and to_time(appr["nbf"]) > t_inv, "violated", "I8", "approval not yet valid", blame="agent")
        # spec 5.10, held approvals: after every check that decides violated, so a hold never hides a violation
        holder = ctx["appr_held"].get(appr["id"]) if bodies else None
        _check(holder is not None and holder["invocation"] != rid, "unresolved", "I7",
               f"approval {appr['id']} is held for {holder and holder['invocation']}, whose outcome is unknown",
               need="held_outcome", ref=holder and holder["invocation"])
        for d in bodies:
            use = (rid, d) if listed is None else op_use
            first = approval_use.setdefault(appr["id"], use)
            _check(first != use, "violated", "I8", f"approval already used by {first[0]}", blame="agent")
    # 16. quantity limits (spec 7.6, v0.3), on every node of the chain and on the intent. An approval that passed I8
    # authorizes going over a limit; the amount still counts toward the period total. Every applicable limit is
    # checked before the result is decided, and a violation beats an unresolved check, so the verdict doesn't depend on
    # the order the limits are listed in (amep#10, vendrell46).
    deferred: list = []
    for n in limited:
        call_sum: dict = {}   # limit index -> amount moved by this call so far
        for x, _d, obs in effects_of:
            applicable = [(i, lim) for i, lim in enumerate(n["claims"]["limits"]) if limit_applies(lim, x)]
            if not applicable:
                continue
            try:
                v = x.get("value")
                _check(v is None, "unresolved", "I7", f"{n['id']} limits this effect but the receipt records no value", need="value", ref=n['id'])
                unit = v["unit"]
                amt = amount_units(v["amount"], unit)
                matching = [(i, lim) for i, lim in applicable if lim["unit"] == unit]
                if not matching:
                    money = unit.startswith(MONEY_UNITS) or x["effect"] == "financial"
                    _check(money, "violated", "I2", f"{unit} is not an asset {n['id']} authorizes", blame="agent")
                    _check(True, "unresolved", "I7", f"{n['id']} limits this effect in another unit than {unit}", need="value", ref=n['id'])
            except Stop as stop:
                deferred.append(stop)
                continue
            for i, lim in matching:
                try:
                    _check_limit(n, i, lim, x, v, unit, amt, obs, appr, call_sum, ctx)
                except Stop as stop:
                    deferred.append(stop)
    for o in ("violated", "unresolved"):
        stop = next((d for d in deferred if d.r[0] == o), None)
        if stop:
            raise stop
    # 17. risk budget: recorded spend must match receipts; over budget needs a bound approval
    c = sum(cost(x) for x, _, _ in effects_of)
    _check("budget_spent" in inv and inv["budget_spent"] != c, "violated", "I7", "recorded budget spend does not match receipts", blame="host")
    over = next((n["id"] for n in chain if "budget" in n["claims"] and spent.get(n["id"], 0) + c > n["claims"]["budget"]), None)
    _check(bool(over) and not appr, "violated", "I2", f"risk budget of {over} exceeded without approval", blame="agent")
    for n in chain:
        spent[n["id"]] = spent.get(n["id"], 0) + c


def verdict(results: list[Result]) -> Result:
    """Spec 10.5: violated beats unresolved beats preserved; first result with that outcome decides."""
    for o in ("violated", "unresolved"):
        r = next((r for r in results if r.outcome == o), None)
        if r:
            return r
    return results[0] if results else Result("-", "unresolved", "I7", "empty packet", gaps=[{"need": "invocation", "ref": "-"}])


