"""Builds schemas/v0.2/*.json (JSON Schema 2020-12) from one definition, matching spec/amep-v0.2.md section 5.
Run from the repo root: python3 -I tools/build_schemas.py schemas/v0.2   (then: python3 -I tools/validate_schemas.py)"""
import json
import os
import sys

out = sys.argv[1]
BASE = "https://amep.example/schemas/v0.2/"
EXT = {"^x-": {}, "\\.": {}}  # extension members: x- prefix or reverse-DNS (spec 16)
C = "common.json#/$defs/"


def obj(title, desc, required, props, kind=None):
    if kind:
        props = {"kind": {"const": kind}, **props}
        required = ["kind", *required]
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": BASE + title + ".json", "title": title,
            "description": desc, "type": "object", "required": required, "properties": props,
            "patternProperties": EXT, "additionalProperties": False}


ref = lambda n: {"$ref": C + n}
schemas = {}
schemas["common"] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema", "$id": BASE + "common.json", "title": "common",
    "description": "Shared AMEP v0.2 types (spec 5.1, 5.3, 5.9).",
    "$defs": {
        "ref": {"type": "string", "minLength": 1},
        "time": {"description": "Seconds since the Unix epoch, or an RFC 3339 date-time with offset (spec 5.1.1).",
                 "anyOf": [{"type": "number"},
                           {"type": "string", "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,3})?(Z|[+-]\\d{2}:\\d{2})$"}]},
        "effect_class": {"enum": ["read", "write_local", "write_shared", "external_send", "destructive", "financial"]},
        "assurance": {"enum": ["L0", "L1", "L2", "L3"]},
        "data_flow": {"type": "string", "pattern": "^[a-z_]+->[a-z_]+$"},
        "proof": {"type": "object", "required": ["alg", "kid", "sig"], "additionalProperties": False,
                  "properties": {"alg": {"enum": ["Ed25519", "ES256"]}, "kid": {"type": "string", "minLength": 1},
                                 "sig": {"type": "string", "minLength": 1}, "timestamp_token": {"type": "string"}}},
        "claims": {"type": "object", "required": ["actions", "resources", "ceiling", "exp"], "additionalProperties": False,
                   "patternProperties": EXT,
                   "properties": {"actions": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                                  "resources": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                                  "data": {"type": "array", "items": {"$ref": "#/$defs/data_flow"}},
                                  "ceiling": {"$ref": "#/$defs/effect_class"},
                                  "exp": {"$ref": "#/$defs/time"}, "nbf": {"$ref": "#/$defs/time"},
                                  "purpose": {"type": "string"},
                                  "deny_actions": {"type": "array", "items": {"type": "string"}},
                                  "deny_resources": {"type": "array", "items": {"type": "string"}},
                                  "depth": {"type": "integer", "minimum": 0}, "budget": {"type": "integer", "minimum": 0}}},
        "declared": {"type": "object", "required": ["action", "resource", "effect"], "additionalProperties": False,
                     "properties": {"action": {"type": "string"}, "resource": {"type": "string"}, "effect": {"$ref": "#/$defs/effect_class"}}},
        "executed_body": {"type": "object", "required": ["action", "resource", "effect", "t"], "additionalProperties": False,
                          "patternProperties": EXT,
                          "properties": {"action": {"type": "string"}, "resource": {"type": "string"},
                                         "effect": {"$ref": "#/$defs/effect_class"},
                                         "released": {"type": "array", "items": {"$ref": "#/$defs/data_flow"}},
                                         "reversible": {"type": "boolean"}, "t": {"$ref": "#/$defs/time"}}},
        "token": {"description": "Source token of a mandate or delegation (spec/profiles/). value only for expired or holder-bound tokens.",
                  "type": "object", "required": ["format", "digest"], "additionalProperties": False,
                  "properties": {"format": {"enum": ["biscuit", "macaroon", "ucan"]}, "block": {"type": "integer", "minimum": 0},
                                 "digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"}, "value": {"type": "string"}}},
        "enforcement": {"type": "object", "required": ["pep", "fail_mode"], "additionalProperties": False,
                        "properties": {"pep": {"type": "string"}, "fail_mode": {"enum": ["closed", "open", "unknown"]},
                                       "host_supports": {"type": "array", "items": {"enum": ["ask", "deny", "rewrite_input", "replace_output"]}},
                                       "encoded_as": {"type": "string"},
                                       "applied": {"enum": ["confirmed", "not_observed", "contradicted"]}}},
    },
}
schemas["mandate"] = obj("mandate", "PrincipalMandate (spec 5.4). Signed by a key with role issuer.", ["id", "principal", "claims"], {
    "id": ref("ref"), "principal": {"type": "string"}, "issuer": {"type": "string"}, "subject_agent": {"type": "string"},
    "claims": ref("claims"),
    "revocation": {"type": "object", "required": ["status_ref"], "properties": {"status_ref": {"type": "string"}}, "additionalProperties": False},
    "token": ref("token"), "proof": ref("proof")}, "mandate")
schemas["delegation"] = obj("delegation", "Delegation (spec 5.5). Signed by a key with role issuer or host.", ["id", "parent", "claims"], {
    "id": ref("ref"), "parent": ref("ref"), "delegate": {"type": "string"}, "claims": ref("claims"),
    "token": ref("token"), "proof": ref("proof")}, "delegation")
schemas["intent"] = obj("intent", "IntentCertificate (spec 5.6).", ["id", "claims"], {
    "id": ref("ref"), "prompt_ref": ref("ref"), "claims": ref("claims"),
    "derivation": {"enum": ["template", "judge", "confirmed"]}, "proof": ref("proof")}, "intent")
schemas["interpretation"] = obj("interpretation", "AdapterInterpretation (spec 5.7). Signed by role host.", ["id", "source", "adapter", "version"], {
    "id": ref("ref"), "source": {"enum": ["curated", "customer", "provider_hint", "judge", "none"]},
    "adapter": {"type": "string"}, "version": {"type": "string"}, "integrity_hash": {"type": "string"}, "proof": ref("proof")}, "interpretation")
schemas["invocation"] = obj("invocation", "Invocation (spec 5.8). Signed by role host.", ["id", "authority_ref", "interpretation_ref", "t", "declared"], {
    "id": ref("ref"), "authority_ref": ref("ref"), "interpretation_ref": ref("ref"), "intent_ref": ref("ref"), "approval_ref": ref("ref"),
    "t": ref("time"), "actor": {"type": "string"}, "declared": ref("declared"), "mediated": ref("executed_body"),
    "influenced_by": {"type": "array", "items": ref("ref")}, "principal_confirmed": {"type": "boolean"},
    "budget_spent": {"type": "integer", "minimum": 0},
    "correlation": {"type": "object", "additionalProperties": False, "properties": {k: {"type": "string"} for k in ("session_ref", "prompt_ref", "tool_use_ref", "traceparent")}},
    "proof": ref("proof")}, "invocation")
schemas["effect"] = obj("effect", "ExecutedEffectReceipt (spec 5.9). Signed by role observer.", ["id", "invocation", "observed_by", "assurance", "executed"], {
    "id": ref("ref"), "invocation": ref("ref"), "observed_by": {"type": "string"}, "assurance": ref("assurance"),
    "executed": ref("executed_body"), "backend_receipt": {}, "proof": ref("proof")}, "effect")
schemas["approval"] = obj("approval", "ApprovalBinding (spec 5.10). Signed by role approver. The digest excludes t.", ["id", "effect_digest", "presence"], {
    "id": ref("ref"), "effect_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "presence": {"enum": ["webauthn", "chat_user", "host_ui", "none"]}, "approver": {"type": "string"},
    "resource_version": {"type": "string"}, "nbf": ref("time"), "expiry": ref("time"), "consumed": {"type": "boolean"},
    "proof": ref("proof")}, "approval")
schemas["finding"] = obj("finding", "ContentFinding (spec 5.11). Counts as trusted only when signed (role host or observer).",
    ["id", "source_locator", "content_hash", "integrity_label"], {
    "id": ref("ref"), "source_locator": {"type": "string"}, "content_hash": {"type": "string"},
    "span": {"type": "object", "required": ["start", "end"], "properties": {"start": {"type": "integer", "minimum": 0}, "end": {"type": "integer", "minimum": 0}, "excerpt": {"type": "string"}}, "additionalProperties": False},
    "hidden_mechanism": {"enum": ["none", "html_comment", "zero_width", "unicode_tags", "white_text", "alt_text", "metadata", "other"]},
    "integrity_label": {"enum": ["trusted", "untrusted"]},
    "requested": {"type": "object", "properties": {"action": {"type": "string"}, "object": {"type": "string"}, "recipient": {"type": "string"}}, "additionalProperties": False},
    "proof": ref("proof")}, "finding")
schemas["revocation"] = obj("revocation", "Revocation (spec 5.12). Signed by role issuer; unsigned revocations on a chain make it unresolved.", ["target", "t"], {
    "id": ref("ref"), "target": ref("ref"), "t": ref("time"), "reason": {"type": "string"}, "proof": ref("proof")}, "revocation")
schemas["status"] = obj("status", "Revocation status assertion (spec 5.12). Signed by role issuer.", ["target", "as_of"], {
    "id": ref("ref"), "target": ref("ref"), "as_of": ref("time"), "revoked_at": ref("time"), "proof": ref("proof")}, "status")
schemas["decision"] = obj("decision", "ContinuityDecision (spec 5.13). Signed by role host.", ["invocation", "outcome", "phase"], {
    "id": ref("ref"), "invocation": ref("ref"), "outcome": {"enum": ["preserved", "violated", "unresolved"]},
    "invariant": {"enum": ["-", "I1", "I2", "I3", "I4", "I5", "I6", "I7", "I8", "I9", "I10", "I11"]},
    "mode": {"enum": ["observe", "allow", "mediate", "step_up", "hold", "deny", "quarantine"]},
    "phase": {"enum": ["pre_execution", "post_execution", "simulation"]},
    "quarantined": {"type": "array", "items": ref("ref")}, "reason": {"type": "string"},
    "safe_alternatives": {"type": "array", "items": ref("executed_body")}, "evidence_refs": {"type": "array", "items": ref("ref")},
    "enforcement": ref("enforcement"), "proof": ref("proof")}, "decision")
arr = lambda n: {"type": "array", "items": {"$ref": n + ".json"}}
schemas["packet"] = obj("packet", "A packet of AMEP objects submitted for evaluation (spec 5.2).", [], {
    "amep_version": {"type": "string"}, "mandates": arr("mandate"), "delegations": arr("delegation"), "intents": arr("intent"),
    "interpretations": arr("interpretation"), "invocations": arr("invocation"), "effects": arr("effect"),
    "approvals": arr("approval"), "revocations": arr("revocation"), "statuses": arr("status"), "findings": arr("finding"),
    "decisions": arr("decision"), "pinned_adapters": {"type": "object", "additionalProperties": {"type": "string"}}})
schemas["keyset"] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema", "$id": BASE + "keyset.json", "title": "keyset",
    "description": "Key set served at /.well-known/amep-keys.json (spec 12.4, 12.5).", "type": "object",
    "additionalProperties": {"type": "object", "required": ["kid", "alg", "x", "roles"], "additionalProperties": False,
        "properties": {"kid": {"type": "string"}, "alg": {"enum": ["Ed25519", "ES256"]}, "x": {"type": "string"},
                       "roles": {"type": "array", "minItems": 1, "items": {"enum": ["issuer", "host", "observer", "approver"]}},
                       "nbf": {"$ref": C + "time"}, "exp": {"$ref": C + "time"}, "revoked": {"type": "boolean"}}}}
os.makedirs(out, exist_ok=True)
for name, s in schemas.items():
    with open(os.path.join(out, name + ".json"), "w") as f:
        json.dump(s, f, indent=1)
print(f"wrote {len(schemas)} schemas")
