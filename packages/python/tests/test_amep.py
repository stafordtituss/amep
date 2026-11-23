"""Tests for amep-protocol. Run: python -m unittest discover -s packages/python/tests"""
import contextlib
import io
import json
import os
import sys
import tempfile
import base64
import hashlib
import shutil
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from amep_protocol import evaluate, sdk, verdict  # noqa: E402
from amep_protocol.cli import main  # noqa: E402

VECTORS = os.path.join(HERE, "..", "..", "..", "vectors")
T = 1767225600


def build(write_resource="repo:app/src/auth.ts", executed_resource=None):
    issuer = sdk.Key.generate("issuer-1", ["issuer", "approver"])
    host = sdk.Key.generate("host-1", ["host"])
    observer = sdk.Key.generate("observer-1", ["observer"])
    m = issuer.sign(sdk.mandate("m-1", "user:alice", sdk.claims(["fs.*"], ["repo:app/*"], "write_local", exp=T + 3600,
                                                                deny_resources=["repo:app/secrets/*"], depth=1)))
    d = issuer.sign(sdk.delegation("d-1", "m-1", sdk.claims(["fs.write"], ["repo:app/src/*"], "write_local", exp=T + 1800,
                                                            deny_resources=["repo:app/secrets/*"], depth=0)))
    a = host.sign(sdk.interpretation("a-1", "host_shell", "r9"))
    i = host.sign(sdk.invocation("i-1", "d-1", "a-1", T + 10, "fs.write", write_resource, "write_local"))
    e = observer.sign(sdk.effect("e-1", "i-1", "hook:host", "L1",
                                 sdk.effect_body("fs.write", executed_resource or write_resource, "write_local", T + 11)))
    return sdk.packet(m, d, a, i, e), sdk.keyset(issuer, host, observer)


class SdkTest(unittest.TestCase):
    def test_round_trip_preserved(self):
        p, keys = build()
        self.assertEqual(verdict(evaluate(p, keys)).outcome, "preserved")

    def test_retargeted_effect_is_violated(self):
        p, keys = build(executed_resource="repo:app/.env")
        r = verdict(evaluate(p, keys))
        self.assertEqual((r.outcome, r.invariant), ("violated", "I2"))

    def test_tampering_is_unresolved(self):
        p, keys = build()
        p["effects"][0]["executed"]["resource"] = "repo:app/src/other.ts"
        r = verdict(evaluate(p, keys))
        self.assertEqual((r.outcome, r.invariant), ("unresolved", "I7"))

    def test_key_refuses_wrong_kind(self):
        host = sdk.Key.generate("host-1", ["host"])
        with self.assertRaises(ValueError):
            host.sign(sdk.mandate("m-x", "user:alice", sdk.claims(["*"], ["*"], "read", exp=T)))

    def test_builders_validate(self):
        with self.assertRaises(ValueError):
            sdk.claims(["fs.read"], ["*"], "unbounded", exp=T)
        with self.assertRaises(ValueError):   # actor required for high-impact effects
            sdk.invocation("i", "m", "a", T, "mail.send", "mail:x", "external_send")

    def test_pem_round_trip(self):
        k = sdk.Key.generate("k", ["host"])
        k2 = sdk.Key.from_pem(k.to_pem(), "k", ["host"])
        self.assertEqual(k.public_entry(), k2.public_entry())


class SuiteTest(unittest.TestCase):
    @unittest.skipUnless(os.path.isdir(VECTORS), "conformance vectors not present")
    def test_conformance_suite(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["check-suite", VECTORS])
        self.assertEqual(code, 0, out.getvalue())


class CliTest(unittest.TestCase):
    def test_verify_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, expected in (("ok", 0), ("bad", 1)):
                p, keys = build(executed_resource=None if name == "ok" else "repo:app/.env")
                pf, kf = os.path.join(tmp, name + ".json"), os.path.join(tmp, name + "-keys.json")
                json.dump(p, open(pf, "w"))
                json.dump(keys, open(kf, "w"))
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["verify", pf, "--keys", kf]), expected)

    def test_keygen_and_sign(self):
        with tempfile.TemporaryDirectory() as tmp:
            prefix = os.path.join(tmp, "issuer-1")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["keygen", "--kid", "issuer-1", "--roles", "issuer", "--out", prefix]), 0)
            self.assertEqual(os.stat(prefix + ".key.pem").st_mode & 0o777, 0o600)
            obj = os.path.join(tmp, "m.json")
            json.dump(sdk.mandate("m-1", "user:alice", sdk.claims(["*"], ["*"], "read", exp=T)), open(obj, "w"))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main(["sign", obj, "--key", prefix + ".key.pem", "--kid", "issuer-1", "--roles", "issuer"]), 0)
            self.assertEqual(json.loads(out.getvalue())["proof"]["kid"], "issuer-1")


if __name__ == "__main__":
    unittest.main()


class NumberRuleTest(unittest.TestCase):
    """Spec 12.1: numbers outside the I-JSON range are malformed; strict parsing rejects inexact literals."""

    def test_canon_range(self):
        from amep_protocol import Malformed, canon
        self.assertEqual(canon({"n": 2 ** 53 - 1}), b'{"n":9007199254740991}')
        with self.assertRaises(Malformed):
            canon({"n": 2 ** 53})

    def test_parse_strict(self):
        from amep_protocol import Malformed, parse_strict
        with self.assertRaises(Malformed):
            parse_strict('{"amount": 1200.0000000000000001}')
        with self.assertRaises(Malformed):
            parse_strict('{"amount": 1e400}')
        self.assertEqual(parse_strict('{"a": 1200.00, "b": 0.1, "c": 1.5e3}'), {"a": 1200.0, "b": 0.1, "c": 1500.0})

    def test_unsafe_integer_is_unresolved(self):
        packet, keys = build()
        packet["invocations"][0]["x-ticket"] = 9007199254740993
        v = verdict(evaluate(packet, keys))
        self.assertEqual((v.outcome, v.invariant), ("unresolved", "I7"))
        self.assertIn("I-JSON range", v.reason)


class VerdictStatementTest(unittest.TestCase):
    """Spec 10.8: verdict records as in-toto statements, signed in DSSE envelopes."""

    def _packet(self):
        here = os.path.dirname(os.path.abspath(__file__))
        f = os.path.join(here, "..", "..", "..", "vectors", "must-reject", "payment-over-the-per-call-limit-without-approval.json")
        if not os.path.exists(f):
            self.skipTest("conformance vectors not present")
        v = json.load(open(f))
        keys = json.load(open(os.path.join(os.path.dirname(f), "..", "keys.json")))
        data = json.dumps(v["packet"]).encode()
        return data, keys

    def test_statement_names_packet_verdict_blame(self):
        from amep_protocol import evaluate_text, verdicts
        data, keys = self._packet()
        st = verdicts.statement(data, keys, evaluate_text(data.decode(), keys))
        self.assertEqual(st["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(st["predicateType"], verdicts.PREDICATE_TYPE)
        self.assertEqual(st["subject"][0]["digest"]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(st["predicate"]["verdict"], {"outcome": "violated", "invariant": "I2", "blame": "agent", "gaps": []})

    def test_envelope_round_trip_and_tamper(self):
        from amep_protocol import evaluate_text, verdicts
        from cryptography.hazmat.primitives import serialization
        data, keys = self._packet()
        k = sdk.Key.generate("verifier-1", ["observer"])
        env = verdicts.sign_envelope(verdicts.statement(data, keys, evaluate_text(data.decode(), keys)), k._key, k.kid)
        pub = {k.kid: k.public_entry()["x"]}
        self.assertEqual(verdicts.verify_envelope(env, pub)["predicate"]["verdict"]["outcome"], "violated")
        bad = dict(env, payload=base64.b64encode(base64.b64decode(env["payload"]).replace(b"violated", b"preserved")).decode())
        with self.assertRaises(ValueError):
            verdicts.verify_envelope(bad, pub)
        with self.assertRaises(ValueError):
            verdicts.verify_envelope(env, {k.kid: sdk.Key.generate("x", ["observer"]).public_entry()["x"]})
        # the JavaScript implementation verifies the Python signature
        node = shutil.which("node")
        if node:
            d = tempfile.mkdtemp()
            json.dump(env, open(os.path.join(d, "env.json"), "w")); json.dump(pub, open(os.path.join(d, "pub.json"), "w"))
            here = os.path.dirname(os.path.abspath(__file__))
            r = subprocess.run([node, os.path.join(here, "..", "..", "..", "tools", "verify_verdict.mjs"),
                                os.path.join(d, "env.json"), os.path.join(d, "pub.json")], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("verified: violated I2", r.stdout)


class SvrStatementTest(unittest.TestCase):
    """The same verdict as an in-toto Simple Verification Result (SVR v0.2)."""

    def _load(self, sub, name):
        here = os.path.dirname(os.path.abspath(__file__))
        f = os.path.join(here, "..", "..", "..", "vectors", sub, name)
        if not os.path.exists(f):
            self.skipTest("conformance vectors not present")
        keys = json.load(open(os.path.join(here, "..", "..", "..", "vectors", "keys.json")))
        return json.dumps(json.load(open(f))["packet"]).encode(), keys

    def test_preserved_violated_and_unresolved(self):
        from amep_protocol import SPEC_VERSION, canon, evaluate_text, verdicts
        positive = os.listdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "vectors", "positive"))
        cases = [("positive", sorted(positive)[0], [verdicts.SVR_PRESERVED]),
                 ("must-reject", "payment-over-the-per-call-limit-without-approval.json", []),
                 ("must-reject", "missing-effect-receipt.json", [])]
        for sub, name, props in cases:
            data, keys = self._load(sub, name)
            res = evaluate_text(data.decode(), keys)
            s = verdicts.svr_statement(data, keys, res, "https://example.com/v", "2026-11-22T00:00:00Z")
            self.assertEqual(s["predicateType"], "https://in-toto.io/attestation/svr/v0.2")
            self.assertEqual(s["predicate"]["properties"], props, name)
            self.assertEqual(s["predicate"]["timeCreated"], "2026-11-22T00:00:00Z")
            self.assertEqual(s["predicate"]["verifier"]["id"], "https://example.com/v")
            pol = s["predicate"]["verifier"]["policies"]
            self.assertEqual(pol[0]["digest"]["sha256"], hashlib.sha256(canon(keys)).hexdigest())
            self.assertEqual(pol[1]["name"], f"amep-{SPEC_VERSION}")
            self.assertEqual(s["subject"], verdicts.statement(data, keys, res)["subject"])

    def test_default_time_is_rfc3339_utc_and_svr_envelopes_verify(self):
        import re
        from amep_protocol import evaluate_text, verdicts
        data, keys = self._load("must-reject", "payment-over-the-per-call-limit-without-approval.json")
        s = verdicts.svr_statement(data, keys, evaluate_text(data.decode(), keys), "https://example.com/v")
        self.assertRegex(s["predicate"]["timeCreated"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        k = sdk.Key.generate("verifier-1", ["observer"])
        env = verdicts.sign_envelope(s, k._key, k.kid)
        pub = {k.kid: k.public_entry()["x"]}
        with self.assertRaises(ValueError):   # by default only AMEP verdict statements are accepted
            verdicts.verify_envelope(env, pub)
        both = (verdicts.PREDICATE_TYPE, verdicts.SVR_TYPE)
        self.assertEqual(verdicts.verify_envelope(env, pub, both)["predicateType"], verdicts.SVR_TYPE)


class Holds(unittest.TestCase):
    """Spec 7.6 rule 6 (v0.3): a call with an unknown outcome is held in verifier state until a later packet resolves it."""
    CASE = os.path.join(HERE, "..", "..", "..", "interop", "finos-aigf", "case-421-family-office")

    def load(self, name):
        with open(os.path.join(self.CASE, name)) as fh:
            return json.load(fh)

    def test_lost_instruction_is_held_at_its_reserve(self):
        st = self.load("state.json")
        evaluate(self.load("4-lost-response.packet.json"), self.load("keys.json"), state=st)
        self.assertEqual(st, self.load("8.state.json"))   # the same state the JavaScript verifier writes

    def test_a_resolved_instruction_releases_its_hold(self):
        st = self.load("9.state.json")
        r = verdict(evaluate(self.load("9-next-batch-reconciled.packet.json"), self.load("keys.json"), state=st))
        self.assertEqual((r.outcome, r.invariant), ("preserved", "-"))
        self.assertEqual(st["held"], {})

    def test_without_a_reserve_the_hold_is_unknown(self):
        with open(os.path.join(VECTORS, "must-reject", "period-limit-carried-across-packets-in-verifier-state.json")) as fh:
            v = json.load(fh)
        with open(os.path.join(VECTORS, "keys.json")) as fh:
            keys = json.load(fh)
        p = {**v["packet"], "effects": []}
        st = json.loads(json.dumps(v["state"]))
        evaluate(p, keys, state=st)
        (hold,) = st["held"].values()
        self.assertEqual(hold, {"invocation": "i-1", "amounts": {"m-1|iso4217:EUR|2592000|0": None}})

    def test_malformed_state_is_unresolved(self):
        r = verdict(evaluate(self.load("1-within-mandate.packet.json"), self.load("keys.json"),
                             state={**self.load("state.json"), "held": {"d": {"invocation": "i-x", "amounts": {"k": 5}}}}))
        self.assertEqual((r.outcome, r.invariant), ("unresolved", "I7"))
