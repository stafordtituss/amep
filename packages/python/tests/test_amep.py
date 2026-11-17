"""Tests for amep-protocol. Run: python -m unittest discover -s packages/python/tests"""
import contextlib
import io
import json
import os
import sys
import tempfile
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
