"""amep-protocol command-line tool.

  amep-protocol verify PACKET --keys KEYS [--state FILE] [--state-out FILE] [--protected PATH ...] [--json]
  amep-protocol check-suite DIR
  amep-protocol keygen --kid KID --roles issuer,approver --out PREFIX
  amep-protocol sign OBJECT --key PEM --kid KID [--roles ROLES]
  amep-protocol approval-digest BODY
  amep-protocol version

Exit codes for verify: 0 preserved, 1 violated, 2 unresolved, 3 usage or input error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import SPEC_VERSION, __version__, sdk
from .core import approval_digest, evaluate, parse_strict, verdict

EXIT = {"preserved": 0, "violated": 1, "unresolved": 2}


def _load(path):
    with (sys.stdin if path == "-" else open(path, encoding="utf-8")) as f:
        return parse_strict(f.read())   # spec 12.1: rejects number literals a double cannot represent exactly


def cmd_verify(a):
    packet, keys = _load(a.packet), _load(a.keys)
    state = _load(a.state) if a.state else {}
    results = evaluate(packet, keys, extra_protected=tuple(a.protected or ()), state=state)
    v = verdict(results)
    if a.state_out:
        with open(a.state_out, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=1)
    if a.json:
        print(json.dumps({"verdict": {"outcome": v.outcome, "invariant": v.invariant, "reason": v.reason},
                          "results": [r.__dict__ for r in results]}, indent=1))
    else:
        for r in results:
            print(f"{r.invocation}\t{r.outcome}\t{r.invariant}\t{r.reason}")
        print(f"verdict: {v.outcome} {v.invariant}")
    return EXIT[v.outcome]


def cmd_check_suite(a):
    keys = _load(os.path.join(a.dir, "keys.json"))
    n = ok = 0
    for sub in ("positive", "must-reject"):
        for f in sorted(os.listdir(os.path.join(a.dir, sub))):
            if not f.endswith(".json"):
                continue
            v = _load(os.path.join(a.dir, sub, f))
            r = verdict(evaluate(v["packet"], keys, state=v.get("state")))
            n += 1
            if (r.outcome, r.invariant) == (v["expect"]["outcome"], v["expect"]["invariant"]):
                ok += 1
            else:
                print(f"FAIL {sub}/{f}: got {r.outcome}/{r.invariant} ({r.reason})")
    print(f"amep-protocol {__version__} agrees with expected outcomes on {ok}/{n} vectors")
    return 0 if ok == n and n else 1


def cmd_keygen(a):
    key = sdk.Key.generate(a.kid, [r for r in a.roles.split(",") if r])
    path = a.out + ".key.pem"
    if os.path.exists(path):
        print(f"refusing to overwrite {path}", file=sys.stderr)
        return 3
    key.save(path)
    print(json.dumps({a.kid: key.public_entry()}, indent=1))
    print(f"private key written to {path} (mode 0600); add the entry above to your key set", file=sys.stderr)
    return 0


def cmd_sign(a):
    with open(a.key, "rb") as f:
        key = sdk.Key.from_pem(f.read(), a.kid, [r for r in (a.roles or "").split(",") if r]
                               or list(sdk.ROLES))
    print(json.dumps(key.sign(_load(a.object)), indent=1, ensure_ascii=False))
    return 0


def cmd_digest(a):
    print(approval_digest(_load(a.body)))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="amep-protocol", description="Verify and produce AMEP evidence.")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="evaluate a packet (spec section 10)")
    v.add_argument("packet", help="packet JSON file, or - for stdin")
    v.add_argument("--keys", required=True, help="key set JSON file")
    v.add_argument("--state", help="verifier state from earlier packets (spec 10.7)")
    v.add_argument("--state-out", help="write the updated state here")
    v.add_argument("--protected", action="append", help="extra protected path marker (spec 8.1); repeatable")
    v.add_argument("--json", action="store_true", help="print results as JSON")
    v.set_defaults(fn=cmd_verify)
    c = sub.add_parser("check-suite", help="run a conformance suite directory")
    c.add_argument("dir")
    c.set_defaults(fn=cmd_check_suite)
    k = sub.add_parser("keygen", help="create an Ed25519 key with roles")
    k.add_argument("--kid", required=True)
    k.add_argument("--roles", required=True, help="comma-separated: issuer, host, observer, approver")
    k.add_argument("--out", required=True, help="file prefix; writes PREFIX.key.pem")
    k.set_defaults(fn=cmd_keygen)
    s = sub.add_parser("sign", help="sign an AMEP object")
    s.add_argument("object")
    s.add_argument("--key", required=True, help="PKCS#8 PEM private key")
    s.add_argument("--kid", required=True)
    s.add_argument("--roles", help="comma-separated roles of the key, to refuse kinds it may not sign")
    s.set_defaults(fn=cmd_sign)
    d = sub.add_parser("approval-digest", help="digest of an effect body for an approval (spec 5.10)")
    d.add_argument("body")
    d.set_defaults(fn=cmd_digest)
    ver = sub.add_parser("version")
    ver.set_defaults(fn=lambda a: print(f"amep-protocol {__version__} (AMEP {SPEC_VERSION})") or 0)
    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except (OSError, ValueError, KeyError) as e:
        print(f"amep-protocol: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
