# amep-protocol (Python)

Verify and produce **AMEP™** (Agentic Mandate Evidence Protocol) evidence: signed records proving that what an AI agent actually did stayed within the authority a person delegated.

Specification and conformance suite: https://github.com/stafordtituss/amep

```
pip install amep-protocol
```

## Verify a packet

```
amep-protocol verify packet.json --keys keys.json
```

Each invocation gets an outcome and the deciding invariant. The exit code is 0 for `preserved`, 1 for `violated` and 2 for `unresolved`. `--json` prints machine-readable results. `--state` and `--state-out` carry approval use and risk budgets across a stream of packets.

```python
from amep_protocol import evaluate, verdict

results = evaluate(packet, keys)
print(verdict(results).outcome, verdict(results).invariant)
```

## Produce evidence

```python
from amep_protocol import sdk

issuer = sdk.Key.generate("issuer-1", ["issuer", "approver"])
host = sdk.Key.generate("host-1", ["host"])
observer = sdk.Key.generate("observer-1", ["observer"])

m = issuer.sign(sdk.mandate("m-1", "user:alice",
        sdk.claims(["fs.*"], ["repo:app/*"], "write_local", exp=1767229200, deny_resources=["repo:app/secrets/*"])))
a = host.sign(sdk.interpretation("a-1", "host_shell", "r9"))
i = host.sign(sdk.invocation("i-1", "m-1", "a-1", 1767225610, "fs.write", "repo:app/src/auth.ts", "write_local"))
e = observer.sign(sdk.effect("e-1", "i-1", "hook:host", "L1",
        sdk.effect_body("fs.write", "repo:app/src/auth.ts", "write_local", 1767225611)))

packet = sdk.packet(m, a, i, e)
keys = sdk.keyset(issuer, host, observer)
```

A key refuses to sign object kinds its roles don't allow, for example a host key signing a mandate.

## Keys from the command line

```
amep-protocol keygen --kid issuer-1 --roles issuer,approver --out issuer-1
amep-protocol sign mandate.json --key issuer-1.key.pem --kid issuer-1 --roles issuer,approver
```

## Conformance

```
amep-protocol check-suite vectors/
```

License: Apache 2.0. "AMEP" is a trademark of Staford Titus Selvaraj.
