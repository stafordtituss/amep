# @stafordtituss/amep (JavaScript)

Verify and produce **AMEP™** (Agentic Mandate Evidence Protocol) evidence: signed records proving that what an AI agent actually did stayed within the authority a person delegated.

Specification and conformance suite: https://github.com/stafordtituss/amep

```
npm install @stafordtituss/amep
```

Node.js 20 or later. No dependencies.

## Verify a packet

```
npx -p @stafordtituss/amep amep-protocol verify packet.json --keys keys.json
```

The exit code is 0 for `preserved`, 1 for `violated` and 2 for `unresolved`. `--json` prints machine-readable results; `--state` and `--state-out` carry approval use and risk budgets across a stream of packets.

```js
import { verifyPacket } from "@stafordtituss/amep";

const { verdict, results } = verifyPacket(packet, keys);
console.log(verdict.outcome, verdict.invariant);
```

## Produce evidence

```js
import { Key, keyset, sdk } from "@stafordtituss/amep";

const issuer = Key.generate("issuer-1", ["issuer", "approver"]);
const host = Key.generate("host-1", ["host"]);
const observer = Key.generate("observer-1", ["observer"]);

const m = issuer.sign(sdk.mandate("m-1", "user:alice",
  sdk.claims(["fs.*"], ["repo:app/*"], "write_local", 1767229200, { denyResources: ["repo:app/secrets/*"] })));
const a = host.sign(sdk.interpretation("a-1", "host_shell", "r9"));
const i = host.sign(sdk.invocation("i-1", "m-1", "a-1", 1767225610, "fs.write", "repo:app/src/auth.ts", "write_local"));
const e = observer.sign(sdk.effect("e-1", "i-1", "hook:host", "L1",
  sdk.effectBody("fs.write", "repo:app/src/auth.ts", "write_local", 1767225611)));

const packet = sdk.packet([m, a, i, e]);
const keys = keyset(issuer, host, observer);
```

A key refuses to sign object kinds its roles don't allow.

## In the browser

`import { evaluate, verdict } from "@stafordtituss/amep/core"` has no Node.js imports. Pass your own signature check (for example WebCrypto Ed25519, verified ahead of time) as the third argument to `evaluate`.

License: Apache 2.0. "AMEP" is a trademark of Staford Titus Selvaraj.
