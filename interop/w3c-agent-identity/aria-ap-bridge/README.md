# ARIA AP and AMEP on one exchange

| | |
|---|---|
| **Title** | Identity and admission (ARIA AP) alongside delegated authority (AMEP) |
| **Author** | Staford Titus Selvaraj (independent) |
| **Date / version** | 2026-11-19 / 0.1 |
| **Status** | Demonstration, for discussion in the W3C Agent Identity Registry Protocol CG |
| **Licence** | Apache 2.0 |

## The question

ARIA AP 1.0 answers: **who sent this request, and did the receiver admit it?** Its signed receipt says the receiver admitted and completed an operation. The November update is explicit about what that does not establish: that a human approved it, that the effect matched what was authorized, or the authorization history behind it.

AMEP answers a different question about the same action: **was it within the authority a person delegated, through every hop?** This demo runs both on one exchange to show that they fit together without changing ARIA.

## The scenario

The CG's hiring use case with one delegation hop, as in [`../delegation-continuity`](../delegation-continuity):

```
H  did:web:acme.example:people:hr-lead     signs an AMEP mandate for the hiring agent
A  did:aria:acme.example:hiring-agent      delegates interview scheduling (AMEP delegation)
B  did:aria:acme.example:scheduling-agent  ARIA credential; sends an ARIA AP signed request
T  did:aria:acme.example:calendar          ARIA credential; admits it and signs an aria-ap-receipt/1
```

Each case is a real ARIA AP 1.0.1 exchange, using `@trustlayer-foundation/aria-sdk` and `aria-ap`: receiver identity, an RFC 9421 signed request, admission, the operation ledger and a signed receipt, which B then verifies. The same exchange is recorded as AMEP evidence and evaluated by the AMEP verifier.

## Results

| Case | ARIA AP | AMEP |
|---|---|---|
| B books the interview slot it was asked to book | allow; receipt `completed`, verified | `preserved` |
| B, steered by injected text, writes to the executive calendar | allow; receipt `completed`, verified | `violated`, I2: resource outside the delegation |
| H revoked the hiring mandate before B acted | allow; receipt `completed`, verified | `violated`, I6: an ancestor was revoked before the action |
| B's own ARIA credential was revoked | deny (`credential_revoked`); receipt `rejected/attempt`, verified | `unresolved`, I7: nothing executed, so there is no effect to check |

ARIA AP is right in every row: B is who it claims to be, and in the first three rows its credential stands and has the scope `calendar:event:create`. What ARIA cannot see is H's authority, which never reaches the receiver. AMEP's verdicts come from that chain. The last row is the reverse: a revoked identity is ARIA's to stop, and it does.

The Python and JavaScript AMEP verifiers agree on all four packets.

## How the two are linked

- **One key, two formats.**
  - B's ARIA holder key also signs B's AMEP invocation (role `host`).
  - T's ARIA holder key also signs T's AMEP effect receipt (role `observer`).
  - The AMEP key id is the ARIA holder key's DID URL, so the agent ARIA identifies is provably the one that acted under the delegation.
- **The ARIA receipt is the backend receipt.**
  - T's AMEP effect carries the ARIA receipt's id and digest in `backend_receipt`.
  - AMEP defines that as assurance level L3: confirmed by the receiving system.
- **The bridge check** in `demo.mjs` confirms, for each executed case, that:
  - the effect names that exact receipt;
  - both are signed by the same key;
  - the receipt's sender is the invocation's actor;
  - the receipt's receiver is the effect's observer.

| ARIA AP 1.0 | AMEP |
|---|---|
| Agent DID and AID credential | `actor` of the invocation; the holder key signs it |
| Receiver DID and credential | `observed_by` of the effect; the holder key signs it |
| `aria-ap-receipt/1`, `completed` | Executed-effect receipt at L3, with the ARIA receipt as `backend_receipt` |
| `aria-ap-receipt/1`, `rejected` (attempt) | No effect: nothing to check against the delegation |
| Scope `calendar:event:create` | Action `calendar.write`; the delegation narrows it to resources under `calendar:interview/req-1042/` |
| `hitlRequired` and the application's approval evidence | AMEP approval bound to the exact effect (not exercised in this demo) |
| Credential revocation (status list) | Revocation of the **authority** (mandate or delegation), signed by the principal |
| Delegation: not supported in 1.0 | Mandate, delegation and attenuation, checked hop by hop |

## Limits

- **Local test issuer, not TrustLayer.** Every run creates a fresh ML-DSA-65 + Ed25519 issuer and signed status list, and both ARIA verifiers trust only that issuer.
  - No credential comes from TrustLayer or agent.bar.
  - Credential ids follow the AID 1.0 schema's `api.aria.bar` URL pattern, but no such credentials exist.
  - Nothing goes over the network.
- **The mapping from the HTTP request to AMEP's action and resource is the demo's own,** done by the host that records the invocation. A deployment would pin it as an AMEP interpretation, as `a-1` does here.
- **AMEP evidence travels separately.** Nothing is added to the ARIA AP wire format. AMEP evaluates after the fact; it does not change ARIA admission.

## Run it

```
npm install
node demo.mjs
```

Requires Node.js 20 or later. The evidence for each case (the ARIA receipt, the AMEP packet and the verdict) is written to `out/`, together with the public test keys.
