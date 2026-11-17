# AMEP Profile: PASETO Envelopes (`AMEP-PASETO`)

| | |
|---|---|
| **Document** | `amep-profile-paseto` |
| **Version** | 0.2.0-draft.4 |
| **Status** | Public Draft. Companion to `spec/amep-v0.2.md` (the "core"). |
| **Author** | Staford Titus Selvaraj |

The key words MUST, SHOULD and MAY are used as in BCP 14 (RFC 2119, RFC 8174).

## 1. Purpose

PASETO (Platform-Agnostic Security Tokens) gives versioned, misuse-resistant signed and encrypted tokens. In AMEP it is an **envelope**: a way to move AMEP objects or packets between services, or store them encrypted. It carries no mandate logic of its own and does not attenuate.

**Rule.** An AMEP object carried in PASETO keeps its own `proof` (JCS + Ed25519, core 12). The PASETO signature or encryption protects the envelope in transit. It is **never** a substitute for the object's proof. A verifier MUST unwrap the envelope and then verify the AMEP object exactly as if it had arrived without one.

## 2. Versions and purposes

Only version 4 is used.

| Token | Use in AMEP |
|---|---|
| `v4.public` | Signed envelope (Ed25519) for service-to-service transfer of AMEP objects, packets or decisions, for example from a PDP to a PEP. |
| `v4.local` | Encrypted envelope for storing or transferring AMEP evidence that contains personal data, under a customer-managed key. |

Other versions MUST NOT be used.

## 3. Payload and footer

- **Payload:** the JSON of one AMEP object, or of one packet (core 5.2), encoded as UTF-8. PASETO's own `exp`, `iat` and `aud` claims MAY be added at the top level of the payload, prefixed so they cannot collide with AMEP members. They control acceptance of the **envelope** only.
- **Footer:** `{"kid": "<envelope key id>", "typ": "amep+json", "amep": "0.2"}`.
- **Implicit assertion** (`v4` supports one): the string `amep:` followed by the packet or object `id`, so that an envelope cannot be moved onto a different object.

## 4. Processing

A receiver:

1. verifies (`v4.public`) or decrypts (`v4.local`) the envelope, and checks its PASETO claims;
2. parses the payload as AMEP;
3. verifies every contained AMEP object's proof and signer role (core 12.5), and evaluates it per core 10.

If step 1 fails, the envelope is rejected and nothing inside it is used. If step 3 fails, the usual AMEP outcomes apply (for example `unresolved`, I7). A valid envelope never makes invalid evidence valid.

Envelope keys are separate from AMEP evidence keys. A deployment SHOULD NOT reuse an `issuer`, `host`, `observer` or `approver` key as a PASETO key.

## 5. Security considerations

- Encoding is not encryption: a `v4.public` envelope is readable by anyone who holds it. Use `v4.local` for personal data.
- Envelope expiry is not mandate expiry. Expiry of authority comes only from the AMEP claims.
