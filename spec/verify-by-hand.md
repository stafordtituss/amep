# Verifying AMEP evidence by hand

This page shows how to check a signed AMEP object without any AMEP code, using only standard tools:
- `jq`;
- `xxd`;
- `shasum` (or `sha256sum`);
- OpenSSL 3 or later.

The same steps are in [`tools/verify_by_hand.sh`](../tools/verify_by_hand.sh). That script was checked against the reference verifier on all 972 signed objects in conformance suite v0.3.0, and agrees on 971 of them. The exception is a deliberate edge case, explained in "Limits" below.

Checking signatures by hand establishes that the evidence is genuine and was signed by a key entitled to sign it. A verdict (`preserved`, `violated` or `unresolved`) also needs the claim algebra and invariants (spec Sections 7–10). For that, use a verifier, or the offline browser page `verifier/browser/amep-verify.html`.

## Why signatures, not only hashes

A hash shows that some bytes match a published digest. If the party that serves the bytes also serves the digest, it can replace both. AMEP objects are signed with Ed25519 keys bound to roles (spec 12.5). You check the signature yourself, over a canonical form you compute yourself, against a key set you obtained independently. Nothing depends on trusting a check made upstream.

## The steps

The examples use the conformance vector [`vectors/positive/call-statement-and-receipt-bound-to-the-signed-invocation.json`](../vectors/positive/call-statement-and-receipt-bound-to-the-signed-invocation.json) and its key set `vectors/keys.json`. The packet sits under `.packet`.

```bash
F=vectors/positive/call-statement-and-receipt-bound-to-the-signed-invocation.json
OBJ=$(jq -c '.packet.effects[0]' "$F")
KID=$(jq -r .proof.kid <<<"$OBJ")
```

### 0. Well-formed JSON (spec 12.1)

Duplicate member names make a packet malformed. jq silently keeps the last value, so list jq's paths and look for repeats:

```bash
jq -c --stream 'select(length == 2) | .[0]' "$F" | sort | uniq -d      # must print nothing
jq '[.. | numbers | select(. > 9007199254740991 or . < -9007199254740991)] | length' <<<"$OBJ"   # must be 0
```

### 1. The signing input (spec 12.2)

The input is the RFC 8785 canonical form of the object without its `proof`. For a version-2 proof (`"v": 2`), it is prefixed with `AMEP-v0.3`, a zero byte, the object's `kind`, and a zero byte:

```bash
printf 'AMEP-v0.3\0%s\0' "$(jq -r .kind <<<"$OBJ")" > input.bin       # only when .proof.v is 2
jq -jcS 'del(.proof)' <<<"$OBJ" >> input.bin
```

`jq -jcS` (compact, sorted keys, no trailing newline) produces RFC 8785 bytes when every number is an integer and member names are in the Basic Multilingual Plane, which covers AMEP objects in practice. Otherwise, use a full RFC 8785 implementation (see "Limits").

### 2. The key (spec 12.2, 12.4, 12.5)

```bash
X=$(jq -r --arg k "$KID" '.[$k].x' vectors/keys.json)
jq -r --arg k "$KID" '.[$k].roles[]' vectors/keys.json      # a receipt needs "observer"
```

**Check the role.** The key must hold a role allowed for the object's kind:

| Kind | Allowed roles |
|---|---|
| `mandate`, `revocation`, `status` | `issuer` |
| `delegation`, `intent` | `issuer` or `host` |
| `interpretation`, `invocation`, `decision` | `host` |
| `effect`, `call_statement` | `observer` |
| `approval` | `approver` |
| `finding` | `host` or `observer` |

**Check the key encoding.** `X` must be 64 lowercase hex digits, and must not be a weak point. Clear the top bit of the last byte to get y. Reject the key if y is any of these 32-byte little-endian values:
- `00…00`;
- `01` followed by zeros;
- `ecff…ff7f`;
- `26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05`;
- `c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a`.

Also reject it if y is not below 2^255 − 19. These checks matter: with OpenSSL 3.6, the identity key (`01` followed by zeros) accepts a fixed signature for every message.

### 3. The signature encoding (spec 12.2)

`sig` must be 128 lowercase hex digits. Its first 32 bytes (R) must pass the same point check as the key. Its last 32 bytes (S), read little-endian, must be less than L = 2^252 + 27742317777372353535851937790883648493. In big-endian hex, L is `1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed`.

```bash
SIG=$(jq -r .proof.sig <<<"$OBJ")
printf %s "$SIG" | xxd -r -p > sig.bin
```

### 4. Verify with OpenSSL

The Ed25519 public key, in DER form, is a fixed 12-byte prefix followed by the 32 raw key bytes:

```bash
{ printf 302a300506032b6570032100; printf %s "$X"; } | xxd -r -p > pubkey.der
openssl pkeyutl -verify -pubin -keyform DER -inkey pubkey.der -rawin -in input.bin -sigfile sig.bin
# Signature Verified Successfully
```

On macOS, `/usr/bin/openssl` is LibreSSL and cannot do this. Use an OpenSSL 3 build, for example `/opt/homebrew/bin/openssl`.

### 5. Binding to the call (spec 5.14)

A receipt or call statement that carries `invocation_digest` must match the SHA-256 of the canonical form of the signed invocation it names, **including** that invocation's proof:

```bash
INV=$(jq -c --arg i "$(jq -r .invocation <<<"$OBJ")" '.packet.invocations[] | select(.id == $i)' "$F")
jq -jcS . <<<"$INV" | shasum -a 256          # must equal .invocation_digest
```

### Other digests

These use the same `jq -jcS … | shasum -a 256` pattern:

- **Approval** (spec 5.10): `effect_digest` = the digest of the executed body without `t`, that is `jq -jcS '.executed | del(.t)'`.
- **Arguments** (spec 5.14): `args_digest` = the digest of the tool-call arguments object, that is `jq -jcS '.'` over the arguments.

## Running the script

```bash
OPENSSL=/opt/homebrew/bin/openssl tools/verify_by_hand.sh "$F" '.packet.effects[0]' vectors/keys.json
```

It prints each step and `VERIFIED`, or the first step that fails. On the must-reject vectors it reports, for example:
- `public key is non-canonical or of small order` (the identity-key forgery);
- `signature S is not less than the group order L` (a malleated signature);
- `key host-1 holds roles [host], but a call_statement needs one of: observer`;
- `invocation_digest does not match the signed invocation` (a receipt replayed from another call);
- `duplicate member name at ["effects",0,"executed","resource"]`.

## Limits

- **jq is not a full RFC 8785 canonicalizer.** It keeps non-integer number literals as written (`1.0` stays `1.0`), writes exponents differently, escapes U+007F, and orders member names above U+FFFF by code point rather than by UTF-16 code unit. None of this can produce a false acceptance: different bytes only make a genuine signature fail. In the suite, this happens for exactly one object, the vector `jcs-canonical-form--unicode-keys--floats`, which exists to catch such canonicalizers. If a signature fails, recompute the input with a full RFC 8785 implementation before concluding that it is forged.
- **One object at a time.** These steps check one object. Packet-wide rules, such as unique object ids and a single version, and the evaluation itself, need a verifier.
