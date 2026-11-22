#!/usr/bin/env bash
# Verify one signed AMEP object with standard tools only: jq, xxd, base64, shasum and OpenSSL 3 or later.
# No AMEP code is used. This is the recipe of spec/verify-by-hand.md, as a script.
#
#   tools/verify_by_hand.sh FILE JQ_PATH KEYS
#     FILE     a packet, or a conformance vector (packet under .packet)
#     JQ_PATH  where the signed object is, for example '.packet.effects[0]'
#     KEYS     the key set (spec 12.4), for example vectors/keys.json
#
# Set OPENSSL to an OpenSSL 3+ binary if `openssl` is LibreSSL (as on macOS), for example
#   OPENSSL=/opt/homebrew/bin/openssl tools/verify_by_hand.sh ...
# Exit status 0: the signature verifies, the key holds a role allowed for the object's kind, and any
# invocation_digest matches. Non-zero: it does not (the first failed step is printed).
set -euo pipefail
f=$1; path=$2; keys=$3; OPENSSL=${OPENSSL:-openssl}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $*"; exit 1; }
ok() { echo "  ok  $*"; }
# Reverse the byte order of a hex string (little-endian <-> big-endian), portably.
rev_hex() { printf %s "$1" | fold -w2 | awk '{b[NR]=$0} END{for(i=NR;i>0;i--) printf "%s", b[i]}'; }

# 0. Well-formed I-JSON (spec 12.1). jq keeps the last of two duplicate member names silently, so duplicates are
#    found from jq's stream of paths: a path that occurs twice is a duplicate member.
dups=$(jq -c --stream 'select(length == 2) | .[0]' "$f" | sort | uniq -d | head -1)
[ -z "$dups" ] || fail "duplicate member name at $dups"
obj=$(jq -c "$path" "$f")
[ "$obj" != null ] || fail "no object at $path"
big=$(jq '[.. | numbers | select(. > 9007199254740991 or . < -9007199254740991)] | length' <<<"$obj")
[ "$big" = 0 ] || fail "number outside the I-JSON range (|n| > 2^53 - 1): verifiers would canonicalize it differently"
ok "well-formed I-JSON: no duplicate member names, numbers within 2^53 - 1"
kind=$(jq -r '.kind // ""' <<<"$obj")
kid=$(jq -r '.proof.kid // ""' <<<"$obj")
v=$(jq -r '.proof.v // 1' <<<"$obj")
echo "$kind signed by $kid (proof version $v)"

# 1. The signing input (spec 12.2): the canonical form of the object without its proof, prefixed for v2 proofs
#    by "AMEP-v0.3" NUL kind NUL. `jq -jcS` gives RFC 8785 bytes for objects whose numbers are integers and whose
#    member names are in the Basic Multilingual Plane; if a signature fails, re-check with a full RFC 8785 tool.
if [ "$v" = 2 ]; then printf 'AMEP-v0.3\0%s\0' "$kind" > "$tmp/input"; else : > "$tmp/input"; fi
jq -jcS 'del(.proof)' <<<"$obj" >> "$tmp/input"
ok "signing input: $(wc -c < "$tmp/input" | tr -d ' ') bytes, sha256 $(shasum -a 256 "$tmp/input" | cut -c1-16)..."

# 2. The key: exactly 64 lowercase hex digits, not a non-canonical or small-order point (spec 12.2), and a role
#    permitted for this kind (spec 12.5).
x=$(jq -r --arg k "$kid" '.[$k].x // ""' "$keys")
[[ $x =~ ^[0-9a-f]{64}$ ]] || fail "key $kid not in the key set, or not 64 lowercase hex digits"
P_BE=7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
SMALL="0000000000000000000000000000000000000000000000000000000000000000
0100000000000000000000000000000000000000000000000000000000000000
ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
point_ok() {   # $1: 32-byte encoding in hex; checks y with the sign bit cleared
  local y="${1:0:62}$(printf %02x $((0x${1:62:2} & 0x7f)))"
  grep -qx "$y" <<<"$SMALL" && return 1
  [[ "$(rev_hex "$y")" < "$P_BE" ]]
}
point_ok "$x" || fail "public key is non-canonical or of small order"
ok "public key is canonical and not of small order"
case $kind in
  mandate|revocation|status) need="issuer" ;;
  delegation|intent) need="issuer host" ;;
  interpretation|invocation|decision) need="host" ;;
  effect|call_statement) need="observer" ;;
  approval) need="approver" ;;
  finding) need="host observer" ;;
  *) fail "unknown kind '$kind'" ;;
esac
roles=$(jq -r --arg k "$kid" '.[$k].roles[]?' "$keys")
role_ok=no; for r in $need; do grep -qx "$r" <<<"$roles" && role_ok=yes; done
[ $role_ok = yes ] || fail "key $kid holds roles [$(echo $roles)], but a $kind needs one of: $need"
ok "key holds a role allowed for a $kind ($need)"

# 3. The signature: exactly 128 lowercase hex digits; R canonical and not of small order; S < L (not malleable).
sig=$(jq -r '.proof.sig // ""' <<<"$obj")
[[ $sig =~ ^[0-9a-f]{128}$ ]] || fail "signature is not 128 lowercase hex digits"
point_ok "${sig:0:64}" || fail "signature R is non-canonical or of small order"
L_BE=1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
[[ "$(rev_hex "${sig:64:64}")" < "$L_BE" ]] || fail "signature S is not less than the group order L"
ok "signature encoding is canonical (S < L)"

# 4. OpenSSL verifies Ed25519 over the signing input. The public key is the raw 32 bytes behind the fixed DER
#    prefix of an Ed25519 SubjectPublicKeyInfo.
{ printf 302a300506032b6570032100; printf %s "$x"; } | xxd -r -p > "$tmp/pubkey.der"
printf %s "$sig" | xxd -r -p > "$tmp/sig"
"$OPENSSL" pkeyutl -verify -pubin -keyform DER -inkey "$tmp/pubkey.der" -rawin -in "$tmp/input" -sigfile "$tmp/sig" > "$tmp/out" 2>&1 \
  || fail "signature does not verify ($(head -1 "$tmp/out"))"
ok "OpenSSL: $(head -1 "$tmp/out")"

# 5. Binding (spec 5.14): invocation_digest is the SHA-256 of the canonical form of the signed invocation,
#    including its proof.
want=$(jq -r '.invocation_digest // ""' <<<"$obj")
if [ -n "$want" ]; then
  root=$(jq -e 'has("packet")' "$f" > /dev/null && echo .packet || echo .)
  inv=$(jq -c --arg i "$(jq -r .invocation <<<"$obj")" "$root.invocations[]? | select(.id == \$i)" "$f")
  [ -n "$inv" ] || fail "the invocation it names is not in the packet"
  got=$(jq -jcS . <<<"$inv" | shasum -a 256 | cut -d' ' -f1)
  [ "$got" = "$want" ] || fail "invocation_digest does not match the signed invocation (got $got)"
  ok "invocation_digest matches the signed invocation"
fi
echo "VERIFIED"
