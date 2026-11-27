#!/bin/sh
# Runs every protect-mcp fixture through the AMEP profile. From the repo root: sh interop/protect-mcp/run-all.sh
set -u
K=deb516bdd67886e150fea0da92946ec1caa9f19d168e349879f02e9695bae78c   # ScopeBlind quickstart issuer key
C=$(cat interop/protect-mcp/fixtures/constructed/issuer-key.txt)     # constructed test key
run() { echo "== $1 (packet $3)"; node packages/conformance/bin/amep-conformance.mjs import "$1" --profile protect-mcp \
  --map interop/protect-mcp/toolmap.json --issuer-key "$2" --packet "$3" --keys "$4" | grep -E "format checks|AMEP decision|AMEP verdict|binding to|phase of"; }
P=interop/protect-mcp/packet.json; PK=interop/protect-mcp/keys.json; D=interop/protect-mcp/fixtures
for f in 1-allow 2-deny 3-deny-altered-to-allow; do run $D/$f.json $K $P $PK; done
for f in 4-missing-canonical-marker 5-post-execution-receipt 6-allow-resigned; do run $D/constructed/$f.json $C $P $PK; done
for p in packet-repeated packet-repeated-correlated; do run $D/1-allow.json $K $D/constructed/$p.json $D/constructed/keys.json; done
