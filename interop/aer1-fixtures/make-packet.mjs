// Builds the AMEP gateway packet for the AER-1 RFC 8785 fixture run (stafordtituss/amep#11): the mandate and the
// signed invocation that fixture 1 (receipt 0bc28781, live_price BTC) should bind to by digest. Deterministic TEST keys.
// Run from the repo root:  node interop/aer1-fixtures/make-packet.mjs
import { writeFileSync } from "node:fs";
import { createHash, createPrivateKey } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Key, keyset } from "../../packages/js/src/node.mjs";
import * as sdk from "../../packages/js/src/sdk.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const testKey = (kid, roles) => {
  const seed = createHash("sha256").update(`amep-test-vector-key-v1:${kid}`).digest();
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  return new Key(kid, roles, createPrivateKey({ key: der, format: "der", type: "pkcs8" }));
};
const I = testKey("principal-1", ["issuer"]), H = testKey("gateway-1", ["host"]);
// The caller may read market prices, for the rest of 2026.
const m = I.sign(sdk.mandate("m-1", "user:fixture-caller", sdk.claims(["market.read"], ["market:price/*"], "read", "2026-12-31T00:00:00Z")), { v: 2 });
const a = H.sign(sdk.interpretation("a-1", "mcp:zambo", "4.1.4"), { v: 2 });
// The call fixture 1 records: live_price with {"symbol":"BTC"}, signed by the gateway before the receipt's created_at.
const args = { symbol: "BTC" };
const inv = H.sign(sdk.invocation("i-1", "m-1", "a-1", "2026-11-21T23:55:40Z", "market.read", "market:price/BTC", "read",
  { argsDigest: sdk.argsDigest(args) }), { v: 2 });
writeFileSync(join(HERE, "gateway-packet.json"), JSON.stringify(sdk.packet([m, a, inv], { amepVersion: "0.3" }), null, 1) + "\n");
writeFileSync(join(HERE, "gateway-keys.json"), JSON.stringify(keyset(I, H), null, 1) + "\n");
console.log(`args_digest of ${JSON.stringify(args)}: ${sdk.argsDigest(args)}`);
