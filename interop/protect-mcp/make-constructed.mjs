// Constructed fixtures for the binding and phase rules asked for in Tom Farley's review of stafordtituss/amep#20.
// These are NOT ScopeBlind output: each is a copy of the quickstart's allow receipt (fixtures/1-allow.json) with one
// field changed, re-signed in the same wire format with a deterministic test key ("amep-constructed"), so that only the
// rule under test differs. Run from the repo root:  node interop/protect-mcp/make-constructed.mjs
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash, createPrivateKey, createPublicKey, sign as edSign } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canon } from "../../packages/js/src/core.mjs";
import { Key, keyset } from "../../packages/js/src/node.mjs";
import * as sdk from "../../packages/js/src/sdk.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "fixtures", "constructed");
mkdirSync(OUT, { recursive: true });
const seed = kid => createHash("sha256").update(`amep-test-vector-key-v1:${kid}`).digest();
const pkcs8 = s => createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), s]), format: "der", type: "pkcs8" });
const gw = pkcs8(seed("amep-constructed"));
const gwPub = createPublicKey(gw).export({ format: "der", type: "spki" }).subarray(12).toString("hex");

const base = JSON.parse(readFileSync(join(HERE, "fixtures", "1-allow.json"), "utf8")).payload;
function receipt(change) {
  const payload = { ...structuredClone(base), issuer_id: "amep-constructed", public_key: gwPub };
  change(payload);
  return { payload, signature: { alg: "EdDSA", kid: "amep-constructed", sig: edSign(null, Buffer.from(canon(payload), "utf8"), gw).toString("hex") } };
}
const write = (name, obj) => writeFileSync(join(OUT, name), JSON.stringify(obj, null, 1) + "\n");
write("4-missing-canonical-marker.json", receipt(p => { delete p.payload_digest.canonical; }));
write("5-post-execution-receipt.json", receipt(p => { p.reason = "post_execution_receipt"; }));
write("6-allow-resigned.json", receipt(() => {}));   // control: identical to fixture 1 except the key
writeFileSync(join(OUT, "issuer-key.txt"), gwPub + "\n");

// The repeated call: two invocations with the same arguments as the quickstart's Read. The digest establishes the
// arguments, not which call the receipt decided; only a trusted identifier tells them apart.
const testKey = (kid, roles) => new Key(kid, roles, pkcs8(seed(kid)));
const I = testKey("principal-1", ["issuer"]), H = testKey("agent-host-1", ["host"]);
const m = I.sign(sdk.mandate("m-1", "user:quickstart", sdk.claims(["repo.read"], ["repo:file/*"], "read", "2026-12-31T00:00:00Z")), { v: 2 });
const a = H.sign(sdk.interpretation("a-1", "protect-mcp", "0.32.5"), { v: 2 });
const args = { path: "README.md" };
const inv = (id, t, correlation) => H.sign(sdk.invocation(id, "m-1", "a-1", t, "repo.read", "repo:file/README.md", "read",
  { argsDigest: sdk.argsDigest(args), correlation }), { v: 2 });
write("packet-repeated.json", sdk.packet([m, a, inv("i-1", "2026-11-24T15:42:59Z"), inv("i-1b", "2026-11-24T15:43:30Z")], { amepVersion: "0.3" }));
write("packet-repeated-correlated.json", sdk.packet([m, a,
  inv("i-1", "2026-11-24T15:42:59Z", { tool_use_ref: base.request_id }), inv("i-1b", "2026-11-24T15:43:30Z", { tool_use_ref: "tu-other" })], { amepVersion: "0.3" }));
write("keys.json", keyset(I, H));
console.log(`constructed issuer key ${gwPub}`);
