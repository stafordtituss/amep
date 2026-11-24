// Builds the AMEP packet for the protect-mcp fixture run (ScopeBlind/scopeblind-gateway#31): a mandate and the two
// invocations the quickstart's receipts decide on, bound by args_digest. Deterministic TEST keys.
// Run from the repo root:  node interop/protect-mcp/make-packet.mjs
//
// The mandate is deliberately wider than the gateway's starter policy (it allows pushing to the origin), so both calls
// are within authority, and the result turns only on what the evidence shows about execution.
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
const I = testKey("principal-1", ["issuer"]), H = testKey("agent-host-1", ["host"]);
const m = I.sign(sdk.mandate("m-1", "user:quickstart", sdk.claims(["repo.read", "repo.push"],
  ["repo:file/*", "repo:git/origin/*"], "external_send", "2026-12-31T00:00:00Z")), { v: 2 });
const a = H.sign(sdk.interpretation("a-1", "protect-mcp", "0.32.5"), { v: 2 });
// The two calls of the pinned quickstart, with the exact tool inputs it evaluates.
const read = { path: "README.md" }, push = { command: "git push --" + "force origin main" };
const i1 = H.sign(sdk.invocation("i-1", "m-1", "a-1", "2026-11-24T15:42:59Z", "repo.read", "repo:file/README.md", "read",
  { argsDigest: sdk.argsDigest(read) }), { v: 2 });
const i2 = H.sign(sdk.invocation("i-2", "m-1", "a-1", "2026-11-24T15:43:00Z", "repo.push", "repo:git/origin/main", "external_send",
  { actor: "agent:quickstart", argsDigest: sdk.argsDigest(push) }), { v: 2 });
writeFileSync(join(HERE, "packet.json"), JSON.stringify(sdk.packet([m, a, i1, i2], { amepVersion: "0.3" }), null, 1) + "\n");
writeFileSync(join(HERE, "keys.json"), JSON.stringify(keyset(I, H), null, 1) + "\n");
console.log(`args_digest i-1 ${sdk.argsDigest(read)}\nargs_digest i-2 ${sdk.argsDigest(push)}`);
