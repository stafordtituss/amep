// For tools/compare_verifiers.py: evaluates each packet file in a manifest with the JavaScript reference verifier and
// prints the SHA-256 of the JCS form of its verdict statement (spec 10.8) and of its SVR. Usage: node tools/js_statements.mjs MANIFEST
import { readFileSync } from "node:fs";
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { evaluateText, signingInput, canon } from "../packages/js/src/core.mjs";
import { statement, svrStatement } from "../packages/js/src/verdict.mjs";

function sigOk(obj, key) {
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(key.x, "hex")]);
  return edVerify(null, Buffer.from(signingInput(obj), "utf8"), createPublicKey({ key: der, format: "der", type: "spki" }), Buffer.from(obj.proof.sig, "hex"));
}
const manifest = JSON.parse(readFileSync(process.argv[2], "utf8"));
const out = {};
for (const [name, m] of Object.entries(manifest)) {
  const bytes = readFileSync(m.packet);
  const keys = JSON.parse(readFileSync(m.keys, "utf8"));
  const res = evaluateText(bytes.toString("utf8"), keys, sigOk, [], m.state ? structuredClone(m.state) : {});
  const h = x => createHash("sha256").update(canon(x), "utf8").digest("hex");
  // the SVR with a fixed verifier id and time, so that the two implementations can be compared byte for byte
  out[name] = [h(statement(bytes, keys, res)), h(svrStatement(bytes, keys, res, "urn:amep:compare", "2026-01-01T00:00:00Z"))];
}
console.log(JSON.stringify(out));
