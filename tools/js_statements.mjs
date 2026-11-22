// For tools/compare_verifiers.py: evaluates each packet file in a manifest with the JavaScript reference verifier and
// prints the SHA-256 of the JCS form of its verdict statement (spec 10.8). Usage: node tools/js_statements.mjs MANIFEST
import { readFileSync } from "node:fs";
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { evaluateText, signingInput, canon } from "../packages/js/src/core.mjs";
import { statement } from "../packages/js/src/verdict.mjs";

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
  out[name] = createHash("sha256").update(canon(statement(bytes, keys, res)), "utf8").digest("hex");
}
console.log(JSON.stringify(out));
