// Prints the JavaScript reference verifier's full results (every result of every vector, with blame and gaps) as JSON.
// Used by tools/compare_verifiers.py. Usage: node tools/js_results.mjs DIR [DIR ...]
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { createPublicKey, verify as edVerify } from "node:crypto";
import { evaluate, evaluateText, signingInput } from "../packages/js/src/core.mjs";

function sigOk(obj, key) {
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(key.x, "hex")]);
  return edVerify(null, Buffer.from(signingInput(obj), "utf8"), createPublicKey({ key: der, format: "der", type: "spki" }), Buffer.from(obj.proof.sig, "hex"));
}
const out = {};
for (const dir of process.argv.slice(2)) {
  const keys = JSON.parse(readFileSync(join(dir, "keys.json"), "utf8"));
  for (const sub of ["positive", "must-reject"]) {
    if (!existsSync(join(dir, sub))) continue;
    for (const f of readdirSync(join(dir, sub)).filter(f => f.endsWith(".json")).sort()) {
      const v = JSON.parse(readFileSync(join(dir, sub, f), "utf8"));
      const st = v.state ? structuredClone(v.state) : {};
      const res = v.packet_text !== undefined ? evaluateText(v.packet_text, keys, sigOk, [], st) : evaluate(v.packet, keys, sigOk, [], st);
      out[`${dir}/${sub}/${f}`] = res.map(r => ({ id: r.id, outcome: r.outcome, invariant: r.invariant, blame: r.blame ?? null, gaps: r.gaps ?? [], within_window: r.within_window ?? null }));
    }
  }
}
console.log(JSON.stringify(out));
