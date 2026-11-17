// AMEP v0.2 reference verifier, Node CLI (no dependencies). Independent of the Python implementation.
// Usage: node verifier/typescript/amep_verifier.mjs vectors            check the conformance suite
//        node verifier/typescript/amep_verifier.mjs --packet p.json keys.json   evaluate one packet
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { createPublicKey, verify as edVerify, createHash } from "node:crypto";
import { evaluate, verdict, canon, stripProof, sha256Hex } from "./amep_core.mjs";

function sigOk(obj, key) {
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(key.x, "hex")]); // Ed25519 SPKI prefix
  const pub = createPublicKey({ key: der, format: "der", type: "spki" });
  return edVerify(null, Buffer.from(canon(stripProof(obj)), "utf8"), pub, Buffer.from(obj.proof.sig, "hex"));
}

// self-test: the pure-JS SHA-256 used by the core must match node:crypto
for (const s of ["", "abc", "café ☕ 😀", "x".repeat(1000)])
  if (sha256Hex(s) !== createHash("sha256").update(s, "utf8").digest("hex")) { console.error("sha256 self-test failed"); process.exit(2); }

if (process.argv[2] === "--packet") {
  const pk = JSON.parse(readFileSync(process.argv[3], "utf8")), keys = JSON.parse(readFileSync(process.argv[4], "utf8"));
  const res = evaluate(pk, keys, sigOk);
  for (const r of res) console.log(`${r.id}\t${r.outcome}\t${r.invariant}\t${r.reason}`);
  const v = verdict(res); console.log(`verdict: ${v.outcome} ${v.invariant}`);
  process.exit(v.outcome === "preserved" ? 0 : 1);
}

const dir = process.argv[2] || "vectors";
const keys = JSON.parse(readFileSync(join(dir, "keys.json"), "utf8"));
let ok = 0, n = 0; const fails = [];
for (const sub of ["positive", "must-reject"]) for (const f of readdirSync(join(dir, sub)).filter(f => f.endsWith(".json")).sort()) {
  const d = JSON.parse(readFileSync(join(dir, sub, f), "utf8")); const r = verdict(evaluate(d.packet, keys, sigOk, [], d.state ? structuredClone(d.state) : {}));
  n++; if (r.outcome === d.expect.outcome && r.invariant === d.expect.invariant) ok++; else fails.push(`${sub}/${f}: got ${r.outcome}/${r.invariant} (${r.reason})`);
}
console.log(`node verifier agrees with expected outcomes on ${ok}/${n} vectors`); if (fails.length) console.log(fails.join("\n"));
process.exit(ok === n ? 0 : 1);
