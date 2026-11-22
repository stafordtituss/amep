// Check a signed AMEP verdict or SVR (a DSSE envelope over an in-toto statement, spec 10.8) with the JavaScript implementation.
// Usage: node tools/verify_verdict.mjs ENVELOPE.json PUBLIC_KEYS.json   (PUBLIC_KEYS: {"keyid": "<64 hex>"})
// Prints the verdict and exits 0 when a signature verifies, 1 otherwise.
import { readFileSync } from "node:fs";
import { verifyEnvelope, PREDICATE_TYPE, SVR_TYPE } from "../packages/js/src/verdict.mjs";

try {
  const stmt = verifyEnvelope(JSON.parse(readFileSync(process.argv[2], "utf8")), JSON.parse(readFileSync(process.argv[3], "utf8")), [PREDICATE_TYPE, SVR_TYPE]);
  const p = stmt.predicate, digest = stmt.subject[0].digest.sha256.slice(0, 16);
  if (p.verdict) console.log(`verified: ${p.verdict.outcome} ${p.verdict.invariant} (packet sha256 ${digest}...)`);
  else console.log(`verified SVR: properties ${JSON.stringify(p.properties)} (packet sha256 ${digest}...)`);
} catch (e) {
  console.log(`not verified: ${e.message}`);
  process.exit(1);
}
