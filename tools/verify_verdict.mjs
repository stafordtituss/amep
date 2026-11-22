// Check a signed AMEP verdict (a DSSE envelope over an in-toto statement, spec 10.8) with the JavaScript implementation.
// Usage: node tools/verify_verdict.mjs ENVELOPE.json PUBLIC_KEYS.json   (PUBLIC_KEYS: {"keyid": "<64 hex>"})
// Prints the verdict and exits 0 when a signature verifies, 1 otherwise.
import { readFileSync } from "node:fs";
import { verifyEnvelope } from "../packages/js/src/verdict.mjs";

try {
  const stmt = verifyEnvelope(JSON.parse(readFileSync(process.argv[2], "utf8")), JSON.parse(readFileSync(process.argv[3], "utf8")));
  const v = stmt.predicate.verdict;
  console.log(`verified: ${v.outcome} ${v.invariant} (packet sha256 ${stmt.subject[0].digest.sha256.slice(0, 16)}...)`);
} catch (e) {
  console.log(`not verified: ${e.message}`);
  process.exit(1);
}
