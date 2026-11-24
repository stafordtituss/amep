// Writes AMEP's column for a crosswalk, one entry per bundle (vector name): each payment's outcome, deciding invariant,
// blame and named gaps, with the SHA-256 of the exact fixture files it was computed from. Deterministic, so another
// implementation can join on vector name and diff.
//   interop/ap2/verdicts.json           the first families (sdk, synthetic): pinned by others, kept byte-stable
//   interop/ap2/verdicts-checkout.json  the SDK family with checkouts and payment.reference (make_sdk_bundles_v2.py)
//
// Run from the repo root:  node interop/ap2/verdicts.mjs            (rewrite both)
//                          node interop/ap2/verdicts.mjs --check    (exit 1 if either is out of date)
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { analyseBundle } from "../../packages/conformance/src/profiles/ap2.mjs";
import { amepOf } from "./compare.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "..", "packages", "conformance", "test", "fixtures", "ap2");
const OUTPUTS = {
  "verdicts.json": { sdk: "sdk-bundles.json", synthetic: "bundles.json" },
  "verdicts-checkout.json": { "sdk-checkout": "sdk-bundles-v2.json" },
};

let stale = false;
for (const [outName, families] of Object.entries(OUTPUTS)) {
  const OUT = join(HERE, outName);
  const out = { format: "amep-ap2-verdicts-1", verifier: "AMEP ap2 profile (packages/conformance/src/profiles/ap2.mjs) with @stafordtituss/amep from this repository",
    note: "One entry per bundle. 'ap2_checks_failed' lists AP2 artifact checks that failed; 'payments' gives AMEP's result per payment, in order, evaluated payment by payment with verifier state carried (spec 10.7). Gaps name the missing record.",
    families: {} };
  for (const [fam, file] of Object.entries(families)) {
    const bytes = readFileSync(join(FIX, file));
    const fx = JSON.parse(bytes);
    const vectors = {};
    for (const [name, b] of Object.entries(fx.bundles)) {
      const an = analyseBundle(b, fx.trust);
      const failed = [an.open, ...an.payments.map(p => p.closed)].flatMap(x => x.checks.filter(c => !c[1]).map(c => c[0]));
      const a = amepOf(an);
      vectors[name] = { ap2_checks_failed: failed, mapping_problems: a.problems,
        payments: a.results.map((r, i) => ({ payment: i + 1, transaction_id: an.payments[i]?.closed.claims?.transaction_id ?? null,
          outcome: r.outcome, invariant: r.invariant, blame: r.blame, gaps: r.gaps })),
        verdict: { outcome: a.verdict.outcome, invariant: a.verdict.invariant } };
    }
    out.families[fam] = { fixture: `packages/conformance/test/fixtures/ap2/${file}`, fixture_sha256: createHash("sha256").update(bytes).digest("hex"), vectors };
  }
  const text = JSON.stringify(out, null, 1) + "\n";
  if (process.argv.includes("--check")) {
    if (!existsSync(OUT) || readFileSync(OUT, "utf8") !== text) { console.error(`interop/ap2/${outName} is out of date`); stale = true; }
    else console.log(`interop/ap2/${outName} is up to date`);
  } else { writeFileSync(OUT, text); console.log(`wrote ${OUT}`); }
}
if (stale) process.exit(1);
