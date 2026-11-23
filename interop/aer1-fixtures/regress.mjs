#!/usr/bin/env node
// Regression check for Brennan Zambo's two AER-1 fixtures.
//
// It reruns the AMEP importer on both fixtures and checks the results that
// EXPECTED.md (committed in 5f59f88, before either side ran them) says must hold:
//   - completed call 0bc28781: six format checks ok, bound to the gateway's
//     invocation by digest, AMEP verdict `preserved`, exit status 0;
//   - refusal 38a410ab: six format checks ok, NOT imported because the record
//     says nothing executed, no AMEP verdict, exit status 1.
// The second is the case that matters: an importer that turns a refusal into an
// executed action looks as if it works and misleads the next auditor.
//
// Inputs are pinned by SHA-256 (the hashes in OUR-RUN.md). If a fixture or the
// tool map changes upstream, the check stops with exit status 2 and says so,
// because the expectations in 5f59f88 were written for those exact bytes.
//
// Usage, from the repository root, after `(cd packages/conformance && npm install)`:
//   node interop/aer1-fixtures/regress.mjs            fetch the pinned inputs
//   node interop/aer1-fixtures/regress.mjs --dir D    use local copies in D
// Exit status: 0 all expectations hold; 1 a regression; 2 an input changed;
// 3 an input could not be fetched.

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const cli = join(root, "packages/conformance/bin/amep-conformance.mjs");

const HUB = "https://rambozambodotdev.gitlab.io/aer1-hub/fixtures/amep/";
const GIST =
  "https://gist.githubusercontent.com/zambodotdev/a70a6df54e8ba89ed780abde108aa5fd/raw/6668e55855c1f24944bd44d0ea6a8306a4c81a6c/";

const INPUTS = {
  "completed-call-0bc28781.json": {
    url: HUB + "completed-call-0bc28781.json",
    sha256: "49f552c1848ec74258e543ca53a11dab5d86607ddf7fc41cc411bad4ad666e70",
  },
  "refusal-38a410ab.json": {
    url: HUB + "refusal-38a410ab.json",
    sha256: "fa5230aa9cb10e940d65d6fc0ad066834c1a17472f4f12ba6a38e96d771c9383",
  },
  "toolmap.json": {
    url: GIST + "toolmap.json",
    sha256: "16231e8bd465a410cb6a53a7502df9cc15146c1d8549bbae1175b0720c6be0e3",
  },
};

const FORMAT_PASS = "profile aer1: format checks pass (id matched)";
const SIX_CHECKS = [
  "ok   id format (Section 3)",
  "ok   created_at valid (Section 6)",
  "ok   provenance class (Section 5)",
  "ok   canonical bytes: canonical base64, strict UTF-8 (Section 4)",
  "ok   output_hash = SHA-256(canonical bytes) (Section 4)",
  "ok   metadata_hash = SHA-256(metadata block) (Section 3.1)",
];

const CASES = [
  {
    name: "completed call 0bc28781",
    file: "completed-call-0bc28781.json",
    args: [
      "--expected-id", "0bc28781-e16a-4232-b05e-ef4f19238e69",
      "--packet", join(here, "gateway-packet.json"),
      "--keys", join(here, "gateway-keys.json"),
    ],
    status: 0,
    contains: [
      FORMAT_PASS,
      ...SIX_CHECKS,
      "mapped to AMEP: market.read market:price/BTC (read), assurance L1, binding digest",
      "AMEP verdict for the call: preserved -",
    ],
    absent: ["not imported"],
  },
  {
    name: "refusal 38a410ab",
    file: "refusal-38a410ab.json",
    args: ["--expected-id", "38a410ab-597e-45e0-9549-0b3bf2916b39"],
    status: 1,
    contains: [
      FORMAT_PASS,
      ...SIX_CHECKS,
      'not imported: the record\'s committed output says the call was not executed (status "payment_required")',
    ],
    absent: ["mapped to AMEP:", "AMEP verdict"],
  },
];

const sha256 = (b) => createHash("sha256").update(b).digest("hex");

async function loadInputs() {
  const i = process.argv.indexOf("--dir");
  const local = i > 0 ? resolve(process.argv[i + 1]) : null;
  const dir = local ?? mkdtempSync(join(tmpdir(), "aer1-fixtures-"));
  for (const [name, pin] of Object.entries(INPUTS)) {
    let bytes;
    if (local) {
      bytes = readFileSync(join(dir, name));
    } else {
      let res;
      try {
        res = await fetch(pin.url);
      } catch (e) {
        console.error(`could not fetch ${pin.url}: ${e.message}`);
        process.exit(3);
      }
      if (!res.ok) {
        console.error(`could not fetch ${pin.url}: HTTP ${res.status}`);
        process.exit(3);
      }
      bytes = Buffer.from(await res.arrayBuffer());
      writeFileSync(join(dir, name), bytes);
    }
    const got = sha256(bytes);
    if (got !== pin.sha256) {
      console.error(
        `input changed: ${name}\n  pinned ${pin.sha256}\n  got    ${got}\n` +
          "The expectations in EXPECTED.md (5f59f88) were written for the pinned bytes. " +
          "Review the new input and write new expectations before rerunning.",
      );
      process.exit(2);
    }
    console.log(`input ${name}: sha256 ${got} (pinned)`);
  }
  return dir;
}

const dir = await loadInputs();
const js = JSON.parse(readFileSync(join(root, "packages/js/package.json"), "utf8"));
const commit = spawnSync("git", ["rev-parse", "--short", "HEAD"], { cwd: root, encoding: "utf8" });
console.log(
  `importer: packages/conformance at ${commit.stdout.trim() || "unknown commit"}, ` +
    `@stafordtituss/amep ${js.version}, Node.js ${process.version}\n`,
);

let failures = 0;
for (const c of CASES) {
  const run = spawnSync(
    process.execPath,
    [cli, "import", join(dir, c.file), "--map", join(dir, "toolmap.json"), ...c.args],
    { cwd: root, encoding: "utf8" },
  );
  const out = (run.stdout ?? "") + (run.stderr ?? "");
  const problems = [];
  if (run.status !== c.status) problems.push(`exit status ${run.status}, expected ${c.status}`);
  for (const s of c.contains) if (!out.includes(s)) problems.push(`missing: ${s}`);
  for (const s of c.absent) if (out.includes(s)) problems.push(`must not appear: ${s}`);
  if (problems.length) {
    failures++;
    console.log(`FAIL ${c.name}`);
    for (const p of problems) console.log(`  ${p}`);
    console.log("  output:\n" + out.replace(/^/gm, "    "));
  } else {
    console.log(`ok   ${c.name} (exit ${run.status})`);
  }
}

console.log(
  failures
    ? `\n${failures} of ${CASES.length} fixtures regressed against EXPECTED.md (5f59f88)`
    : `\nboth fixtures match EXPECTED.md (5f59f88)`,
);
process.exit(failures ? 1 : 0);
