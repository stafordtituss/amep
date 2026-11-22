#!/usr/bin/env node
// amep-conformance: test any AMEP implementation, and any execution-record format, against AMEP.
//
//   amep-conformance verify --cmd "<verifier command>" [--suite DIR ...] [--name N --version V] [--json FILE] [--md FILE]
//       Runs every conformance vector through the verifier under test and reports agreement, suite by suite.
//       Placeholders in --cmd: {packet} {keys} {state}. Example (the reference Python tool):
//         amep-conformance verify --cmd "amep-protocol verify {packet} --keys {keys} {state} --json"
//
//   amep-conformance import RECORD.json --map TOOLMAP.json [--profile aer1] [--expected-id ID]
//                    [--packet AMEP_PACKET.json --keys KEYS.json [--invocation ID]]
//       Checks a record in another format by that format's own rules, maps it to an AMEP effect, and reports what
//       AMEP needs that the record does not carry. With --packet, signs the mapped effect as the importer and gives
//       the AMEP verdict for the call.
//
//   amep-conformance profiles        lists the import profiles
// Exit status: verify 0 when every vector agrees; import 0 when the record imports (and, with --packet, the verdict is
// preserved), 1 otherwise; 3 on usage errors.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { parseStrict } from "@stafordtituss/amep/core";
import { Key } from "@stafordtituss/amep";
import { loadSuite, markdownReport, verifyImplementation, TOOL_VERSION } from "../src/verify.mjs";
import { PROFILES, importRecord, evaluateImported } from "../src/import.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const DEFAULT_SUITES = ["vectors", "interop/approval-path-attacks", "interop/w3c-agent-identity/delegation-continuity"].map(d => join(REPO, d));
const load = p => parseStrict(readFileSync(p, "utf8"));

async function main(argv) {
  const [cmd, ...rest] = argv;
  const { values: o, positionals: pos } = parseArgs({ args: rest, allowPositionals: true, options: {
    cmd: { type: "string" }, suite: { type: "string", multiple: true }, name: { type: "string" }, version: { type: "string" },
    json: { type: "string" }, md: { type: "string" }, map: { type: "string" }, profile: { type: "string" },
    "expected-id": { type: "string" }, packet: { type: "string" }, keys: { type: "string" }, invocation: { type: "string" },
    quiet: { type: "boolean" } } });
  switch (cmd) {
    case "verify": {
      if (!o.cmd) throw new Usage("verify needs --cmd");
      const suites = (o.suite?.length ? o.suite : DEFAULT_SUITES).map(loadSuite);
      const r = await verifyImplementation({ cmd: o.cmd, suites, name: o.name, version: o.version,
        onProgress: o.quiet ? undefined : (s, f, ok) => { if (!ok) process.stderr.write(`  miss  ${s}/${f}\n`); } });
      for (const s of r.suites) console.log(`${s.name.padEnd(28)} ${String(s.agree).padStart(4)}/${s.vectors}   positive ${s.positive.agree}/${s.positive.vectors}, must-reject ${s.must_reject.agree}/${s.must_reject.vectors}   sha256 ${s.sha256.slice(0, 16)}`);
      console.log(`overall: ${r.totals.agree}/${r.totals.vectors} verdicts agree`);
      if (o.json) writeFileSync(o.json, JSON.stringify(r, null, 1));
      if (o.md) writeFileSync(o.md, markdownReport(r) + "\n");
      return r.totals.agree === r.totals.vectors ? 0 : 1;
    }
    case "import": {
      if (!pos[0]) throw new Usage("import needs a record file");
      const record = load(pos[0]);
      const map = o.map ? load(o.map) : { tools: {} };
      const packet = o.packet ? load(o.packet) : null;
      const out = importRecord(record, { profile: o.profile, map, expectedId: o["expected-id"],
        invocations: packet?.invocations ?? [], invocationId: o.invocation });
      console.log(`profile ${out.profile}: format checks ${out.integrity.verdict} (id ${out.integrity.id_verdict})`);
      for (const c of out.integrity.checks) console.log(`  ${c.pass ? "ok  " : "FAIL"} ${c.rule}`);
      if (out.effect) console.log(`mapped to AMEP: ${out.effect.executed.action} ${out.effect.executed.resource} (${out.effect.executed.effect}), assurance ${out.effect.assurance}, binding ${out.mapping.binding}`);
      else console.log(`not imported: ${out.not_imported}`);
      if (out.mapping.conflict) console.log(`warning: ${out.mapping.conflict}`);
      console.log("what AMEP needs that this record does not carry:");
      for (const g of out.gaps) console.log(`  [${g.status}] ${g.need}: ${g.detail}`);
      let code = out.effect ? 0 : 1;
      if (packet && out.effect) {
        if (!o.keys) throw new Usage("--packet needs --keys");
        const importer = Key.generate("importer-1", ["observer"]);
        const ev = evaluateImported(packet, load(o.keys), [out], importer);
        console.log(`AMEP verdict for the call: ${ev.verdict.outcome} ${ev.verdict.invariant} (${ev.verdict.reason})`);
        code = ev.verdict.outcome === "preserved" ? 0 : 1;
      }
      if (o.json) writeFileSync(o.json, JSON.stringify(out, null, 1));
      return code;
    }
    case "profiles":
      for (const p of Object.values(PROFILES)) console.log(`${p.id}\t${p.title}`);
      return 0;
    case "version":
      console.log(TOOL_VERSION); return 0;
    default:
      throw new Usage("commands: verify, import, profiles, version");
  }
}

class Usage extends Error {}
main(process.argv.slice(2)).then(c => process.exit(c), e => { console.error(e instanceof Usage ? `usage: ${e.message}` : `error: ${e.message}`); process.exit(3); });
