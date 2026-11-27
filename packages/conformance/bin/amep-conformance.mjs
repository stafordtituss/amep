#!/usr/bin/env node
// amep-conformance: test any AMEP implementation, and any execution-record format, against AMEP.
//
//   amep-conformance verify --cmd "<verifier command>" [--suite DIR ...] [--name N --version V] [--json FILE] [--md FILE]
//       Runs every conformance vector through the verifier under test and reports agreement, suite by suite.
//       Placeholders in --cmd: {packet} {keys} {state}. Example (the reference Python tool):
//         amep-conformance verify --cmd "amep-protocol verify {packet} --keys {keys} {state} --json"
//
//   amep-conformance import RECORD.json --map TOOLMAP.json [--profile aer1] [--expected-id ID]
//                    [--packet AMEP_PACKET.json --keys KEYS.json [--invocation ID]] [--issuer-key HEX]
//       Checks a record in another format by that format's own rules, maps it to an AMEP effect, and reports what
//       AMEP needs that the record does not carry. With --packet, signs the mapped effect as the importer and gives
//       the AMEP verdict for the call. A decision receipt (protect-mcp) is authenticated with --issuer-key, the
//       issuer's Ed25519 public key obtained separately; it yields no effect, and with --packet its decision is
//       re-expressed as an AMEP pre-execution decision for the invocation it binds to by digest.
//
//   amep-conformance import-book BOOK.jsonl [--profile provared] [--map MAP.json] [--json FILE]
//       Checks a whole book of records (a Provared book) by its format's own rules, re-expresses the verified records
//       as AMEP evidence signed by the importer, and gives the AMEP verdict for every action.
//
//   amep-conformance profiles        lists the import profiles
// Exit status: verify 0 when every vector agrees; import 0 when the record imports (and, with --packet, the verdict is
// preserved), 1 otherwise; 3 on usage errors.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { evaluate, parseStrict, verdict } from "@stafordtituss/amep/core";
import { Key, sigOk } from "@stafordtituss/amep";
import { importProvaredBook } from "../src/profiles/provared.mjs";
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
    "issuer-key": { type: "string" },
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
        invocations: packet?.invocations ?? [], invocationId: o.invocation, issuerKey: o["issuer-key"] });
      console.log(`profile ${out.profile}: format checks ${out.integrity.verdict} (id ${out.integrity.id_verdict})`);
      for (const c of out.integrity.checks) console.log(`  ${c.pass ? "ok  " : "FAIL"} ${c.rule}`);
      if (out.effect) console.log(`mapped to AMEP: ${out.effect.executed.action} ${out.effect.executed.resource} (${out.effect.executed.effect}), assurance ${out.effect.assurance}, binding ${out.mapping.binding}`);
      else console.log(`not imported: ${out.not_imported}`);
      if (out.decision) console.log(`AMEP decision: ${out.decision.mode} (${out.decision.phase}) for invocation ${out.decision.invocation}, binding ${out.mapping.binding}`);
      else if (out.mapping.no_decision) console.log(`no AMEP decision: ${out.mapping.no_decision}`);
      else if (out.mapping.unbound && out.integrity.verdict === "pass") console.log(`no AMEP decision: not bound (${out.mapping.binding}): ${out.mapping.unbound}`);
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
      if (packet && out.decision) {
        // The gateway's decision, authenticated above, re-expressed as AMEP evidence signed by the importer (role host,
        // since decisions are host statements). Under spec 10.3 it cannot settle whether the call ran.
        if (!o.keys) throw new Usage("--packet needs --keys");
        const importer = Key.generate("importer-1", ["host"]);
        const pk = { ...packet, decisions: [...(packet.decisions || []), importer.sign(out.decision, { v: 2 })] };
        const results = evaluate(pk, { ...load(o.keys), [importer.kid]: importer.publicEntry() }, sigOk);
        const r = results.find(x => x.id === out.decision.invocation) ?? verdict(results);
        const gap = r.gaps?.[0] ? ` gap ${r.gaps[0].need}` : "";
        console.log(`AMEP verdict for the call: ${r.outcome} ${r.invariant} (${r.reason})${gap}`);
        code = r.outcome === "preserved" ? 0 : 1;
      }
      if (o.json) writeFileSync(o.json, JSON.stringify(out, null, 1));
      return code;
    }
    case "import-book": {
      if (!pos[0]) throw new Usage("import-book needs a book file");
      if (o.profile && o.profile !== "provared") throw new Usage(`unknown book profile ${o.profile}; books: provared`);
      const keys = { issuer: Key.generate("importer-issuer", ["issuer", "approver"]), host: Key.generate("importer-host", ["host"]),
        observer: Key.generate("importer-observer", ["observer"]) };
      const out = importProvaredBook(readFileSync(pos[0], "utf8"), { keys, map: o.map ? load(o.map) : { actions: {} } });
      for (const l of out.lines) {
        console.log(`line ${l.line}: ${l.role ?? l.kinds.join("+")}${l.problems.length ? `  ${l.problems.length} problem(s)` : "  checks pass"}`);
        for (const p of l.problems) console.log(`  FAIL ${p}`);
        for (const p of l.notChecked) console.log(`  not checked: ${p}`);
        for (const p of l.notHandled) console.log(`  not handled: ${p}`);
      }
      if (!out.packet) { console.log("no verified slip: nothing to evaluate"); return 1; }
      const results = evaluate(out.packet, out.keys, sigOk, [], structuredClone(out.state));
      for (const r of results) console.log(`AMEP ${r.id} (line ${out.byInvocation[r.id]}): ${r.outcome} ${r.invariant}${r.blame ? ` blame ${r.blame}` : ""}${r.gaps.length ? ` gaps ${r.gaps.map(g => g.need).join(",")}` : ""}: ${r.reason}`);
      const v = verdict(results);
      console.log(`AMEP verdict for the book: ${v.outcome} ${v.invariant}`);
      console.log("what the import could not express:");
      for (const g of out.gaps) console.log(`  ${g.need}: ${g.detail}`);
      if (o.json) writeFileSync(o.json, JSON.stringify({ ...out, results, verdict: v }, null, 1));
      return out.lines.some(l => l.problems.length) ? 1 : v.outcome === "preserved" ? 0 : 1;
    }
    case "profiles":
      for (const p of Object.values(PROFILES)) console.log(`${p.id}\t${p.title}`);
      console.log("provared\tProvared book (draft-izmaylov-agent-permission-receipts), via import-book");
      return 0;
    case "version":
      console.log(TOOL_VERSION); return 0;
    default:
      throw new Usage("commands: verify, import, import-book, profiles, version");
  }
}

class Usage extends Error {}
main(process.argv.slice(2)).then(c => process.exit(c), e => { console.error(e instanceof Usage ? `usage: ${e.message}` : `error: ${e.message}`); process.exit(3); });
