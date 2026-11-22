// `amep-conformance verify`: run every conformance vector through any AMEP verifier, in any language, and report how
// many verdicts it gets right, suite by suite, with a reproducible fingerprint of the suites it ran.
//
// The verifier under test is a command template. Placeholders:
//   {packet}  path of a file holding the packet as JSON text (byte-exact for the parser vectors)
//   {keys}    path of the key set
//   {state}   "--state <path>" when the vector carries verifier state across packets, otherwise nothing
// The command prints JSON on stdout: {"outcome": ..., "invariant": ...}, or {"verdict": {"outcome": ..., "invariant": ...}}.
// Both reference command-line tools follow this contract:
//   amep-protocol verify {packet} --keys {keys} {state} --json
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";

/** Split a command template into argv, honouring single and double quotes. No shell is involved. */
export function splitCommand(template) {
  const out = []; let cur = "", q = null, any = false;
  for (const ch of template) {
    if (q) { if (ch === q) q = null; else cur += ch; continue; }
    if (ch === "'" || ch === '"') { q = ch; any = true; continue; }
    if (/\s/.test(ch)) { if (cur || any) out.push(cur); cur = ""; any = false; continue; }
    cur += ch;
  }
  if (q) throw new Error("unbalanced quote in --cmd");
  if (cur || any) out.push(cur);
  return out;
}

/** The vectors of one suite directory (keys.json, positive/, must-reject/), with a SHA-256 over all their bytes. */
export function loadSuite(dir) {
  const keysText = readFileSync(join(dir, "keys.json"), "utf8");
  const h = createHash("sha256").update(keysText);
  const vectors = [];
  for (const sub of ["positive", "must-reject"]) {
    if (!existsSync(join(dir, sub))) continue;
    for (const f of readdirSync(join(dir, sub)).filter(f => f.endsWith(".json")).sort()) {
      const text = readFileSync(join(dir, sub, f), "utf8");
      h.update(`${sub}/${f}\0`).update(text);
      const v = JSON.parse(text);
      vectors.push({ file: `${sub}/${f}`, name: v.name, expect: v.expect, state: v.state,
        packetText: v.packet_text ?? JSON.stringify(v.packet) });
    }
  }
  return { name: basename(resolve(dir)), dir: resolve(dir), keysText, vectors, sha256: h.digest("hex") };
}

function runOne(argvTemplate, files, timeoutMs) {
  const argv = argvTemplate.flatMap(a => a === "{state}" ? (files.state ? ["--state", files.state] : [])
    : [a.replaceAll("{packet}", files.packet).replaceAll("{keys}", files.keys)]);
  return new Promise(res => {
    execFile(argv[0], argv.slice(1), { timeout: timeoutMs, maxBuffer: 16 << 20 }, (err, stdout, stderr) => {
      try {
        const o = JSON.parse(stdout);
        const v = o.verdict ?? o;
        if (typeof v.outcome !== "string") throw new Error("no outcome");
        res({ outcome: v.outcome, invariant: v.invariant ?? "-", reason: v.reason });
      } catch {
        res({ outcome: "error", invariant: "-", reason: (stderr || err?.message || "no JSON on stdout").toString().split("\n")[0].slice(0, 200) });
      }
    });
  });
}

/**
 * Run the suites against a verifier command. Returns a results document: what ran (suite fingerprints), what the
 * implementation got right, and every miss with the expected and actual verdicts.
 */
export async function verifyImplementation({ cmd, suites, name = "unnamed", version = "unknown", timeoutMs = 20_000, onProgress }) {
  const argvTemplate = splitCommand(cmd);
  if (!argvTemplate.length) throw new Error("empty --cmd");
  const tmp = mkdtempSync(join(tmpdir(), "amep-conformance-"));
  const report = { tool: "amep-conformance", tool_version: TOOL_VERSION, ran_at: new Date().toISOString(),
    implementation: { name, version, command: cmd }, suites: [], totals: { vectors: 0, agree: 0 }, misses: [] };
  try {
    for (const s of suites) {
      const keys = join(tmp, "keys.json"); writeFileSync(keys, s.keysText);
      const res = { name: s.name, sha256: s.sha256, vectors: s.vectors.length, agree: 0,
        positive: { vectors: 0, agree: 0 }, must_reject: { vectors: 0, agree: 0 } };
      for (const v of s.vectors) {
        const packet = join(tmp, "packet.json"); writeFileSync(packet, v.packetText);
        let state;
        if (v.state) { state = join(tmp, "state.json"); writeFileSync(state, JSON.stringify(v.state)); }
        const got = await runOne(argvTemplate, { packet, keys, state }, timeoutMs);
        const ok = got.outcome === v.expect.outcome && got.invariant === v.expect.invariant;
        const bucket = v.file.startsWith("positive/") ? res.positive : res.must_reject;
        bucket.vectors++; if (ok) { bucket.agree++; res.agree++; }
        else report.misses.push({ suite: s.name, vector: v.file, name: v.name, expected: v.expect, got });
        onProgress?.(s.name, v.file, ok);
      }
      report.suites.push(res);
      report.totals.vectors += res.vectors; report.totals.agree += res.agree;
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  return report;
}

/** A Markdown summary for the implementation-report issue form. */
export function markdownReport(r) {
  const lines = [
    `**Implementation:** ${r.implementation.name} ${r.implementation.version}`,
    `**Ran:** ${r.ran_at} with amep-conformance ${r.tool_version}`,
    "",
    "| Suite | SHA-256 (first 16) | Positive | Must-reject | Total |",
    "|---|---|---|---|---|",
    ...r.suites.map(s => `| ${s.name} | \`${s.sha256.slice(0, 16)}\` | ${s.positive.agree}/${s.positive.vectors} | ${s.must_reject.agree}/${s.must_reject.vectors} | **${s.agree}/${s.vectors}** |`),
    "",
    `**Overall:** ${r.totals.agree}/${r.totals.vectors} verdicts agree with the expected outcome and deciding invariant.`,
  ];
  if (r.misses.length) {
    lines.push("", "<details><summary>Disagreements</summary>", "", "| Suite | Vector | Expected | Got |", "|---|---|---|---|");
    for (const m of r.misses.slice(0, 200))
      lines.push(`| ${m.suite} | \`${m.vector}\` | ${m.expected.outcome} ${m.expected.invariant} | ${m.got.outcome} ${m.got.invariant} |`);
    lines.push("", "</details>");
  }
  return lines.join("\n");
}

export const TOOL_VERSION = "0.1.0-experimental.1";
