// Compares AMEP with the Delegation Receipt Protocol's own published vectors (authproof-sdk at 5047798, MIT; see the
// fixture's NOTICE.md) and writes COMPARISON.md. DRP vectors are pre-execution decisions (PERMIT or DENY for a proposed
// action); AMEP judges what executed. For each vector this reports DRP's own receipt checks, where the deciding
// authority comes from, and AMEP's verdict had the action run as proposed, with the verifier-supplied scope adopted
// as authority (a re-expression, labelled as such).
//
// Run from the repo root:  node interop/drp/compare.mjs            (rewrite COMPARISON.md)
//                          node interop/drp/compare.mjs --check    (exit 1 if COMPARISON.md is out of date)
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { createHash, createPrivateKey } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { evaluate, verdict } from "../../packages/js/src/core.mjs";
import { Key, keyset, sigOk } from "../../packages/js/src/node.mjs";
import { analyseVector, claimsOf, CLASS_OF_OPERATION } from "../../packages/conformance/src/profiles/drp.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "..", "packages", "conformance", "test", "fixtures", "drp");
const OUT = join(HERE, "COMPARISON.md");
const testKey = (kid, roles) => {
  const seed = createHash("sha256").update(`amep-test-vector-key-v1:${kid}`).digest();
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  return new Key(kid, roles, createPrivateKey({ key: der, format: "der", type: "pkcs8" }));
};
const I = testKey("drp-importer-issuer", ["issuer"]), H = testKey("drp-importer-host", ["host"]), O = testKey("drp-importer-observer", ["observer"]);
const KEYS = keyset(I, H, O);

/** AMEP's verdict had the proposed action run, with the verifier-supplied scope adopted as the authority. */
export function amepIfExecuted(v, a) {
  if (!a.action) return { na: "the action is free text" };
  if (v.verifierOptions?.maxChainDepth) return { na: "the deciding rule is the verifier's maximum chain depth, not signed authority" };
  const root = v.parentScopeSchema ?? v.verifierOptions?.scopeSchema ?? null;
  if (!root) return { na: "no machine-readable root authority, signed or supplied" };
  const rc = claimsOf(root);
  if (rc.gap) return { na: rc.gap };
  const cls = CLASS_OF_OPERATION[a.action.operation];
  if (!cls) return { na: `operation ${a.action.operation} has no AMEP effect class` };
  const tw = v.receipt.timeWindow, t = v.receipt.issuedAt;
  const objs = [I.sign({ id: "m-1", kind: "mandate", principal: "drp-user", claims: { ...rc.claims, nbf: tw.start, exp: tw.end } }, { v: 2 })];
  let authority = "m-1";
  if (v.parentScopeSchema && a.signedSchema) {
    const cc = claimsOf(a.signedSchema);
    if (cc.gap) return { na: cc.gap };
    objs.push(I.sign({ id: "d-1", kind: "delegation", parent: "m-1", claims: { ...cc.claims, nbf: tw.start, exp: tw.end } }, { v: 2 }));
    authority = "d-1";
  }
  const declared = { action: `drp.${a.action.operation}`, resource: `drp:${a.action.resource}`, effect: cls };
  objs.push(H.sign({ id: "a-1", kind: "interpretation", source: "curated", adapter: "drp-scope", version: "1.0" }, { v: 2 }));
  objs.push(H.sign({ id: "i-1", kind: "invocation", authority_ref: authority, interpretation_ref: "a-1", actor: "drp-agent", t, declared }, { v: 2 }));
  objs.push(O.sign({ id: "e-1", kind: "effect", invocation: "i-1", observed_by: "drp-hypothetical-execution", assurance: "L1",
    executed: { ...declared, released: [], t } }, { v: 2 }));
  const packet = { amep_version: "0.3", mandates: objs.filter(o => o.kind === "mandate"), delegations: objs.filter(o => o.kind === "delegation"),
    interpretations: objs.filter(o => o.kind === "interpretation"), invocations: objs.filter(o => o.kind === "invocation"), effects: objs.filter(o => o.kind === "effect") };
  return { result: verdict(evaluate(packet, KEYS, sigOk)), grants: "grants" in rc.claims || objs.some(o => o.claims && "grants" in o.claims) };
}

export function compare() {
  const rows = [];
  for (const sub of ["positive", "negative"]) for (const f of readdirSync(join(FIX, sub)).filter(x => x.endsWith(".json")).sort()) {
    const v = JSON.parse(readFileSync(join(FIX, sub, f), "utf8"));
    const a = analyseVector(v);
    const problems = [...a.checks.receipt.problems, ...a.checks.chain.flatMap(c => c.problems)];
    const amep = amepIfExecuted(v, a);
    const drp = v.expected.outcome;
    let relation;
    if (amep.na) relation = "not comparable: " + amep.na;
    else if (drp === "PERMIT" && amep.result.outcome === "preserved") relation = "agree";
    else if (drp === "DENY" && amep.result.outcome === "violated") relation = "agree";
    else if (drp === "DENY" && amep.result.outcome === "preserved") relation = "DRP denies on a check AMEP doesn't make: " + (v.expected.denialCode ?? "");
    else relation = "disagree";
    rows.push({ id: `${sub}/${v.id}`, drp, denial: v.expected.denialCode, problems, authority: a.authority, amep, relation, gaps: a.gaps });
  }
  return rows;
}

function render(rows) {
  const cell = r => r.amep.na ? "" : `\`${r.amep.result.outcome}\`${r.amep.result.invariant && r.amep.result.invariant !== "-" ? " " + r.amep.result.invariant : ""}${r.amep.result.blame ? `, blame \`${r.amep.result.blame}\`` : ""}${r.amep.grants ? " (uses grants)" : ""}`;
  const agree = rows.filter(r => r.relation === "agree").length, comparable = rows.filter(r => !r.amep.na).length;
  return [
    "# AMEP beside the Delegation Receipt Protocol's own vectors",
    "",
    "Generated by `node interop/drp/compare.mjs` from the reference SDK's published vectors (Commonguy25/authproof-sdk at `5047798`, MIT; see `packages/conformance/test/fixtures/drp/NOTICE.md`). `--check` fails if this file is out of date.",
    "",
    "DRP's vectors are **pre-execution** decisions: PERMIT or DENY for a proposed action. AMEP judges **what executed**. The AMEP column asks the matching question: had the action run as proposed, would AMEP find it within authority? For it, the scope the DRP verifier was given is adopted as authority, re-expressed and signed by the importer. In these vectors that scope is supplied at check time, not signed by the user.",
    "",
    `Every receipt was first checked by DRP's own (legacy) rule: the P-256 signature, the receipt id, and for sub-receipts the orchestrator binding. Problems found: ${rows.filter(r => r.problems.length).map(r => r.id).join(", ") || "none"}.`,
    "",
    "| Vector | DRP | DRP receipt checks | Deciding authority | AMEP, had it run | Relation |",
    "|---|---|---|---|---|---|",
    ...rows.map(r => `| \`${r.id}\` | ${r.drp}${r.denial ? ` (${r.denial})` : ""} | ${r.problems.length ? r.problems.join("; ") : "pass"} | ${r.authority} | ${cell(r)} | ${r.relation} |`),
    "",
    `**Summary:** of ${rows.length} vectors, ${comparable} can be compared. AMEP agrees with DRP's decision on ${agree} of those ${comparable}; the others are checks DRP makes before execution that AMEP doesn't make after it (see the README).`,
  ].join("\n") + "\n";
}

if (fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const text = render(compare());
  if (process.argv.includes("--check")) {
    const ok = readFileSync(OUT, "utf8") === text;
    console.log(ok ? "COMPARISON.md is up to date" : "COMPARISON.md is out of date: run node interop/drp/compare.mjs");
    process.exit(ok ? 0 : 1);
  }
  writeFileSync(OUT, text);
  console.log(`wrote ${OUT}`);
}
