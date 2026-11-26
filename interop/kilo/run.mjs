#!/usr/bin/env node
// A Kilo Code session as AMEP evidence, and one verdict per tool call that anyone can recompute offline.
//   node interop/kilo/run.mjs [--json out.json] [--write-packet]
//
// Inputs: kilo.json (the user's permission config), session.json (a session in the shape of `kilo export`) and
// workspace-observer.json (what a process outside the agent saw change). All three are constructed for the demo;
// see make-session.py. Keys are deterministic test keys, one per party:
//   user              signs the mandate made from kilo.json (in practice: the config as committed and signed)
//   kilo-host         signs Kilo's tool calls and its pre-execution deny decisions
//   kilo-reader       Kilo's own record of a read (the same operator as kilo-host)
//   workspace-observer  the sandbox or build host that owns the workspace: another operator
//   deploy-target     the service a deploy would reach: another operator
import { readFileSync, writeFileSync } from "node:fs";
import { createHash, createPrivateKey } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { digest, evaluate, verdict } from "../../packages/js/src/core.mjs";
import { Key, sigOk } from "../../packages/js/src/index.mjs";
import { claimsFromConfig, importSession } from "../../packages/conformance/src/profiles/kilo.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const J = f => JSON.parse(readFileSync(join(HERE, f), "utf8"));
const config = J("kilo.json"), session = J("session.json"), observed = J("workspace-observer.json");

const testKey = (kid, roles) => {
  const seed = createHash("sha256").update(`amep-test-vector-key-v1:${kid}`).digest();
  return new Key(kid, roles, createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" }));
};
const user = testKey("user", ["issuer"]), host = testKey("kilo-host", ["host"]), reader = testKey("kilo-reader", ["observer"]);
const ws = testKey("workspace-observer", ["observer"]), deploy = testKey("deploy-target", ["observer"]);
const keys = {
  [user.kid]: user.publicEntry(),
  [host.kid]: { ...host.publicEntry(), operator: "kilo-user-machine" },
  [reader.kid]: { ...reader.publicEntry(), operator: "kilo-user-machine" },
  [ws.kid]: { ...ws.publicEntry(), operator: "workspace-host" },
  [deploy.kid]: { ...deploy.publicEntry(), operator: "deploy-target" },
};

// 1. The permission config as the user's mandate. What an allowed command may write is not in kilo.json, so the
//    deployment states it (commandScopes); without it every write by an allowed command is outside the grant.
const { claims, differences } = claimsFromConfig(config.permission, { ceiling: "write_local", exp: "2026-12-31T00:00:00Z",
  commandScopes: { "npm *": ["node_modules/*", "package-lock.json"] } });
const mandate = user.sign({ id: "m-1", kind: "mandate", principal: "user:developer", claims }, { v: 2 });
const interp = host.sign({ id: "a-1", kind: "interpretation", source: "curated", adapter: "kilo-code", version: "b12e612" }, { v: 2 });

// 2. The session's tool calls, and Kilo's own deny decisions.
const { calls, gaps } = importSession(session, { commandEffects: { "npm run deploy*": "external_send" } });
const invocations = calls.map(c => host.sign(c.invocation, { v: 2 }));
const byId = Object.fromEntries(invocations.map(i => [i.id, i]));
const decisions = calls.filter(c => c.decision).map(c => host.sign(c.decision, { v: 2 }));

// 3. What changed, as recorded outside the agent. A read changes nothing, so Kilo's own record of it is the effect.
const effects = [], statements = [];
for (const c of calls) {
  const inv = byId[c.callID], t = new Date(Date.parse(inv.t) + 500).toISOString().replace(/\.\d{3}Z$/, "Z");
  if (c.kilo !== "completed") continue;
  if (inv.declared.action === "fs.read")
    effects.push(reader.sign({ id: `e-${c.callID}`, kind: "effect", invocation: c.callID, observed_by: "kilo", assurance: "L1",
      invocation_digest: digest(inv), executed: { ...inv.declared, released: [], t } }, { v: 2 }));
  (observed.calls[c.callID]?.writes ?? []).forEach((path, n) =>
    effects.push(ws.sign({ id: `e-${c.callID}-${n}`, kind: "effect", invocation: c.callID, observed_by: "workspace-observer",
      assurance: "L2", invocation_digest: digest(inv),
      executed: { action: "fs.write", resource: `file:${path}`, effect: "write_local", released: [], t } }, { v: 2 })));
}
// A call Kilo stopped: Kilo's deny is its own word (spec 10.3). For a file edit, the workspace observer saw no write
// during the call, which is the independent showing that nothing was executed in the workspace.
for (const c of calls) {
  const inv = byId[c.callID];
  if (c.kilo === "completed" || !inv.declared.resource.startsWith("file:") || (observed.calls[c.callID]?.writes ?? []).length) continue;
  statements.push(ws.sign({ id: `c-${c.callID}`, kind: "call_statement", invocation: c.callID, observed_by: "workspace-observer",
    disposition: "not_executed", effect_count: 0, t: inv.t, invocation_digest: digest(inv) }, { v: 2 }));
}
for (const [id, s] of Object.entries(observed.registry_statements ?? {}))
  statements.push(deploy.sign({ id: `c-${id}`, kind: "call_statement", invocation: id, observed_by: "deploy-target",
    disposition: s.disposition, effect_count: 0, t: byId[id].t, invocation_digest: digest(byId[id]) }, { v: 2 }));

const packet = { amep_version: "0.3", mandates: [mandate], interpretations: [interp], invocations, effects, decisions, call_statements: statements };
const run = pk => Object.fromEntries(evaluate(pk, keys, sigOk).map(r => [r.id, r]));
const withStatement = run(packet);
const withoutStatement = run({ ...packet, call_statements: statements.filter(s => s.observed_by !== "deploy-target") });
// Which of a call's effects departed: the evaluation reports the first, by rule; name the effect for the reader.
const departed = c => effects.filter(e => e.invocation === c.callID && !claims.grants.some(g =>
  g.actions.some(p => p === e.executed.action || (p.endsWith("*") && e.executed.action.startsWith(p.slice(0, -1)))) &&
  g.resources.some(p => p === e.executed.resource || (p.endsWith("*") && e.executed.resource.startsWith(p.slice(0, -1)))))).map(e => e.executed.resource);

const rows = calls.map(c => ({ call: c.callID, tool: c.tool, input: c.input, kilo: c.kilo,
  amep: withStatement[c.callID], amep_without_deploy_target: withoutStatement[c.callID],
  outside_grant: withStatement[c.callID].outcome === "violated" ? departed(c) : [] }));
console.log(`Kilo config -> AMEP mandate: ${claims.grants.length} grants, deny ${JSON.stringify(claims.deny_resources ?? [])}`);
for (const d of differences) console.log(`  differs: ${d}`);
for (const g of gaps) console.log(`  gap: ${JSON.stringify(g)}`);
console.log("");
for (const r of rows) {
  console.log(`${r.call}  ${r.tool.padEnd(4)} ${r.input.padEnd(32)} Kilo: ${r.kilo.padEnd(17)} AMEP: ${r.amep.outcome} ${r.amep.invariant} - ${r.amep.reason}${r.amep.blame ? ` (blame ${r.amep.blame})` : ""}${r.outside_grant.length ? `: ${r.outside_grant.join(", ")}` : ""}`);
  if (r.amep_without_deploy_target.outcome !== r.amep.outcome)
    console.log(`${"".padEnd(60)}without the deploy target's record: ${r.amep_without_deploy_target.outcome} ${r.amep_without_deploy_target.invariant} - ${r.amep_without_deploy_target.reason}`);
}
console.log(`\nsession verdict: ${verdict(Object.values(withStatement)).outcome}`);
const arg = process.argv;
if (arg.includes("--write-packet")) {
  writeFileSync(join(HERE, "packet.json"), JSON.stringify(packet, null, 1) + "\n");
  writeFileSync(join(HERE, "keys.json"), JSON.stringify(keys, null, 1) + "\n");
}
if (arg.includes("--json")) writeFileSync(arg[arg.indexOf("--json") + 1], JSON.stringify({ claims, differences, gaps, rows }, null, 1) + "\n");
