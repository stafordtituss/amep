#!/usr/bin/env node
// The worked case of "Auditable Claims about AI Agents" (Zhao, Li, Li, Nian, Liu, Zhou and Hu; arXiv:2610.07459, Section 4,
// Tables 3 and 4) encoded as AMEP evidence, one packet per evidence state, with AMEP's verdict.
//   node interop/auditable-claims/run.mjs [--json out.json]
//
// The setting, from the paper: a firm's document agent may read one matter folder, summarize it and email documents.
// Policy P-7 v3: each email with an attachment sent outside example-firm.com must fall within a grant from the
// authorization server that names its recipient and attachment hash, approved by a signed-in person before sending.
// Three writers: the agent (its own log), the authorization server (grant log, the identity team), the mail gateway
// (delivery log, IT), the independent record. The paper's records are constructed for teaching; so are these.
//
// The mapping is AMEP's reading of the paper, not the authors':
//   a grant g, issued by the authorization server for user:alvarez -> an AMEP mandate whose resource names the
//       recipient and the attachment hash, signed by the authorization server's key (operator: the identity team)
//   the agent's standing authority (read the matter folder) -> a mandate without email.send
//   an agent log entry -> an AMEP invocation, signed by the agent's host (operator: the agent team, the audited party)
//   a gateway delivery -> an AMEP effect receipt, signed by the gateway (operator: IT)
// Attachment hashes are elided in the paper ("9f2c...e1"); full values here are derived from those labels.
import { writeFileSync } from "node:fs";
import { createHash, createPrivateKey } from "node:crypto";
import { digest, evaluate, verdict } from "../../packages/js/src/core.mjs";
import { Key, sigOk } from "../../packages/js/src/index.mjs";

const key = (kid, roles) => {
  const seed = createHash("sha256").update(`amep-test-vector-key-v1:${kid}`).digest();
  return new Key(kid, roles, createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" }));
};
const as = key("as.example-firm.com", ["issuer"]), agent = key("doc-agent-host", ["host"]), gateway = key("mail-gateway", ["observer"]);
const keys = {
  [as.kid]: { ...as.publicEntry(), operator: "example-firm:identity-team" },
  [agent.kid]: { ...agent.publicEntry(), operator: "example-firm:agent-team" },
  [gateway.kid]: { ...gateway.publicEntry(), operator: "example-firm:it" },
};
const h = label => createHash("sha256").update(label).digest("hex");
const MARCH_END = "2026-04-01T00:00:00Z";
const mail = (to, hash) => `mail:${to}/sha256:${hash}`;
const standing = as.sign({ id: "m-agent", kind: "mandate", principal: "user:alvarez",
  claims: { actions: ["docs.read", "docs.summarize"], resources: ["matter:folder-1/*"], ceiling: "read", exp: MARCH_END } }, { v: 2 });
const grant = (id, to, hash) => as.sign({ id, kind: "mandate", principal: "user:alvarez",
  claims: { actions: ["email.send"], resources: [mail(to, hash)], ceiling: "external_send", data: ["matter->external"], exp: MARCH_END } }, { v: 2 });
const interp = agent.sign({ id: "a-1", kind: "interpretation", source: "curated", adapter: "doc-agent", version: "2.4.1" }, { v: 2 });
const send = (id, authority, to, hash, t) => agent.sign({ id, kind: "invocation", authority_ref: authority, interpretation_ref: "a-1", t,
  actor: "doc-agent/2.4.1", declared: { action: "email.send", resource: mail(to, hash), effect: "external_send" } }, { v: 2 });
const delivery = (id, inv, to, hash, t) => gateway.sign({ id, kind: "effect", invocation: inv?.id ?? id.replace("e-", "unlogged-"), observed_by: "mail-gateway",
  assurance: "L3", ...(inv ? { invocation_digest: digest(inv) } : {}),
  executed: { action: "email.send", resource: mail(to, hash), effect: "external_send", released: ["matter->external"], t } }, { v: 2 });
const packet = objs => ({ amep_version: "0.3", interpretations: [interp], mandates: [standing], invocations: [], effects: [], ...objs });

const cases = [];
const add = (state, paper, records, pk) => {
  const res = evaluate(pk, keys, sigOk);
  const v = verdict(res);
  cases.push({ state, paper, records, amep: { outcome: v.outcome, invariant: v.invariant, reason: v.reason, blame: v.blame ?? null, gaps: v.gaps ?? [] },
    per_call: res.map(r => ({ id: r.id, outcome: r.outcome, invariant: r.invariant })), packet_sha256: digest(pk) });
};

// A (PRE): configuration only. The tool manifest grants send_email; no transmission is recorded.
add("A", "March claim UNDECIDABLE", "the tool manifest and approval configuration; no send recorded", packet({}));

// B, tx-19: the agent names grant g-5531; the server's grant for the same recipient and hash; the gateway's delivery.
{ const hb = h("9f2c...e1"), g = grant("g-5531", "counsel@example.org", hb), i = send("tx-19", "g-5531", "counsel@example.org", hb, "2026-03-04T10:02:14Z");
  add("B, tx-19", "this email meets P-7", "agent log names g-5531; grant log; gateway delivery with matching recipient and hash",
    packet({ mandates: [standing, g], invocations: [i], effects: [delivery("e-tx-19", i, "counsel@example.org", hb, "2026-03-04T10:02:15Z")] })); }

// C, tx-23: the agent logged only a confirmation in its own chat interface and names no grant; the gateway delivered;
// the server's grant log, complete for the period, holds none covering it. The agent acted under its standing authority.
{ const hc = h("41ab...07"), i = send("tx-23", "m-agent", "press@example.net", hc, "2026-03-06T15:40:05Z");
  add("C, tx-23", "violates P-7; March claim CONTRADICTED", "interface confirmation only; no grant; gateway delivery",
    packet({ invocations: [i], effects: [delivery("e-tx-23", i, "press@example.net", hc, "2026-03-06T15:40:06Z")] })); }

// D, tx-31: the agent log names no grant and lacks the correlation identifier; the server's log for that hour was lost.
// The gateway's delivery cannot be joined to the agent's entry.
{ const hd = h("tx-31 attachment"), i = send("tx-31", "g-lost", "partner@example.com", hd, "2026-03-12T09:15:00Z");
  add("D, tx-31", "UNDECIDABLE for this email", "agent entry with no grant and no correlation id; server log lost; gateway delivery",
    packet({ invocations: [i], effects: [delivery("e-gw-0312", null, "partner@example.com", hd, "2026-03-12T09:15:01Z")] })); }

// E: the agent log, hash-chained and signed, verifies and records three emails; the gateway shows a fourth from the
// agent's account, with no log entry and no grant.
{ const hs = [1, 2, 3].map(n => h(`E attachment ${n}`)), grants = hs.map((x, n) => grant(`g-e${n + 1}`, "counsel@example.org", x));
  const invs = hs.map((x, n) => send(`tx-e${n + 1}`, `g-e${n + 1}`, "counsel@example.org", x, `2026-03-2${n}T11:00:00Z`));
  const effs = hs.map((x, n) => delivery(`e-tx-e${n + 1}`, invs[n], "counsel@example.org", x, `2026-03-2${n}T11:00:01Z`));
  const fourth = delivery("e-gw-fourth", null, "unknown@example.net", h("E attachment 4"), "2026-03-24T16:30:00Z");
  add("E, 4th email", "UNDECIDABLE for this email", "signed agent log verifies for three emails; gateway shows a fourth with no log entry and no grant",
    packet({ mandates: [standing, ...grants], invocations: invs, effects: [...effs, fourth] })); }

for (const c of cases) console.log(`${c.state.padEnd(14)} paper: ${c.paper.padEnd(40)} AMEP: ${c.amep.outcome} ${c.amep.invariant} - ${c.amep.reason}${c.amep.gaps.length ? `  [gap: ${c.amep.gaps.map(g => g.need).join(", ")}]` : ""}${c.amep.blame ? `  (blame ${c.amep.blame})` : ""}`);
if (process.argv.includes("--json")) writeFileSync(process.argv[process.argv.indexOf("--json") + 1], JSON.stringify({ amep: "0.3.2", source: "arXiv:2610.07459, Section 4", cases }, null, 1) + "\n");
