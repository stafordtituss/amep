// Import profile for Kilo Code sessions (Kilo-Org/kilocode): the user's permission config and a session from
// `kilo export`, re-expressed as AMEP evidence.
//
// Kilo decides before each tool call. A rule per tool and pattern says allow, ask or deny; the last matching rule wins
// (packages/opencode/src/permission/index.ts, evaluate), and `*` matches anything (src/util/wildcard.ts). A denied
// call ends in PermissionDeniedError, a call the user refused in PermissionRejectedError or PermissionCorrectedError.
// That answers "may this call start?". It does not answer "what did the call do?": an allowed `npm install` runs
// whatever its scripts run. AMEP answers the second question from a record kept outside the agent.
//
// What this profile produces:
// - claims: the config as an AMEP mandate's claims. allow rules become grants, deny rules become deny_resources, and
//   ask rules become nothing, because the user's answer to an ask is in Kilo's event log (permission.v2.replied), not
//   in the export, and is Kilo's own record of it.
// - invocations: one per tool part of the export, with the tool's input as declared action and resource.
// - decisions: the pre-execution deny or reject that Kilo recorded, for the calls that ended in a permission error.
// The mapping is never wider than Kilo's: where they differ, it is stricter, and `differences` says where.

const PERMISSION_ERRORS = [
  ["PermissionDeniedError", "deny", /prevents you from using this specific tool call/],
  ["PermissionRejectedError", "reject", /The user rejected permission to use this specific tool call\.?$/],
  ["PermissionCorrectedError", "reject", /The user rejected permission to use this specific tool call with the following feedback/],
];
export const TOOLS = {
  read: { action: "fs.read", prefix: "file:", input: "filePath", effect: "read" },
  edit: { action: "fs.write", prefix: "file:", input: "filePath", effect: "write_local" },
  write: { action: "fs.write", prefix: "file:", input: "filePath", effect: "write_local" },
  bash: { action: "process.exec", prefix: "cmd:", input: "command", effect: "write_local" },
};

/** A Kilo wildcard as an AMEP pattern, or null. AMEP patterns have one wildcard, a trailing `*` (spec 6). */
function pattern(prefix, p) {
  const body = p.endsWith("**") ? p.slice(0, -2) + "*" : p;
  const inner = body.endsWith("*") ? body.slice(0, -1) : body;
  if (/[*?]/.test(inner)) return null;
  return prefix + body;
}

/**
 * The permission config as AMEP claims.
 * @param permission  the `permission` member of kilo.json
 * @param o.commandScopes  for an allowed command pattern, the workspace paths it may write ({"npm *": ["node_modules/*"]}).
 *   Kilo has no such member; without it, every file an allowed command writes is outside the grant.
 */
export function claimsFromConfig(permission, { ceiling = "write_local", exp, commandScopes = {} } = {}) {
  const grants = [], denyResources = [], differences = [];
  const rules = typeof permission === "string" ? { "*": permission } : permission;
  for (const [tool, rule] of Object.entries(rules)) {
    const t = TOOLS[tool];
    const entries = typeof rule === "string" || rule === null ? [["*", rule]] : Object.entries(rule);
    if (!t) { differences.push(`${tool}: not mapped, so no ${tool} call is within the grant`); continue; }
    entries.forEach(([p, action], i) => {
      const amep = pattern(t.prefix, p);
      if (!amep) { differences.push(`${tool} "${p}": a wildcard inside the pattern; AMEP patterns end in one "*", so it grants nothing`); return; }
      if (action === "allow") {
        // A later deny or ask over the same pattern beats this allow in Kilo; AMEP's deny list covers the deny case.
        grants.push({ actions: [t.action], resources: [amep] });
        for (const w of commandScopes[p] ?? []) grants.push({ actions: ["fs.write"], resources: [pattern("file:", w)] });
        if (entries.slice(i + 1).some(([q, a]) => a === "ask" && (q === "*" || q === p)))
          differences.push(`${tool} "${p}": allow followed by an ask that overrides it in Kilo; AMEP keeps the allow`);
      } else if (action === "deny") {
        denyResources.push(amep);
        if (entries.slice(i + 1).some(([, a]) => a === "allow"))
          differences.push(`${tool} "${p}": deny followed by an allow; Kilo lets the later allow win where both match, AMEP's deny always wins (stricter)`);
      } else if (action === "ask") {
        differences.push(`${tool} "${p}": ask grants nothing in AMEP; a call allowed by the user's answer needs that answer as a signed approval`);
      }
    });
  }
  const claims = { grants, ceiling, exp };
  if (denyResources.length) claims.deny_resources = denyResources;
  return { claims, differences };
}

// A command's effect class is not in Kilo's record. The deployment states it per command pattern (a deploy command is
// an external send); a command it doesn't list is declared write_local.
const effectOf = (t, raw, commandEffects) => {
  if (t.prefix !== "cmd:") return t.effect;
  const hit = Object.entries(commandEffects).find(([p]) => p.endsWith("*") ? raw.startsWith(p.slice(0, -1)) : raw === p);
  return hit ? hit[1] : t.effect;
};
const rel = (dir, p) => (dir && p.startsWith(dir.endsWith("/") ? dir : dir + "/") ? p.slice(dir.length + (dir.endsWith("/") ? 0 : 1)) : p);
const iso = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

/** The tool calls of an exported session: invocation bodies (unsigned), plus Kilo's own permission outcomes. */
export function importSession(exported, { authorityRef = "m-1", interpretationRef = "a-1", actor = "agent:kilo", commandEffects = {} } = {}) {
  const dir = exported.info?.directory;
  const calls = [], gaps = [];
  for (const m of exported.messages ?? []) for (const part of m.parts ?? []) {
    if (part.type !== "tool") continue;
    const t = TOOLS[part.tool], st = part.state ?? {};
    if (!t) { gaps.push({ call: part.callID, need: "tool map", detail: `tool ${part.tool} is not mapped` }); continue; }
    const raw = st.input?.[t.input];
    if (typeof raw !== "string") { gaps.push({ call: part.callID, need: "input", detail: `no ${t.input} in the input` }); continue; }
    const resource = t.prefix + (t.prefix === "file:" ? rel(dir, raw) : raw);
    const invocation = { id: part.callID, kind: "invocation", authority_ref: authorityRef, interpretation_ref: interpretationRef,
      t: iso(st.time?.start ?? 0), actor, declared: { action: t.action, resource, effect: effectOf(t, raw, commandEffects) } };
    // A command's file writes are chosen by the program it runs, not named by the call (spec 5.8.2): it declares the
    // workspace as its scope, and each write is then judged against the grant.
    if (t.prefix === "cmd:") invocation.declared.scope = { actions: ["fs.*"], resources: ["file:*"] };
    let kilo = st.status === "completed" ? "completed" : st.status === "error" ? "error" : st.status;
    let decision = null;
    if (st.status === "error") {
      const hit = PERMISSION_ERRORS.find(([, , re]) => re.test(st.error ?? ""));
      if (hit) {
        kilo = hit[1] === "deny" ? "denied by a rule" : "rejected by the user";
        decision = { kind: "decision", invocation: part.callID, outcome: "violated", mode: "deny", phase: "pre_execution",
          // Kilo raises the error before the tool body runs, so it records the deny as applied. That is still Kilo's own
          // word: for a high-impact call, AMEP also needs a not_executed statement from a party other than the host.
          reason: `Kilo ${hit[0]}`, enforcement: { pep: "kilo-permission", fail_mode: "closed", applied: "confirmed" } };
      }
    }
    calls.push({ callID: part.callID, tool: part.tool, input: raw, kilo, invocation, decision });
  }
  return { calls, gaps };
}
