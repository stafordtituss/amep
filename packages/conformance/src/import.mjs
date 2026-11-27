// `amep-conformance import`: a universal adapter from other execution-record formats to AMEP evidence.
//
// A format is supported by a *profile* (src/profiles/): detect(record), check(record) for the format's own integrity
// rules, extract(record) for what the record says, an assurance and observer rule, and gaps() stating what AMEP needs
// that the format does not carry. What a tool call *means* in AMEP terms (action, resource, effect class) is not in
// any of these formats, so it comes from a *tool map* the deployment publishes:
//
//   { "tools": { "live_price": { "action": "market.read", "resource": "market:price/{provenance.request.symbol}",
//                                "effect": "read" } } }
//
// The adapter never invents a value: anything neither the record nor the map supplies is reported as a gap, and an
// effect that cannot be mapped is not produced, so the AMEP verdict for that call stays `unresolved`.
import { CEILING, digest, evaluate, verdict } from "@stafordtituss/amep/core";
import { sigOk } from "@stafordtituss/amep";
import { aer1 } from "./profiles/aer1.mjs";
import { oidfActionReceipt } from "./profiles/oidf-action-receipt.mjs";
import { protectMcp } from "./profiles/protect-mcp.mjs";
import { agentReceipts } from "./profiles/agent-receipts.mjs";

export const PROFILES = { aer1, "oidf-action-receipt": oidfActionReceipt, "protect-mcp": protectMcp, "agent-receipts": agentReceipts };

function lookup(obj, path) {
  return path.split(".").reduce((o, k) => (o && typeof o === "object" ? o[k] : undefined), obj);
}
function fill(template, fields) {
  let missing = null;
  const out = template.replace(/\{([A-Za-z0-9_.]+)\}/g, (_, p) => {
    const v = lookup(fields, p);
    if (typeof v !== "string" && typeof v !== "number") { missing ??= p; return ""; }
    return String(v);
  });
  return missing ? { missing } : { value: out };
}

/**
 * Import one record. Returns { profile, integrity, mapping, effect (unsigned AMEP effect or null), gaps }.
 * `invocations` (optional): AMEP invocations the record may belong to; binding is made only by a matching digest.
 * `issuerKey` (optional): the record issuer's public key, obtained separately, for profiles that check signatures.
 * A decision-only profile (protect-mcp) never yields an effect; for a bound record it yields `decision`, an unsigned
 * AMEP pre-execution decision.
 */
export function importRecord(record, { profile: pid, map = { tools: {} }, expectedId, publicKey, invocations = [], invocationId, issuerKey } = {}) {
  const profile = pid ? PROFILES[pid] : Object.values(PROFILES).find(p => p.detect(record));
  if (!profile) throw new Error(pid ? `unknown profile ${pid}` : "no profile recognizes this record");
  const integrity = profile.check(record, { expectedId, publicKey, issuerKey });
  const info = profile.extract(record, integrity.committed);
  const entry = map.tools?.[info.tool.name];
  const mapping = { mappedFrom: entry ? "map" : "missing", binding: "missing", released: entry?.released ?? null };
  let effect = null, why = null;

  if (integrity.verdict !== "pass") why = `record did not pass its own format checks (${integrity.verdict})`;
  else if (profile.importable?.(info)) why = profile.importable(info);
  else if (!entry) why = `tool ${JSON.stringify(info.tool.name)} is not in the tool map`;
  else if (!CEILING.includes(entry.effect)) why = `tool map gives an unknown effect class ${JSON.stringify(entry.effect)}`;
  else if (CEILING.indexOf(entry.effect) >= CEILING.indexOf("external_send") && !Array.isArray(entry.released))
    why = `effect class ${entry.effect} needs a declared release in the tool map`;
  else if (Array.isArray(info.side_effects) && info.side_effects.some(s => s !== "none") && entry.effect === "read")
    why = `the record's committed side effects ${JSON.stringify(info.side_effects)} contradict the tool map's "read": the map would understate the call`;
  else {
    const res = fill(entry.resource, info.fields);
    if (res.missing) why = `resource template needs ${res.missing}, which the record does not carry`;
    else {
      // Binding to the authorizing call: only by digest, never by guessing. A record whose input commitment equals the
      // invocation's args_digest is bound; otherwise the caller must name the invocation, and the binding is reported
      // as asserted by the caller.
      const hex = (info.input_hash ?? "").replace(/^sha256:/, "");
      const byDigest = invocations.find(i => i.args_digest && i.args_digest === hex);
      let inv = byDigest;
      if (byDigest) mapping.binding = "digest";
      else if (invocationId) { inv = invocations.find(i => i.id === invocationId) ?? { id: invocationId }; mapping.binding = "asserted by the importer"; }
      const side = info.side_effects;
      if (Array.isArray(side) && side.includes("none") && entry.effect !== "read")
        mapping.conflict = `the record's committed side effects are ["none"], but the tool map says ${entry.effect}`;
      effect = {
        kind: "effect", id: `${profile.id}:${info.record_id}`, invocation: inv?.id ?? null,
        observed_by: profile.observer(record, info.provenance), assurance: profile.assurance(info.provenance),
        executed: { action: entry.action, resource: res.value, effect: entry.effect, released: entry.released ?? [], t: info.time },
        [`x-${profile.id}`]: { record_id: info.record_id, output_hash: record.output_hash, metadata_hash: record.metadata_hash,
          input_hash: record.input_hash, provenance: info.provenance, id_verdict: integrity.id_verdict },
      };
      if (inv?.id && byDigest) effect.invocation_digest = digest(byDigest);
    }
  }
  let decision = null;
  if (profile.decisionOnly) {
    mapping.authenticated = integrity.verdict === "pass";
    // An unauthenticated receipt is not bound to anything: what it says is not the gateway's statement.
    const b = integrity.verdict === "pass" ? profile.bind(info, entry, invocations)
      : { binding: "not used", why: "the receipt failed its own checks, so it is not bound to any invocation" };
    mapping.binding = b.binding;
    if (b.why) mapping.unbound = b.why;
    mapping.phase = info.phase ?? "not established";
    if (b.inv && integrity.verdict === "pass") {
      if (info.phase === "pre_execution") decision = profile.toDecision(info, b.inv.id, `${profile.id}:${info.record_id}`);
      else mapping.no_decision = `bound to ${b.inv.id}, but the receipt's phase is ${info.phase ?? "not established"}, so it is not re-expressed as a pre-execution decision`;
    }
  }
  return { profile: profile.id, integrity: { verdict: integrity.verdict, id_verdict: integrity.id_verdict, checks: integrity.checks },
    mapping, effect, ...(profile.decisionOnly ? { decision } : {}), not_imported: why, gaps: profile.gaps(info, mapping) };
}

/** Sign imported effects as the importer (role observer) and evaluate them with the rest of an AMEP packet. */
export function evaluateImported(packet, keys, imported, importerKey) {
  const effects = imported.filter(x => x.effect && x.effect.invocation).map(x => importerKey.sign(x.effect, { v: 2 }));
  const pk = { ...packet, effects: [...(packet.effects || []), ...effects] };
  const results = evaluate(pk, { ...keys, [importerKey.kid]: importerKey.publicEntry() }, sigOk);
  return { packet: pk, results, verdict: verdict(results) };
}
