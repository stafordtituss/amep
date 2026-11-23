// AMEP object builders (spec/amep-v0.2.md, section 5). Each returns a plain object with the spec's member
// names, checks enumerated values, and omits members that are undefined. Sign the result with a Key holding a
// role permitted for its kind (spec 12.5); see ./node.mjs.
import { CEILING, approvalDigest, digest } from "./core.mjs";

const oneOf = (name, value, allowed) => {
  if (!allowed.includes(value)) throw new Error(`${name} must be one of ${allowed.join(", ")}; got ${JSON.stringify(value)}`);
  return value;
};
const clean = o => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== null));

export const ASSURANCE = ["L0", "L1", "L2", "L3"];
export const SOURCES = ["curated", "customer", "provider_hint", "judge", "none"];
export const PRESENCE = ["webauthn", "chat_user", "host_ui", "none"];
export const MODES = ["observe", "allow", "mediate", "step_up", "hold", "deny", "quarantine"];
export const PHASES = ["pre_execution", "post_execution", "simulation"];
export const OUTCOMES = ["preserved", "violated", "unresolved"];

export function claims(actions, resources, ceiling, exp, { data, nbf, purpose, denyActions, denyResources, depth, budget } = {}) {
  oneOf("ceiling", ceiling, CEILING);
  return clean({ actions: [...actions], resources: [...resources], ceiling, exp, data, nbf, purpose,
    deny_actions: denyActions, deny_resources: denyResources, depth, budget });
}

export const mandate = (id, principal, claimSet, { issuer, subjectAgent, statusRef, token } = {}) =>
  clean({ id, kind: "mandate", principal, issuer, subject_agent: subjectAgent, claims: claimSet,
    revocation: statusRef ? { status_ref: statusRef } : undefined, token });

export const delegation = (id, parent, claimSet, { delegate, token } = {}) =>
  clean({ id, kind: "delegation", parent, delegate, claims: claimSet, token });

export function intent(id, claimSet, { promptRef, derivation } = {}) {
  if (derivation !== undefined) oneOf("derivation", derivation, ["template", "judge", "confirmed"]);
  return clean({ id, kind: "intent", prompt_ref: promptRef, claims: claimSet, derivation });
}

export function interpretation(id, adapter, version, { source = "curated", integrityHash } = {}) {
  oneOf("source", source, SOURCES);
  return clean({ id, kind: "interpretation", source, adapter, version, integrity_hash: integrityHash });
}

/** The executed-effect body (spec 5.9), also used for invocation.mediated and approvals. */
export function effectBody(action, resource, effect, t, { released = [], reversible, accessed, recipient, value } = {}) {
  oneOf("effect", effect, CEILING);
  return clean({ action, resource, effect, released: [...released], reversible, accessed, recipient, value, t });
}

/** A quantity (spec 5.9.2): amounts are exact decimal strings, for example value("1200.00", "iso4217:EUR"). */
// periodSpent: the observer's own totals by period length, each for the window it names (spec 5.9.2), for example
// { "2592000": { from: 1765152000, total: "1030.00" } }.
export function value(amount, unit, { periodSpent } = {}) {
  if (typeof amount !== "string") throw new Error('amount must be a decimal string, for example "1200.00"');
  return clean({ amount, unit, period_spent: periodSpent });
}

export function invocation(id, authorityRef, interpretationRef, t, action, resource, effect,
  { actor, intentRef, approvalRef, mediated, influencedBy, principalConfirmed, derivedFrom, budgetSpent, correlation, argsDigest } = {}) {
  oneOf("effect", effect, CEILING);
  if (CEILING.indexOf(effect) >= CEILING.indexOf("write_shared") && !actor)
    throw new Error("actor is required for effects of class write_shared and above (spec 5.8, I10)");
  return clean({ id, kind: "invocation", authority_ref: authorityRef, interpretation_ref: interpretationRef,
    intent_ref: intentRef, approval_ref: approvalRef, t, actor, declared: { action, resource, effect }, mediated,
    influenced_by: influencedBy, principal_confirmed: principalConfirmed, derived_from: derivedFrom,
    budget_spent: budgetSpent, correlation, args_digest: argsDigest });
}

export function effect(id, invocationId, observedBy, assurance, executed, { backendReceipt, invocationDigest } = {}) {
  oneOf("assurance", assurance, ASSURANCE);
  return clean({ id, kind: "effect", invocation: invocationId, observed_by: observedBy, assurance, executed,
    backend_receipt: backendReceipt, invocation_digest: invocationDigest });
}

export const DISPOSITIONS = ["completed", "not_executed", "failed_after_effects"];
/** The observer's signed account of one tool call (spec 5.14). */
export function callStatement(id, invocationId, observedBy, disposition, effectCount, t, { invocationDigest, argsDigest } = {}) {
  oneOf("disposition", disposition, DISPOSITIONS);
  if (disposition === "not_executed" && effectCount !== 0) throw new Error("a not_executed call has no effects");
  return clean({ id, kind: "call_statement", invocation: invocationId, observed_by: observedBy, disposition,
    effect_count: effectCount, t, invocation_digest: invocationDigest, args_digest: argsDigest });
}

/** SHA-256 of the JCS form of a tool call's arguments (spec 5.14), as sent by the host or received by the server. */
export const argsDigest = args => digest(args ?? {});

/** An approval bound to an effect body; the digest is computed without the body's t (spec 5.10). */
export function approval(id, body, presence, { expiry, nbf, approver, resourceVersion, consumed } = {}) {
  oneOf("presence", presence, PRESENCE);
  return clean({ id, kind: "approval", effect_digest: approvalDigest(body), presence, approver,
    resource_version: resourceVersion, nbf, expiry, consumed });
}

export function finding(id, sourceLocator, contentHash, integrityLabel, { span, hiddenMechanism, requested } = {}) {
  oneOf("integrity_label", integrityLabel, ["trusted", "untrusted"]);
  return clean({ id, kind: "finding", source_locator: sourceLocator, content_hash: contentHash, span,
    hidden_mechanism: hiddenMechanism, integrity_label: integrityLabel, requested });
}

export const revocation = (target, t, { reason, id } = {}) => clean({ id, kind: "revocation", target, t, reason });
export const status = (target, asOf, { revokedAt, id } = {}) => clean({ id, kind: "status", target, as_of: asOf, revoked_at: revokedAt });

export function enforcement(pep, failMode, { hostSupports, encodedAs, applied } = {}) {
  oneOf("fail_mode", failMode, ["closed", "open", "unknown"]);
  if (applied !== undefined) oneOf("applied", applied, ["confirmed", "not_observed", "contradicted"]);
  return clean({ pep, fail_mode: failMode, host_supports: hostSupports, encoded_as: encodedAs, applied });
}

export function decision(invocationId, outcome, mode, phase,
  { id, invariant, reason, quarantined, safeAlternatives, evidenceRefs, enforcement: enf } = {}) {
  oneOf("outcome", outcome, OUTCOMES); oneOf("mode", mode, MODES); oneOf("phase", phase, PHASES);
  return clean({ id, kind: "decision", invocation: invocationId, outcome, invariant, mode, phase, quarantined, reason,
    safe_alternatives: safeAlternatives, evidence_refs: evidenceRefs, enforcement: enf });
}

const MEMBER = { mandate: "mandates", delegation: "delegations", intent: "intents", interpretation: "interpretations",
  invocation: "invocations", effect: "effects", approval: "approvals", revocation: "revocations", status: "statuses",
  finding: "findings", decision: "decisions", call_statement: "call_statements" };

/** Group objects into a packet (spec 5.2) by kind, keeping their order. */
export function packet(objects, { pinnedAdapters, amepVersion = "0.2" } = {}) {
  const out = { amep_version: amepVersion };
  for (const o of objects) {
    const m = MEMBER[o.kind];
    if (!m) throw new Error(`unknown object kind ${JSON.stringify(o.kind)}`);
    (out[m] ??= []).push(o);
  }
  if (pinnedAdapters) out.pinned_adapters = { ...pinnedAdapters };
  return out;
}
