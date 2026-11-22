// Import profile for OpenID Foundation Delegated Authorization action receipts: the `delegation:action-receipt`
// statement class of the eKYC & IDA "Delegated Authorization Execution Layer", v0.2 §6.4, which AuthZEN #795 names as
// a receipt format for its `receipt` obligation.
//
// The execution layer's verification flow (§6.7) checks signatures, registration and that the delegation references
// resolve (step 4). It does not define how a verifier decides whether the action in the receipt stayed within the
// Authority and Task those references point to. This profile maps the receipt to an AMEP effect so that the AMEP
// evaluation can make that decision, and reports what the receipt does not carry for it.
//
// Signature formats are deferred to a later profile of the execution layer (§6.10), so this profile checks the payload's
// structure, not the PEP's COSE or JOSE signature; derived effects are capped at assurance L1.
const OUTCOMES = ["success", "failure", "network-error", "partial"];
const isHashRef = h => h && typeof h === "object" && h.alg === "sha-256" && typeof h.digest === "string";

export const oidfActionReceipt = {
  id: "oidf-action-receipt",
  title: "OpenID DA execution layer action receipt (delegation:action-receipt, v0.2 §6.4)",
  detect: r => r?.statement_class === "delegation:action-receipt",

  check(r) {
    const checks = [];
    let rejected = null, failed = null;
    const add = (rule, pass, detail) => checks.push({ rule, pass, detail });
    const need = (rule, pass, detail, why) => { add(rule, pass, detail); if (!pass) rejected ??= why; };
    need("statement class (§6.4)", r.statement_class === "delegation:action-receipt", r.statement_class, "not an action receipt");
    need("audit_id present (§6.4)", typeof r.audit_id === "string" && r.audit_id.length > 0, r.audit_id, "audit_id missing");
    const d = r.delegation ?? {};
    const refsOk = ["relationship", "authority", "task"].every(k => typeof d[k]?.jti === "string" && isHashRef(d[k]?.hash));
    need("delegation references with SHA-256 hashes (§6.4)", refsOk, Object.keys(d).join(", "), "delegation references incomplete");
    const a = r.action ?? {};
    const actionOk = ["rs_identity", "verb", "resource_type", "action_time"].every(k => typeof a[k] === "string");
    need("action descriptor (§6.4)", actionOk, `${a.verb} ${a.resource_type} at ${a.rs_identity}`, "action descriptor incomplete");
    need("result.outcome is a defined value (§6.4)", OUTCOMES.includes(a.result?.outcome), a.result?.outcome, "unknown outcome");
    // The decision attestation may be carried decoded (as here) or as a JWS; only a decoded one can be read.
    const dec = typeof r.decision_attestation === "object" ? r.decision_attestation : null;
    if (dec) {
      add("decision attestation bound to this audit_id (§6.4)", dec.audit_id === r.audit_id, dec.audit_id);
      if (dec.audit_id !== r.audit_id) failed ??= "decision attestation belongs to another audit_id";
      // An executed action under a non-permit decision is evidence of a bypass, not a receipt to import as authorized.
      const contradicted = dec.decision !== "permit" && ["success", "partial"].includes(a.result?.outcome);
      add("action executed only under a permit", !contradicted, dec.decision);
      if (contradicted) failed ??= `action ${a.result.outcome} under a "${dec.decision}" decision: enforcement was contradicted`;
    } else add("decision attestation readable", false, "carried as a signed token; not decoded by this profile");
    const verdict = rejected ? `rejected: ${rejected}` : failed ? "verification failed" : "pass";
    return { verdict, id_verdict: "unverified", checks, committed: null };
  },

  extract(r) {
    const a = r.action ?? {};
    return {
      record_id: r.audit_id, time: a.action_time,
      tool: { name: `${a.verb}:${a.resource_type}`, version: null, committed: false },
      provenance: a.result?.outcome,
      side_effects: a.verb === "read" ? ["none"] : [a.verb],
      // The PDP's request_hash covers the AuthZEN request it evaluated. If the AMEP invocation's args_digest is computed
      // over the same request (the COAZ comparison basis), the two bind by digest.
      input_hash: typeof r.decision_attestation === "object" ? r.decision_attestation?.request_hash?.digest ?? null : null,
      input_hash_layout: "authzen-request (request_hash)",
      outcome: a.result?.outcome,
      fields: r,
    };
  },

  // Only a completed action is an effect to evaluate. failure, network-error: the outcome is not established, so the
  // call stays unresolved (AuthZEN #795 items 1 and 6: an unknown outcome is not evidence of non-execution).
  importable: info => ["success", "partial"].includes(info.outcome) ? null :
    `outcome "${info.outcome}" does not establish what was executed; the call stays unresolved`,
  assurance: () => "L1",
  observer: r => `oidf-pep:${r.action?.rs_identity ?? "unknown"}`,

  gaps(info, mapped) {
    const cs = info.fields?.context?.constraint_state;
    return [
      { need: "origin authentication (who produced the record)", status: "not checked",
        detail: "the PEP's signature format is deferred to a later execution-layer profile (§6.10); this profile reads the payload only, so the importer's key is the AMEP observer and assurance is capped at L1" },
      { need: "the delegation's scope and constraints", status: "references only",
        detail: "the receipt carries jti and hash of the Relationship, Authority and Task JWTs, not their content; the verifier supplies the Task as an AMEP mandate, bound by the Task hash" },
      { need: "canonical action, resource and effect class", status: mapped.mappedFrom,
        detail: mapped.mappedFrom === "map" ? "taken from the deployment's published map of verb and resource type" : "no map entry for this verb and resource type" },
      { need: "binding to the authorizing call", status: mapped.binding,
        detail: "decision_attestation.request_hash equals the AMEP invocation's args_digest when both hash the same AuthZEN request" },
      { need: "the amount of the action", status: "missing",
        detail: cs ? `the action descriptor has no amount; context.constraint_state (${JSON.stringify(cs)}) is a running total asserted by the PEP, so a per-action constraint such as a nightly price cap cannot be checked from the receipt` : "the action descriptor has no amount" },
    ];
  },
};
