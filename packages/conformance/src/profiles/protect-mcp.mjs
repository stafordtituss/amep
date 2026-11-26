// Import profile for protect-mcp decision receipts (ScopeBlind gateway): ACTA envelopes of payload type
// "protectmcp:decision", draft-farley-acta-signed-receipts. Wire format as of scopeblind-gateway 95ecaa3, src/signing.ts
// and src/acta-envelope.ts:
//
//   { "payload": { "type": "protectmcp:decision", "tool_name", "decision": "allow" | "deny", "reason", "policy_digest",
//                  "request_id", "issued_at", "issuer_id", "public_key", "payload_digest": { "input_hash", ... }, ... },
//     "signature": { "alg": "EdDSA", "kid", "sig" } }      sig = Ed25519 over the RFC 8785 bytes of payload, hex
//
// What a decision receipt is, in AMEP terms: the gateway's signed record of its own decision, made before the tool
// ran. It is not a record of an effect. An allow does not show that the tool ran, and a deny does not show that it
// didn't: by spec 10.3 only an observer's not_executed call statement settles non-execution. So this profile never
// produces an AMEP effect. It authenticates the receipt against an issuer key the verifier obtained separately, binds
// it to an AMEP invocation by digest, and re-expresses it as an AMEP pre-execution decision, so the evaluation can apply
// 10.3 to it.
import { createPublicKey, verify as edVerify } from "node:crypto";
import { canon, sha256Hex, HEX64, HEX128 } from "@stafordtituss/amep/core";

const ED25519_SPKI = "302a300506032b6570032100";
function sigValid(payload, sigHex, keyHex) {
  try {
    const key = createPublicKey({ key: Buffer.from(ED25519_SPKI + keyHex, "hex"), format: "der", type: "spki" });
    return edVerify(null, Buffer.from(canon(payload), "utf8"), key, Buffer.from(sigHex, "hex"));
  } catch { return false; }
}

// The payload type is the same for decisions made before execution and for receipts signed after it (reason
// "post_execution_receipt"), so the type alone does not establish phase (review by Tom Farley on stafordtituss/amep#20).
// Pre-execution is established only for the reasons the pinned CLI's `sign --cedar` path emits from a policy
// evaluation: cedar_allow and cedar_deny (with its rule). Any other reason leaves the phase not established.
function phaseOf(reason) {
  if (typeof reason !== "string") return null;
  if (reason === "post_execution_receipt") return "post_execution";
  if (/^cedar_(allow|deny)(:|$)/.test(reason)) return "pre_execution";
  return null;
}

export const protectMcp = {
  id: "protect-mcp",
  title: "protect-mcp decision receipt (protectmcp:decision, draft-farley-acta-signed-receipts)",
  decisionOnly: true,
  detect: r => r?.payload?.type === "protectmcp:decision" && typeof r?.signature === "object",

  check(r, { issuerKey } = {}) {
    const checks = [];
    let rejected = null, failed = null;
    const add = (rule, pass, detail) => checks.push({ rule, pass, detail });
    const need = (rule, pass, detail, why) => { add(rule, pass, detail); if (!pass) rejected ??= why; };
    const p = r.payload ?? {}, s = r.signature ?? {};
    need("payload type protectmcp:decision", p.type === "protectmcp:decision", p.type, "not a protect-mcp decision");
    need("decision is allow or deny", ["allow", "deny"].includes(p.decision), p.decision, "unknown decision");
    need("tool_name, reason and policy_digest present", ["tool_name", "reason", "policy_digest"].every(k => typeof p[k] === "string"),
      Object.keys(p).join(", "), "decision fields missing");
    need("signature is EdDSA with a 128-hex sig", s.alg === "EdDSA" && HEX128.test(s.sig ?? ""), s.alg, "signature malformed");
    need("issuer_id equals signature.kid (ACTA s2.2)", typeof p.issuer_id === "string" && p.issuer_id === s.kid,
      `${p.issuer_id} / ${s.kid}`, "issuer_id does not match kid");
    if (!rejected) {
      if (!issuerKey) {
        add("signature verifies under the expected issuer key", false, "no expected key given (--issuer-key)");
        rejected = "no expected issuer key: the receipt cannot be authenticated, and the public_key it carries is not a substitute";
      } else {
        const ok = HEX64.test(issuerKey) && sigValid(p, s.sig, issuerKey);
        add("signature verifies under the expected issuer key", ok, ok ? "valid" : "invalid_signature");
        if (!ok) failed = "invalid_signature: the payload was altered, or the key is not the issuer's";
        // The key inside the payload is signed, but anyone can sign their own key in: it only matters if it differs.
        if (ok && p.public_key && p.public_key !== issuerKey) add("embedded public_key matches the expected key", false, p.public_key);
      }
    }
    const verdict = rejected ? `rejected: ${rejected}` : failed ? "verification failed" : "pass";
    return { verdict, id_verdict: verdict === "pass" ? "authenticated" : "unverified", checks, committed: null };
  },

  extract(r) {
    const p = r.payload ?? {};
    return {
      // The receipt's identifier as the gateway defines it: SHA-256 of the whole envelope's RFC 8785 bytes.
      record_id: sha256Hex(canon(r)), time: p.issued_at,
      tool: { name: p.tool_name, version: null, committed: true },
      provenance: p.mode, side_effects: null,
      input_hash: p.payload_digest?.input_hash ?? null,
      input_hash_layout: p.payload_digest?.canonical === "jcs" ? "rfc8785-jcs-utf8 (payload_digest)" : p.payload_digest?.canonical,
      digest_canonical: p.payload_digest?.canonical ?? null,
      phase: phaseOf(p.reason),
      decision: p.decision, reason: p.reason, policy_digest: p.policy_digest, mode: p.mode, request_id: p.request_id,
      previous: p.previousReceiptHash ?? null,
      fields: p,
    };
  },

  importable: info => `a decision receipt records the gateway's ${info.decision} before execution, not an effect: ` +
    (info.decision === "allow" ? "it does not show that the tool ran" : "it does not show that the tool didn't run (spec 10.3: only an observer's not_executed statement does)") +
    "; the call stays unresolved until a receipt or call statement from the tool side arrives",
  assurance: () => "L1",
  observer: r => `protect-mcp:${r.payload?.issuer_id ?? "unknown"}`,

  /**
   * Bind a receipt to the one AMEP invocation it decides on, or to none (review on stafordtituss/amep#20):
   * - the digest comparison needs the signed marker payload_digest.canonical === "jcs", since other gateway paths omit
   *   the digest or use another serialization;
   * - the receipt's tool must map to the invocation's declared action;
   * - the candidate must be unambiguous. Two calls with the same arguments have the same digest, so the digest
   *   establishes the arguments, not the invocation. They are told apart only by a trusted identifier: the
   *   invocation's signed correlation.tool_use_ref equal to the receipt's signed request_id. Otherwise the receipt
   *   stays authenticated but unbound.
   */
  bind(info, entry, invocations) {
    const hex = (info.input_hash ?? "").replace(/^sha256:/, "");
    if (!hex) return { binding: "missing", why: "no payload_digest.input_hash" };
    if (info.digest_canonical !== "jcs")
      return { binding: "missing", why: `payload_digest.canonical is ${JSON.stringify(info.digest_canonical)}, not "jcs": input_hash cannot be compared with args_digest` };
    if (!entry) return { binding: "missing", why: `tool ${JSON.stringify(info.tool.name)} is not in the tool map, so the invocation's action cannot be checked` };
    const sameArgs = invocations.filter(i => i.args_digest === hex);
    const cands = sameArgs.filter(i => i.declared?.action === entry.action);
    if (!cands.length) return { binding: "missing", why: sameArgs.length ? `args_digest matches only invocations of another action than ${entry.action}` : "no invocation has this args_digest" };
    if (cands.length === 1) return { binding: "digest", inv: cands[0] };
    const byRef = cands.filter(i => info.request_id && i.correlation?.tool_use_ref === info.request_id);
    if (byRef.length === 1) return { binding: "digest and request_id", inv: byRef[0] };
    return { binding: "ambiguous", why: `${cands.length} invocations of ${entry.action} have these arguments (${cands.map(i => i.id).join(", ")}), and no correlation.tool_use_ref equals the receipt's request_id` };
  },

  /** The AMEP pre-execution decision this receipt states, for an invocation it is bound to (unsigned). */
  toDecision(info, invocationId, recordRef) {
    const deny = info.decision === "deny";
    return {
      id: `protect-mcp:${info.record_id.slice(0, 16)}`, kind: "decision", invocation: invocationId,
      outcome: deny ? "violated" : "preserved", mode: deny ? "deny" : "allow", phase: "pre_execution",
      reason: info.reason, evidence_refs: [recordRef],
      // protect-mcp in enforce mode blocks a denied call; that's its own statement, so it is recorded as declared.
      ...(deny && info.mode === "enforce" ? { enforcement: { pep: "protect-mcp", fail_mode: "closed" } } : {}),
    };
  },

  gaps(info, mapped) {
    return [
      { need: "origin authentication (who produced the record)", status: mapped.authenticated ? "checked" : "not checked",
        detail: "Ed25519 over the RFC 8785 payload, checked against an issuer key the verifier obtained separately; the public_key inside the payload is not used as a trust anchor" },
      { need: "what was executed", status: "missing",
        detail: "the receipt is the gateway's decision before execution; it carries no result, so AMEP gets no effect from it" },
      { need: "confirmation that a denied call did not run", status: "missing",
        detail: "a deny is the gateway's own statement; AMEP needs a not_executed statement from the party that would have executed the call (spec 10.3), so for a high-impact call the gap is named as independent_observer (I10)" },
      { need: "binding to the authorizing call", status: mapped.binding,
        detail: mapped.unbound ?? "payload_digest.input_hash, marked canonical \"jcs\", is SHA-256 over the RFC 8785 bytes of the tool input, the same construction as AMEP's args_digest; it binds when exactly one invocation of the mapped action has that digest, or when the invocation's correlation.tool_use_ref equals request_id" },
      { need: "the phase of the decision", status: info.phase ?? "not established",
        detail: info.phase === "pre_execution" ? `reason ${JSON.stringify(info.reason.split(":")[0])} is emitted by a policy evaluation before execution (sign --cedar)`
          : info.phase === "post_execution" ? "reason post_execution_receipt: signed after execution, so it is not a pre-execution decision, and it carries no result either"
          : "the payload type alone does not establish phase; no pre-execution decision is derived" },
      { need: "the policy the decision followed from", status: "digest only",
        detail: "policy_digest names the policy the gateway says it evaluated; re-deriving the decision would also need that policy text and the evaluation inputs, which the receipt does not carry" },
      { need: "canonical action, resource and effect class", status: mapped.mappedFrom,
        detail: "tool_name and the input are protect-mcp's; their AMEP meaning comes from the deployment's tool map" },
      { need: "completeness of the receipt log", status: "not established",
        detail: "previousReceiptHash links each receipt to the one before it, which detects a removed or reordered link in the supplied chain, not receipts that were never supplied" },
    ];
  },
};
