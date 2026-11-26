// Import profile for Agent Receipts (agent-receipts/obsigna, spec v0.5.0): W3C-VC-shaped receipts of agent actions,
// each signed Ed25519Signature2020 over the RFC 8785 (JCS) form of the receipt without its proof, hash-chained by
// chain.previous_receipt_hash and chain.sequence.
//
// What the profile reads, as reviewed by the Agent Receipts maintainers in agent-receipts/obsigna#1204:
// - Who signs depends on the deployment. In daemon mode (ADR-0010) a separate daemon holds the key and is the issuer;
//   in client-side mode (ADR-0020) the agent's own process signs. Nothing in a receipt proves which mode produced it
//   (tracked in obsigna#1206), so the profile takes the mode from the verifier, out of band, and defaults to the
//   reading that assumes least: the issuer is the acting agent.
// - authorization.scopes are opaque strings, the issuer's statement. The spec maps no action.type to scopes, so
//   whether an action stayed within a grant is decided here by an AMEP mandate the verifier supplies, never from the
//   receipt (obsigna#1207). The spec's own check for high-risk actions is the grounded-principal tier (spec 7.9).
// - issuer.operator names the entity operating the agent. The spec does not bind keys to operators; using it as the
//   AMEP key operator (spec 12.5) is AMEP's interpretation, and the profile says so where it uses it.
// - action.idempotency_key is the logical operation (spec 7.3.6). Agent Receipts surfaces a duplicate as a warning
//   and leaves the judgement to an auditor; AMEP's operation identity rules (spec 5.8.1) make that judgement.
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { canon } from "@stafordtituss/amep/core";

const sha256 = s => "sha256:" + createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");
const withoutProof = r => Object.fromEntries(Object.entries(r).filter(([k]) => k !== "proof"));
/** sha256 over the JCS form of the receipt without its proof block: the receipt hash and the chain link (spec 7.3). */
export const receiptHash = r => sha256(canon(withoutProof(r)));

function strictB64url(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]+$/.test(s)) return null;
  const b = Buffer.from(s, "base64url");
  return b.toString("base64url") === s ? b : null;
}
const RISK = ["low", "medium", "high", "critical"];
const OUTCOME = ["success", "failure", "pending"];

export const agentReceipts = {
  id: "agent-receipts",
  title: "Agent Receipts (agent-receipts/obsigna, spec v0.5.0)",
  detect: r => Array.isArray(r?.type) && r.type.includes("AgentReceipt") && typeof r.credentialSubject === "object",

  /** ctx.publicKey: the issuer's public key (PEM), obtained by the verifier out of band. */
  check(r, { publicKey } = {}) {
    const checks = [];
    let rejected = null, failed = null;
    const add = (rule, pass, detail) => checks.push({ rule, pass, detail });
    const need = (rule, pass, detail, why) => { add(rule, pass, detail); if (!pass) rejected ??= why; };
    const cs = r.credentialSubject ?? {}, a = cs.action ?? {};
    need("type includes VerifiableCredential and AgentReceipt", r.type.includes("VerifiableCredential"), r.type.join(", "), "not an Agent Receipt");
    need("required members: id, version, issuer.id, issuanceDate", ["id", "version", "issuanceDate"].every(k => typeof r[k] === "string") && typeof r.issuer?.id === "string",
      `${r.id} v${r.version}`, "a required member is missing");
    need("action: id, type, risk_level, timestamp", ["id", "type", "timestamp"].every(k => typeof a[k] === "string") && RISK.includes(a.risk_level),
      `${a.type} (${a.risk_level})`, "action incomplete");
    need("principal.id and outcome.status", typeof cs.principal?.id === "string" && OUTCOME.includes(cs.outcome?.status),
      `${cs.principal?.id}, ${cs.outcome?.status}`, "principal or outcome missing");
    need("chain: chain_id, sequence, previous_receipt_hash present", typeof cs.chain?.chain_id === "string" && Number.isInteger(cs.chain?.sequence) && "previous_receipt_hash" in (cs.chain ?? {}),
      cs.chain?.chain_id, "chain block incomplete");
    if (a.idempotency_key !== undefined)
      need("idempotency_key is a non-empty string (spec 4.3.2)", typeof a.idempotency_key === "string" && a.idempotency_key.length > 0, a.idempotency_key, "idempotency_key malformed");
    const p = r.proof;
    need("proof type Ed25519Signature2020", p?.type === "Ed25519Signature2020", p?.type, "wrong proof type");
    const sig = typeof p?.proofValue === "string" && p.proofValue.startsWith("u") ? strictB64url(p.proofValue.slice(1)) : null;
    need("proofValue: multibase base64url ('u'), 64 bytes", sig?.length === 64, p?.proofValue?.slice(0, 1), "proofValue malformed");
    if (!rejected) {
      if (!publicKey) { add("signature", false, "no issuer key given"); failed ??= "no issuer key"; }
      else {
        const ok = edVerify(null, Buffer.from(canon(withoutProof(r)), "utf8"), createPublicKey(publicKey), sig);
        add("Ed25519 signature over the JCS form without proof", ok, ok ? "verifies" : "does not verify");
        if (!ok) failed ??= "signature does not verify";
      }
    }
    const verdict = rejected ? `rejected: ${rejected}` : failed ? "verification failed" : "pass";
    return { verdict, id_verdict: "unverified", checks, committed: null };
  },

  extract(r) {
    const cs = r.credentialSubject ?? {}, a = cs.action ?? {};
    return {
      record_id: r.id, time: a.timestamp,
      tool: { name: a.type, version: null, committed: true },
      provenance: cs.outcome?.status, outcome: cs.outcome?.status, risk: a.risk_level,
      operation: a.idempotency_key ?? null,
      side_effects: null,
      // parameters_hash commits to the call's parameters; it binds to AMEP's args_digest only if both hash the same
      // JCS form of the same parameters, which the spec does not state.
      input_hash: a.parameters_hash ?? null,
      fields: { ...r, action: a, target: a.target, principal: cs.principal },
    };
  },

  // Only a success says the action ran. failure and pending do not establish that nothing was executed: a timeout is
  // an unknown outcome (spec 5.8.1, rule 2), so the call stays unresolved and holds its operation.
  importable: info => info.outcome === "success" ? null :
    `outcome "${info.outcome}" does not establish what was executed; the call stays unresolved`,
  assurance: () => "L1",
  // The observer is the receipt's issuer. Whether that is a party apart from the actor is the deployment question above.
  observer: r => r.issuer?.id ?? "unknown",

  gaps(info, mapped) {
    const f = info.fields;
    return [
      { need: "who signed: the acting agent, or a party apart from it", status: "deployment, not receipt",
        detail: "daemon mode (ADR-0010) and client-side mode (ADR-0020) produce receipts that look the same (obsigna#1206); the verifier states the mode out of band. Covered in Agent Receipts by daemon key custody" },
      { need: "the grant the action is judged against", status: f.credentialSubject?.authorization ? "issuer's statement" : "missing",
        detail: f.credentialSubject?.authorization ? "authorization.scopes are opaque and asserted by the issuer; the verifier supplies the grant as an AMEP mandate (obsigna#1207)"
          : "no authorization block; the verifier supplies the grant as an AMEP mandate. Agent Receipts' grounded-principal tier (spec 7.9) checks that a grant exists for the principal, through grant_ref" },
      { need: "the resource acted on", status: f.target?.resource ? "present" : "missing",
        detail: f.target?.resource ? `action.target.resource = ${f.target.resource}` : "action.target is optional and absent, so a resource-scoped grant cannot be checked unless the tool map fixes the resource for this action type" },
      { need: "canonical action and effect class", status: mapped.mappedFrom,
        detail: mapped.mappedFrom === "map" ? "from the deployment's published map of action.type" : `no map entry for ${info.tool.name}` },
      { need: "binding to the authorizing call", status: mapped.binding,
        detail: info.input_hash ? "parameters_hash may equal the AMEP invocation's args_digest if both are the JCS hash of the same parameters" : "no parameters_hash" },
      { need: "the logical operation (retries)", status: info.operation ? "present" : "missing",
        detail: info.operation ? `idempotency_key ${info.operation} becomes the AMEP invocation's operation (spec 5.8.1)` : "no idempotency_key: a retry cannot be told from a second operation" },
    ];
  },
};

/** Chain checks of spec 7.3: each link's previous_receipt_hash is the hash of the receipt before it; sequences run 1, 2, 3. */
export function checkChain(receipts) {
  const links = [];
  for (let i = 0; i < receipts.length; i++) {
    const ch = receipts[i].credentialSubject?.chain ?? {};
    const prevOk = i === 0 ? ch.previous_receipt_hash === null : ch.previous_receipt_hash === receiptHash(receipts[i - 1]);
    const seqOk = ch.sequence === i + 1;
    const sameChain = ch.chain_id === receipts[0].credentialSubject?.chain?.chain_id;
    links.push({ index: i, link: prevOk, sequence: seqOk, chain_id: sameChain });
  }
  const valid = links.every(l => l.link && l.sequence && l.chain_id);
  const keys = receipts.map(r => r.credentialSubject?.action?.idempotency_key).filter(k => typeof k === "string");
  const duplicates = [...new Set(keys.filter((k, i) => keys.indexOf(k) !== i))];
  return { valid, links, duplicate_idempotency_keys: duplicates };
}
