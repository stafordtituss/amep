// Import profile for Delegation Receipt Protocol vectors (draft-nelson-agent-delegation-receipts; the reference SDK
// github.com/Commonguy25/authproof-sdk). DRP is a pre-execution check: given a user-signed receipt and a proposed
// action, a verifier answers PERMIT or DENY. AMEP judges what executed, afterwards. The profile therefore asks the
// matching question for each DRP vector: had the proposed action run as proposed, would AMEP find it within the
// authority the evidence shows?
//
// It checks each receipt by DRP's own rule first. The SDK's published vectors use the pre-11 rule, which the draft now
// deprecates: an ECDSA P-256 signature over JSON.stringify(body) in insertion order, and a receipt id that is the
// SHA-256 of JSON.stringify(body + signature). The current JWS-over-RFC 8785 profile has no published vectors to test.
//
// It then separates what the user signed from what the verifier supplied at check time (verifierOptions.scopeSchema,
// parentScopeSchema), because AMEP decides authority only from signed, machine-readable evidence.
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { CEILING } from "@stafordtituss/amep/core";

const sha256hex = s => createHash("sha256").update(s).digest("hex");
// DRP operations and the AMEP effect class each corresponds to. Operations outside this list are not guessed.
export const CLASS_OF_OPERATION = { read: "read", write: "write_shared", create: "write_shared", update: "write_shared",
  delete: "destructive", send: "external_send", export: "external_send" };

function p256(jwk, sigHex, text) {
  try {
    const sig = Buffer.from(sigHex ?? "", "hex");
    if (sig.length !== 64) return false;
    return cryptoVerify("sha256", Buffer.from(text, "utf8"), { key: createPublicKey({ key: jwk, format: "jwk" }), dsaEncoding: "ieee-p1363" }, sig);
  } catch { return false; }
}

/** DRP's legacy receipt checks: signature, receipt id, and (for a sub-receipt) the orchestrator binding. */
export function checkLegacyReceipt(receipt, expectedId, parentKey) {
  const problems = [];
  const { signature, orchestratorSignature, ...body } = receipt ?? {};
  if (!p256(receipt?.signerPublicKey, signature, JSON.stringify(body))) problems.push("signature does not check (legacy rule: P-256 over JSON.stringify of the body)");
  const { orchestratorSignature: _o, ...withSig } = receipt ?? {};
  const id = sha256hex(JSON.stringify(withSig));
  if (expectedId && id !== expectedId) problems.push("receipt id is not the SHA-256 of the receipt as given");
  if (receipt?.parentReceiptId) {
    const bound = `orchestrator-delegation:${receipt.parentReceiptId}:${id}`;
    const ok = [parentKey, receipt.signerPublicKey].filter(Boolean).some(k => p256(k, orchestratorSignature, bound));
    if (!ok) problems.push("orchestrator signature over the parent binding does not check");
  }
  return { id, problems };
}

/** A DRP scope schema as AMEP claims, only when AMEP can express it exactly. */
export function claimsOf(schema) {
  const allowed = schema?.allowedActions ?? [], denied = schema?.deniedActions ?? [];
  const ops = [...new Set(allowed.map(a => a.operation))], res = [...new Set(allowed.map(a => a.resource))];
  const unknown = ops.filter(o => !CLASS_OF_OPERATION[o]);
  if (unknown.length) return { gap: `operation ${unknown.join(", ")} has no AMEP effect class` };
  // DRP allows (operation, resource) pairs. When they form a product, plain claims express them; otherwise AMEP 0.3
  // grants do, one grant per pair (spec 5.3), so nothing is widened.
  const product = ops.length * res.length === new Set(allowed.map(a => `${a.operation}|${a.resource}`)).size;
  const deny_actions = [], deny_resources = [];
  for (const d of denied) {
    if (d.resource === "*") deny_actions.push(`drp.${d.operation}`);
    else if (d.operation === "*") deny_resources.push(`drp:${d.resource}`);
    else return { gap: `the denied pair ${d.operation} ${d.resource} has no exact AMEP form` };
  }
  const ceiling = ops.reduce((m, o) => (CEILING.indexOf(CLASS_OF_OPERATION[o]) > CEILING.indexOf(m) ? CLASS_OF_OPERATION[o] : m), "read");
  const authority = product ? { actions: ops.map(o => `drp.${o}`), resources: res.map(r => `drp:${r}`) }
    : { grants: allowed.map(a => ({ actions: [`drp.${a.operation}`], resources: [`drp:${a.resource}`] })) };
  return { claims: { ...authority, ceiling,
    ...(deny_actions.length ? { deny_actions } : {}), ...(deny_resources.length ? { deny_resources } : {}) } };
}

/**
 * Analyse one DRP vector: DRP's own receipt checks, where its deciding authority comes from, and the AMEP evidence that
 * can be built from it. Returns { checks, authority, action, chain, gaps }.
 */
export function analyseVector(v) {
  const gaps = [];
  const parentKey = v.parentReceipt?.signerPublicKey;
  const own = checkLegacyReceipt(v.receipt, v.receiptId, parentKey);
  const chain = [];
  if (v.parentReceipt) chain.push(checkLegacyReceipt(v.parentReceipt, v.parentReceiptId ?? v.receipt?.parentReceiptId));
  for (const c of v.chainReceipts ?? []) chain.push(checkLegacyReceipt(c.receipt, c.receiptId));
  const signed = v.receipt?.scopeSchema;
  const supplied = v.verifierOptions?.scopeSchema ?? v.parentScopeSchema ?? null;
  const authority = signed && v.parentScopeSchema ? "child: scope schema signed in the receipt; parent: scope schema supplied by the verifier"
    : signed ? "signed scope schema in the receipt" : supplied ? "scope schema supplied by the verifier at check time (not signed by the user)"
    : "natural-language scope only";
  if (!signed && !supplied) gaps.push("authority is natural language (`scope`); AMEP decides authority only from machine-readable claims");
  if (v.parentScopeSchema) gaps.push("the parent's machine-readable scope is supplied by the verifier (parentScopeSchema); the parent receipt itself carries natural-language scope only");
  if (v.receipt?.oneTimeUse) gaps.push("one-time use of the receipt itself: AMEP makes approvals single use, not mandates");
  if (v.currentAuthorityState) gaps.push("authority-state drift (the receipt's authorityStateCommitment against the current state) is checked by DRP's verifier; AMEP's nearest check is revocation at the effect's time (I6), and the profile doesn't map it");
  if (v.verifierOptions?.maxChainDepth) gaps.push(`maximum chain depth ${v.verifierOptions.maxChainDepth} is the verifier's policy, not signed by the user`);
  const action = typeof v.action === "object" && v.action ? v.action : null;
  if (!action) gaps.push("the action is free text; AMEP needs an action and a resource");
  return { checks: { receipt: own, chain }, authority, signedSchema: signed ?? null, suppliedSchema: supplied, action, gaps };
}
