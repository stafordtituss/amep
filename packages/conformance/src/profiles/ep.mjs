// Profile for EMILIA Protocol (EP) vectors (draft-schrock-ep-authorization-receipts; github.com/emiliaprotocol/
// emilia-protocol). Two parts, each tested on EP's own published vectors:
//
// 1. checkReceipt: EP-RECEIPT-v1, written clean-room from the rules the vectors and EP's verifier README state (an
//    Ed25519 signature over the recursively key-sorted JSON of the payload; an optional EP-MERKLE-v2 anchor whose leaf
//    is SHA-256(0x00 || canonical payload)). EP's code was not used.
// 2. predictedEffects: EP's outcome binding approves PREDICTED effects with bounds and compares them with OBSERVED
//    effects (in_bounds, divergent, incomparable). The profile re-expresses the predictions as AMEP claims only where
//    AMEP has an exact form, and says why where it doesn't.
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

const canon = v => v === null || typeof v !== "object" ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(",")}]`
  : `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canon(v[k])}`).join(",")}}`;
const sha = buf => createHash("sha256").update(buf).digest();
const b64u = s => Buffer.from(s ?? "", "base64url");

/** EP-RECEIPT-v1 by EP's rules. Returns { valid, problems }. */
export function checkReceipt(doc, publicKeyB64u) {
  const problems = [];
  if (doc?.["@version"] !== "EP-RECEIPT-v1") problems.push(`unsupported version ${doc?.["@version"]}`);
  const sig = doc?.signature;
  if (!sig?.value) problems.push("no signature value");
  else if (sig.algorithm !== "Ed25519") problems.push(`unsupported algorithm ${sig.algorithm}`);
  else {
    let ok = false;
    try {
      const key = createPublicKey({ key: b64u(publicKeyB64u), format: "der", type: "spki" });
      const s = b64u(sig.value);
      ok = s.length === 64 && cryptoVerify(null, Buffer.from(canon(doc.payload), "utf8"), key, s);
    } catch { ok = false; }
    if (!ok) problems.push("signature does not check over the canonical payload");
  }
  const a = doc?.anchor;
  if (a) {
    if (a.alg !== "EP-MERKLE-v2") problems.push(`anchor ${a.alg ?? "without alg"} is refused (only EP-MERKLE-v2 is accepted by default)`);
    else {
      const leaf = sha(Buffer.concat([Buffer.from([0]), Buffer.from(canon(doc.payload), "utf8")]));
      if (a.leaf_hash !== leaf.toString("hex")) problems.push("anchor leaf is not bound to this receipt's payload");
      // The branch hash is SHA-256(0x01 || left || right) over the children's lowercase HEX TEXT, not their raw bytes:
      // that is what EP's published vectors reconstruct (see interop/ep/README.md).
      let h = a.leaf_hash ?? "";
      for (const step of a.merkle_proof ?? []) {
        const [l, r] = step.position === "right" ? [h, step.hash] : [step.hash, h];
        h = sha(Buffer.concat([Buffer.from([1]), Buffer.from(l + r, "utf8")])).toString("hex");
      }
      if (h !== a.merkle_root) problems.push("anchor proof does not reconstruct the root");
    }
  }
  return { valid: problems.length === 0, problems };
}

// EP effect types and the AMEP effect class each corresponds to. Types outside this list are not guessed.
export const CLASS_OF_EFFECT = { payment: "financial", account_close: "destructive", file_delete: "destructive",
  record_update: "write_shared", inventory_reserve: "write_shared" };
const UNIT = "ep:value";   // EP's values carry no unit; the profile names one (AMEP's namespace:identifier form) so limits apply

/**
 * EP predicted effects as AMEP claims, and EP observed effects as AMEP effects, only when exact.
 * Returns { claims, effects } or { na: reason }.
 */
export function predictedEffects(predicted, observed) {
  if (!Array.isArray(observed)) return { na: "observed effects are not a list; the importer refuses it, as EP does" };
  const grants = [], limits = [];
  for (const p of predicted) {
    const op = p.predicate?.op;
    const cls = CLASS_OF_EFFECT[p.effect_type];
    if (op === "absent" && cls) continue;   // not granted: AMEP's claims are an allowlist
    if (op === "lte" && cls === "financial") {
      grants.push({ actions: [`ep.${p.effect_type}`], resources: [`ep:${p.target}`] });
      limits.push({ unit: UNIT, per_effect: p.predicate.value, actions: [`ep.${p.effect_type}`] });
      continue;
    }
    const why = { eq: "an exact value", set_eq: "an exact set of values", gte: "a minimum", range: "a range with a minimum",
      count_lte: "a maximum number of effects" }[op];
    if (why) return { na: `the prediction is ${why} (${op}); AMEP claims have no exact form for it` };
    if (op === "lte") return { na: `a maximum on a ${p.effect_type} value (lte); AMEP limits cap financial amounts in a unit, and the profile maps only those` };
    if (!cls && op === "absent") return { na: `effect type ${p.effect_type} has no AMEP effect class` };
    return { na: `${op} is not an EP predicate op; the importer refuses it, as EP does` };
  }
  const effects = [];
  for (const o of observed) {
    const extra = Object.keys(o).filter(k => !["effect_type", "target", "value", "values"].includes(k));
    if (extra.length) return { na: `observed effect has unknown member ${extra.join(", ")}; the importer refuses it, as EP does` };
    const cls = CLASS_OF_EFFECT[o.effect_type];
    if (!cls) return { na: `effect type ${o.effect_type} has no AMEP effect class` };
    effects.push({ action: `ep.${o.effect_type}`, resource: `ep:${o.target}`, effect: cls,
      ...(cls === "financial" ? { value: { amount: o.value, unit: UNIT } } : {}) });
  }
  const ceiling = "financial";
  const firstGranted = predicted.find(p => p.predicate?.op !== "absent");
  const predictedCall = firstGranted ? { action: `ep.${firstGranted.effect_type}`, resource: `ep:${firstGranted.target}`, effect: CLASS_OF_EFFECT[firstGranted.effect_type] } : null;
  return { predictedCall, claims: { grants: grants.length ? grants : [{ actions: ["ep.none"], resources: ["ep:none"] }], ceiling, ...(limits.length ? { limits } : {}) }, effects };
}
