// Verdict records (spec 10.8, v0.3): a portable, signable statement of what a verifier concluded about a packet.
// It names the exact packet bytes and key set that were evaluated, and for every result its outcome, deciding invariant,
// blame and evidence gaps (spec 10.5.1). Reasons are free text and differ between implementations, so they are not part
// of the record, which is deterministic: two conforming verifiers produce the same bytes.
// Carried as an in-toto Statement v1 and signed in a DSSE envelope.
import { createHash, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import { canon, verdict, ed25519StrictOk, parseStrict } from "./core.mjs";

export const PREDICATE_TYPE = "https://github.com/stafordtituss/amep/verdict/v0.3";
export const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
export const PAYLOAD_TYPE = "application/vnd.in-toto+json";
export const SVR_TYPE = "https://in-toto.io/attestation/svr/v0.2";
export const SVR_PRESERVED = "AMEP_VERDICT_PRESERVED";
export const RULES_URI = "https://github.com/stafordtituss/amep/blob/main/spec/amep-v0.2.md";
const SPEC_VERSION = "0.3.0-draft.1";

const sha256 = b => createHash("sha256").update(b).digest("hex");
const resultOf = r => ({ id: r.id, outcome: r.outcome, invariant: r.invariant, blame: r.blame ?? null, gaps: [...(r.gaps ?? [])] });

/** The predicate. packetBytes: the exact bytes evaluated (Buffer or string, UTF-8). */
export function verdictRecord(packetBytes, keys, results, verifier) {
  const v = verdict(results);
  const rec = {
    packet: { sha256: sha256(packetBytes) },
    keyset: { sha256: sha256(Buffer.from(canon(keys), "utf8")) },
    verdict: { outcome: v.outcome, invariant: v.invariant, blame: v.blame ?? null, gaps: [...(v.gaps ?? [])] },
    results: results.map(resultOf),
  };
  if (verifier) rec.verifier = { ...verifier };
  return rec;
}

/** in-toto ResourceDescriptors for the artifacts a verdict admits: [{ name, digest: { alg: hex } }], none empty. */
function checkSubjects(subjects) {
  if (!Array.isArray(subjects) || subjects.length === 0) throw new Error("subjects must be a non-empty array");
  for (const s of subjects) {
    const d = s && s.digest;
    if (!s || typeof s !== "object" || typeof s.name !== "string" || !d || typeof d !== "object" || Array.isArray(d) ||
        !Object.keys(d).length || !Object.values(d).every(v => typeof v === "string" && /^[0-9a-f]+$/.test(v)))
      throw new Error("each subject needs a name and a digest of lowercase hex values");
  }
  return subjects.map(s => ({ name: s.name, digest: { ...s.digest } }));
}

/**
 * The in-toto Statement v1 for a verdict. Its subject is the artifact the evaluated actions produced, when the caller
 * names one (a commit, a release, a payment), with the packet's digest in the predicate as an input; otherwise the
 * evaluated packet itself. Pass `{ subjects: [{ name, digest: { sha256: hex } }] }` to name artifacts.
 */
export function statement(packetBytes, keys, results, verifier, { subjects } = {}) {
  const predicate = verdictRecord(packetBytes, keys, results, verifier);
  const subject = subjects === undefined ? [{ name: "amep-packet", digest: { sha256: predicate.packet.sha256 } }] : checkSubjects(subjects);
  return { _type: STATEMENT_TYPE, subject, predicateType: PREDICATE_TYPE, predicate };
}

/** The same verdict as an in-toto Simple Verification Result (SVR v0.2), for policy engines that consume SVRs.
 * The only AMEP property is AMEP_VERDICT_PRESERVED, present when the packet verdict is preserved; the verdict record
 * (statement) carries the outcome, blame and gaps. Not deterministic: it names its verifier and the time. */
export function svrStatement(packetBytes, keys, results, verifierId, timeCreated) {
  timeCreated ??= new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const passed = verdict(results).outcome === "preserved";
  return { _type: STATEMENT_TYPE, subject: [{ name: "amep-packet", digest: { sha256: sha256(packetBytes) } }],
    predicateType: SVR_TYPE,
    predicate: {
      verifier: { id: verifierId, policies: [
        { name: "amep-keyset", digest: { sha256: sha256(Buffer.from(canon(keys), "utf8")) } },
        { name: `amep-${SPEC_VERSION}`, uri: RULES_URI }] },
      timeCreated, properties: passed ? [SVR_PRESERVED] : [] } };
}

// DSSE pre-authentication encoding: "DSSEv1" SP len(type) SP type SP len(body) SP body
const pae = (type, body) => Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${body.length} `), body]);

/** A DSSE envelope over the statement's JCS form, signed with an Ed25519 KeyObject. */
export function signEnvelope(stmt, privateKey, keyid) {
  const payload = Buffer.from(canon(stmt), "utf8");
  const sig = edSign(null, pae(PAYLOAD_TYPE, payload), privateKey);
  return { payloadType: PAYLOAD_TYPE, payload: payload.toString("base64"), signatures: [{ keyid, sig: sig.toString("base64") }] };
}

/** Check a DSSE envelope against {keyid: public key hex}; returns the statement, or throws. Only AMEP verdict
 * statements are accepted unless predicateTypes says otherwise, e.g. [PREDICATE_TYPE, SVR_TYPE]. */
export function verifyEnvelope(env, publicKeys, predicateTypes = [PREDICATE_TYPE]) {
  if (env?.payloadType !== PAYLOAD_TYPE) throw new Error("not an in-toto payload");
  const payload = Buffer.from(env.payload, "base64");
  for (const s of env.signatures || []) {
    const x = publicKeys[s.keyid];
    if (!x) continue;
    const sig = Buffer.from(s.sig, "base64");
    if (!ed25519StrictOk(x, sig.toString("hex"))) continue;
    const pub = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(x, "hex")]), format: "der", type: "spki" });
    if (!edVerify(null, pae(PAYLOAD_TYPE, payload), pub, sig)) continue;
    const stmt = parseStrict(payload.toString("utf8"));
    if (stmt._type !== STATEMENT_TYPE || !predicateTypes.includes(stmt.predicateType)) throw new Error(`predicate type ${stmt.predicateType} is not one of ${predicateTypes.join(", ")}`);
    return stmt;
  }
  throw new Error("no signature verifies with the given keys");
}
