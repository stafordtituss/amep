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

/** The in-toto Statement v1 whose subject is the evaluated packet. */
export function statement(packetBytes, keys, results, verifier) {
  const predicate = verdictRecord(packetBytes, keys, results, verifier);
  return { _type: STATEMENT_TYPE, subject: [{ name: "amep-packet", digest: { sha256: predicate.packet.sha256 } }],
    predicateType: PREDICATE_TYPE, predicate };
}

// DSSE pre-authentication encoding: "DSSEv1" SP len(type) SP type SP len(body) SP body
const pae = (type, body) => Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${body.length} `), body]);

/** A DSSE envelope over the statement's JCS form, signed with an Ed25519 KeyObject. */
export function signEnvelope(stmt, privateKey, keyid) {
  const payload = Buffer.from(canon(stmt), "utf8");
  const sig = edSign(null, pae(PAYLOAD_TYPE, payload), privateKey);
  return { payloadType: PAYLOAD_TYPE, payload: payload.toString("base64"), signatures: [{ keyid, sig: sig.toString("base64") }] };
}

/** Check a DSSE envelope against {keyid: public key hex}; returns the statement, or throws. */
export function verifyEnvelope(env, publicKeys) {
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
    if (stmt._type !== STATEMENT_TYPE || stmt.predicateType !== PREDICATE_TYPE) throw new Error("not an AMEP verdict statement");
    return stmt;
  }
  throw new Error("no signature verifies with the given keys");
}
