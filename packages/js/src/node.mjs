// AMEP for Node.js: Ed25519 signature checks and signing keys, built on node:crypto.
// Browsers use the same core (./core.mjs) with WebCrypto instead; see verifier/browser in the repository.
import { createPublicKey, createPrivateKey, generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import { writeFileSync, existsSync } from "node:fs";
import { canon, stripProof, signingInput, evaluate, verdict, SIGNER_ROLES } from "./core.mjs";

export const ROLES = ["issuer", "host", "observer", "approver"];
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex"); // DER prefix of an Ed25519 public key

/** Signature check for core.evaluate: true when obj's proof verifies under key (a key-set entry). */
export function sigOk(obj, key) {
  const pub = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(key.x, "hex")]), format: "der", type: "spki" });
  return edVerify(null, Buffer.from(signingInput(obj), "utf8"), pub, Buffer.from(obj.proof.sig, "hex"));
}

/** Evaluate a packet with node:crypto signature checks. Returns { results, verdict }. */
export function verifyPacket(packet, keys, { protectedPaths = [], state = {} } = {}) {
  const results = evaluate(packet, keys, sigOk, protectedPaths, state);
  return { results, verdict: verdict(results), state };
}

/** An Ed25519 signing key with an AMEP key id and roles (spec 12.5). */
export class Key {
  constructor(kid, roles, keyObject) {
    for (const r of roles) if (!ROLES.includes(r)) throw new Error(`unknown role ${r}`);
    this.kid = kid; this.roles = [...roles]; this.keyObject = keyObject;
  }

  static generate(kid, roles) {
    return new Key(kid, roles, generateKeyPairSync("ed25519").privateKey);
  }

  static fromPem(pem, kid, roles) {
    const k = createPrivateKey(pem);
    if (k.asymmetricKeyType !== "ed25519") throw new Error("AMEP keys must be Ed25519");
    return new Key(kid, roles, k);
  }

  toPem() { return this.keyObject.export({ format: "pem", type: "pkcs8" }); }

  /** Write the key as PKCS#8 PEM, readable only by the current user. Refuses to overwrite. */
  save(path) {
    if (existsSync(path)) throw new Error(`refusing to overwrite ${path}`);
    writeFileSync(path, this.toPem(), { mode: 0o600 });
  }

  /** This key's entry for a key set (spec 12.4). */
  publicEntry() {
    const der = createPublicKey(this.keyObject).export({ format: "der", type: "spki" });
    return { kid: this.kid, alg: "Ed25519", x: der.subarray(SPKI_PREFIX.length).toString("hex"), roles: [...this.roles] };
  }

  /** A copy of obj with a proof. v: 1 signs the JCS form (AMEP v0.2); v: 2 signs the domain-separated input of
   * spec 12.2 (AMEP v0.3). Refuses kinds this key's roles may not sign. */
  sign(obj, { v = 1 } = {}) {
    const allowed = SIGNER_ROLES[obj.kind];
    if (allowed && !this.roles.some(r => allowed.includes(r)))
      throw new Error(`key ${this.kid} (roles ${this.roles.join(", ")}) may not sign a ${obj.kind}; needs one of ${allowed.join(", ")}`);
    const body = stripProof(obj);
    const proof = v === 2 ? { kid: this.kid, alg: "Ed25519", v: 2 } : { kid: this.kid, alg: "Ed25519" };
    const sig = edSign(null, Buffer.from(signingInput({ ...body, proof }), "utf8"), this.keyObject).toString("hex");
    return { ...body, proof: { ...proof, sig } };
  }
}

/** A key set mapping kid to public entry, as served at /.well-known/amep-keys.json. */
export const keyset = (...keys) => Object.fromEntries(keys.map(k => [k.kid, k.publicEntry()]));
