// ARIA AP and AMEP on one exchange.
//
// The CG's hiring use case with one delegation hop (see ../delegation-continuity):
//   H  the HR lead, who authorizes the hiring agent A        (AMEP mandate)
//   A  the hiring agent, who hands scheduling to B           (AMEP delegation)
//   B  the scheduling agent, which calls the calendar T      (ARIA credential + ARIA AP signed request)
//   T  the calendar service, which admits and records it     (ARIA credential + ARIA AP receipt)
//
// Each case runs a real ARIA AP exchange with @trustlayer-foundation/aria-sdk and aria-ap 1.0.1: receiver
// identity, an RFC 9421 signed request, admission and a signed aria-ap-receipt/1. The same exchange is then
// recorded as AMEP evidence and evaluated with @stafordtituss/amep.
//
// Key reuse is the bridge: B's ARIA holder key signs its AMEP invocation, and T's ARIA holder key signs its
// AMEP effect receipt. The AMEP effect carries the ARIA receipt's digest as its backend receipt (AMEP L3).
//
// Credentials here come from a LOCAL TEST ISSUER created on each run, not from TrustLayer or agent.bar.
// The verifiers trust only that issuer. Credential ids follow the AID 1.0 schema's URL pattern, but no
// such credentials exist. Nothing is sent over the network: the issuer's signed status list is served in-process.
//
// Run: npm install && node demo.mjs

import { createHash, createPrivateKey, randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { canonicalJson, createVerifier } from "@trustlayer-foundation/aria-sdk";
import { createAp, MemoryChallengeStore, MemoryOperationStorage, OperationLedger } from "@trustlayer-foundation/aria-ap";
import { Key, keyset, sdk, verifyPacket } from "@stafordtituss/amep";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "out");

// ---------- identities ----------
const H_DID = "did:web:acme.example:people:hr-lead";
const A_DID = "did:aria:acme.example:hiring-agent";
const B_DID = "did:aria:acme.example:scheduling-agent";
const T_DID = "did:aria:acme.example:calendar";
const T_ORIGIN = "https://calendar.acme.example";

const ISSUER = "did:aria:issuer.test";
const ISSUER_VM = `${ISSUER}#key-1`;
const STATUS_ORIGIN = "https://status.issuer.test";
const STATUS_LIST = `${STATUS_ORIGIN}/lists/1`;

// ---------- small encodings ----------
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58btc(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; out = "1" + out; }
  return out;
}
const b64url = bytes => Buffer.from(bytes).toString("base64url");
const utf8 = s => new TextEncoder().encode(s);
const iso = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
const sha256b64 = s => createHash("sha256").update(s).digest("base64");

// ---------- the local test issuer (ML-DSA-65 + Ed25519, suite mldsa65-ed25519-2026) ----------
const issuerPq = ml_dsa65.keygen();
const issuerEd = ed25519.utils.randomSecretKey();
const TRUST = {
  id: "local-test",
  issuer: ISSUER,
  verificationMethod: ISSUER_VM,
  keys: { mldsa65: issuerPq.publicKey, ed25519: ed25519.getPublicKey(issuerEd) },
  maxLevel: "L1",
  statusLists: [STATUS_LIST],
};

function compositeProof(unsigned) {
  const payload = utf8(canonicalJson(unsigned));
  const pq = ml_dsa65.sign(payload, issuerPq.secretKey);
  const classical = ed25519.sign(payload, issuerEd);
  const bytes = new Uint8Array(4 + pq.length + classical.length);
  new DataView(bytes.buffer).setUint32(0, pq.length, false);
  bytes.set(pq, 4);
  bytes.set(classical, 4 + pq.length);
  return "u" + b64url(bytes);
}

/** An agent: an Ed25519 holder key and an AID 1.0 credential naming it, from the local test issuer. */
function agent(did, name, scope, serial, now) {
  const holderSeed = ed25519.utils.randomSecretKey(); // generated fresh on every run, never stored
  const keyId = `${did}#holder-key-1`;
  const credentialId = `https://api.aria.bar/v1/credentials/0193a5b0-0000-7000-8000-${String(serial).padStart(12, "0")}`;
  const unsigned = {
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://aria.bar/ns/v1"],
    type: ["VerifiableCredential", "ARIAIdentityDocument"],
    id: credentialId,
    issuer: ISSUER,
    validFrom: iso(now - 3600e3),
    validUntil: iso(now + 86400e3),
    credentialSubject: {
      id: did,
      agentName: name,
      version: "1.0.0",
      trustLevel: "L1",
      scope,
      delegationDepth: 0,
      maxDelegationDepth: 0,
      spec_version: "1.0",
      principal: { type: "Organization", did: "did:web:acme.example", legalName: "Acme Example Corp (test)", jurisdiction: "US", verificationStatus: "self-declared" },
      holderKey: { id: keyId, type: "Ed25519VerificationKey2020", publicKeyMultibase: "z" + base58btc(ed25519.getPublicKey(holderSeed)) },
      enrollmentAttestation: { userAgentAgreement: true, attestedAt: iso(now - 3600e3), termsVersion: "1.0.0", privacyVersion: "1.0.0" },
    },
    credentialStatus: { id: `${STATUS_LIST}#${serial}`, type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: String(serial), statusListCredential: STATUS_LIST },
  };
  const document = { ...unsigned, proof: { type: "DataIntegrityProof", cryptosuite: "mldsa65-ed25519-2026", created: iso(now - 3600e3), proofPurpose: "assertionMethod", verificationMethod: ISSUER_VM, proofValue: compositeProof(unsigned) } };
  const signer = { keyId, algorithm: "ed25519", sign: async bytes => ed25519.sign(bytes, holderSeed) };
  // The same 32-byte seed as an AMEP signing key (node:crypto), with the ARIA key id as its AMEP kid.
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(holderSeed)]);
  const amepKey = roles => new Key(keyId, roles, createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" }));
  return { did, keyId, credentialId, document, signer, amepKey, statusIndex: serial };
}

// ---------- status, served in-process: the issuer's signed Bitstring Status List ----------
const ariaRevoked = new Set(); // status-list indexes of revoked ARIA credentials
function statusListDocument() {
  const bits = new Uint8Array(131072 / 8);
  for (const i of ariaRevoked) bits[i >> 3] |= 1 << (7 - (i & 7));
  const now = Date.now();
  const unsigned = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    type: ["VerifiableCredential", "BitstringStatusListCredential"],
    id: STATUS_LIST, issuer: ISSUER, validFrom: iso(now - 60e3), validUntil: iso(now + 3600e3),
    credentialSubject: { id: `${STATUS_LIST}#list`, type: "BitstringStatusList", statusPurpose: "revocation", encodedList: "u" + b64url(gzipSync(bits)) },
  };
  return { ...unsigned, proof: { type: "DataIntegrityProof", cryptosuite: "mldsa65-ed25519-2026", created: iso(now), proofPurpose: "assertionMethod", verificationMethod: ISSUER_VM, proofValue: compositeProof(unsigned) } };
}
async function statusFetch(url) {
  if (url !== STATUS_LIST) return new Response("not found", { status: 404 });
  return new Response(JSON.stringify(statusListDocument()), { status: 200, headers: { "content-type": "application/json" } });
}
const verifierConfig = { trust: [TRUST], fetch: { allowedOrigins: [STATUS_ORIGIN], fetch: statusFetch } };

// ---------- one ARIA AP exchange: B calls T to create a calendar entry ----------
const CREATE_EVENT = { name: "create-event", class: "unsafe-body", method: "POST", path: "/v1/events", mediaType: "application/json", scope: "calendar:event:create", minLevel: "L1" };

async function ariaExchange(B, T, body) {
  // The agent's side and the receiver's side each have their own verifier and ARIA AP instance.
  const agentVerifier = createVerifier(verifierConfig), agentAp = createAp({ credentials: agentVerifier });
  const recvVerifier = createVerifier(verifierConfig), recvAp = createAp({ credentials: recvVerifier });

  const tCred = recvVerifier.verifyCredential(T.document);
  if (!tCred.ok) throw new Error(`receiver credential: ${JSON.stringify(tCred)}`);
  const self = { did: T.did, origin: T_ORIGIN, credential: tCred.credential, document: T.document, signer: T.signer };
  const challenges = new MemoryChallengeStore();

  // 1. Who is the receiver? (pinned DID and origin; the answer crosses the wire as JSON)
  const nonce = randomUUID();
  const identity = JSON.parse(JSON.stringify(await recvAp.identify(self, { nonce, audience: B.did }, challenges)));
  const receiver = await agentAp.verifyReceiverIdentity(identity, { origin: T_ORIGIN, did: T.did }, { nonce, audience: B.did });
  if (!receiver.ok) throw new Error(`receiver identity: ${receiver.reason}`);

  // 2. A signed attempt (RFC 9421, B's holder key)
  const bCred = agentVerifier.verifyCredential(B.document);
  if (!bCred.ok) throw new Error(`agent credential: ${JSON.stringify(bCred)}`);
  const operationId = randomUUID();
  const sentAt = Date.now();
  const signed = await agentAp.signRequest({
    request: { method: "POST", target: "/v1/events", headers: { "content-type": "application/json" }, body: utf8(JSON.stringify(body)) },
    class: "unsafe-body", operationId, receiver: receiver.receiver, credential: bCred.credential, signer: B.signer,
  });

  // 3. The receiver authenticates and admits it
  const docs = { [B.credentialId]: B.document };
  const presented = await recvAp.verifyPresentation(signed.request, {
    receiver: { did: T.did, origin: T_ORIGIN }, operations: [CREATE_EVENT], challenges, resolveCredential: async url => docs[url] ?? null,
  });
  if (!presented.ok) throw new Error(`presentation: ${presented.code} ${presented.reason}`);
  const status = await recvVerifier.checkStatus(presented.presentation.credential);
  const admission = await recvAp.admit({
    presentation: presented.presentation, status,
    scopePolicy: [{ effect: "allow", pattern: "calendar:event:*" }],
    authorize: async () => ({ allowed: true }), // T's own resource rule: B's organization may write this calendar
  });

  // 4. Run once, and sign the receipt
  let receipt, transportStatus, executed = false;
  if (admission.decision === "allow") {
    const ledger = new OperationLedger(recvAp, new MemoryOperationStorage(), self);
    const begun = await ledger.begin(admission);
    if (begun.kind !== "claimed") throw new Error(`begin: ${begun.kind}`);
    executed = true; // the calendar entry is written here, in the same transaction as settle
    const outcome = await ledger.settle(begun.claim, { state: "completed", status: 201 });
    receipt = outcome.receipt; transportStatus = 201;
  } else {
    receipt = await recvAp.buildAttemptRefusal(admission.refusal, self);
    transportStatus = admission.refusal.status;
  }

  // 5. The agent checks the receipt against what it sent
  const wireReceipt = JSON.parse(JSON.stringify(receipt));
  const checked = await agentAp.verifyReceipt(wireReceipt, { receiver: receiver.receiver, attempts: [signed.sent], mode: "decision", transportStatus });
  return { admission: admission.decision === "allow" ? "allow" : `${admission.decision} (${admission.reason})`, receipt: wireReceipt, receiptValid: checked.ok, sentAt, executed };
}

// ---------- AMEP evidence for the same exchange ----------
const EXEC_DENY = ["calendar:interview/executive/*"];

function amepPacket({ H, Akey, Bkey, Tkey, aria, resource, sentAt, revokedAt }) {
  const t0 = sentAt;
  const m = H.sign(sdk.mandate("m-1", H_DID, sdk.claims(
    ["hiring.read", "calendar.write", "communication.send"],
    ["hiring:candidate/*", "calendar:interview/*", "communication:candidate/*"],
    "external_send", iso(t0 + 3600e3), { denyResources: EXEC_DENY, depth: 2, purpose: "hiring" })));
  const d = Akey.sign(sdk.delegation("d-1", "m-1", sdk.claims(
    ["calendar.write"], ["calendar:interview/req-1042/*"], "write_shared", iso(t0 + 1800e3),
    { denyResources: EXEC_DENY, depth: 0, purpose: "hiring" }), { delegate: B_DID }));
  const a = Bkey.sign(sdk.interpretation("a-1", "aria-ap:create-event", "1.0.1"));
  const tInv = iso(t0);
  const i = Bkey.sign(sdk.invocation("i-1", "d-1", "a-1", tInv, "calendar.write", resource, "write_shared", { actor: B_DID }));
  const objects = [m, d, a, i];
  if (aria.executed) {
    const digest = `sha-256=:${sha256b64(canonicalJson(aria.receipt))}:`;
    objects.push(Tkey.sign(sdk.effect("e-1", "i-1", T_DID, "L3",
      sdk.effectBody("calendar.write", resource, "write_shared", aria.receipt.issuedAt, { reversible: true }),
      { backendReceipt: { type: aria.receipt.type, id: aria.receipt.id, digest } })));
  }
  if (revokedAt) objects.push(H.sign(sdk.revocation("m-1", iso(revokedAt), { id: "r-1", reason: "candidate withdrew" })));
  return sdk.packet(objects);
}

/** The link between the two: the AMEP effect names this exact ARIA receipt, signed by the same key, for the same sender. */
function bridgeCheck(packet, aria, keys) {
  const e = (packet.effects ?? [])[0];
  if (!e) return "no effect recorded";
  const digest = `sha-256=:${sha256b64(canonicalJson(aria.receipt))}:`;
  const ok = e.backend_receipt?.digest === digest
    && aria.receipt.proof.keyid === e.proof.kid && keys[e.proof.kid]
    && aria.receipt.request.sender.did === packet.invocations[0].actor
    && aria.receipt.receiver.did === e.observed_by;
  return ok ? "linked" : "NOT linked";
}

// ---------- the cases ----------
const CASES = [
  { slug: "within-delegation", title: "B books the interview slot it was asked to book",
    resource: "calendar:interview/req-1042/slot-3" },
  { slug: "outside-delegation", title: "B, steered by injected text, writes to the executive calendar",
    resource: "calendar:interview/executive/board-prep" },
  { slug: "upstream-revoked", title: "H revoked the hiring mandate before B acted",
    resource: "calendar:interview/req-1042/slot-3", revokeMandate: true },
  { slug: "aria-credential-revoked", title: "B's own ARIA credential was revoked",
    resource: "calendar:interview/req-1042/slot-3", revokeAria: true },
];

async function main() {
  mkdirSync(OUT, { recursive: true });
  const now = Date.now();
  const B = agent(B_DID, "scheduling-agent", ["calendar:event:create"], 11, now);
  const T = agent(T_DID, "calendar", ["calendar:event:receive"], 12, now);

  const H = Key.generate("hr-lead#key-1", ["issuer"]);         // H's issuer key (in practice, H's identity provider)
  const Akey = Key.generate(`${A_DID}#key-1`, ["host"]);        // A's host signs the delegation
  const Bkey = B.amepKey(["host"]);                             // B's ARIA holder key, as AMEP host key
  const Tkey = T.amepKey(["observer"]);                         // T's ARIA holder key, as AMEP observer key
  const keys = keyset(H, Akey, Bkey, Tkey);
  writeFileSync(join(OUT, "keys.json"), JSON.stringify(keys, null, 2));

  const rows = [];
  for (const c of CASES) {
    ariaRevoked.clear();
    if (c.revokeAria) ariaRevoked.add(B.statusIndex);
    const [area, req, slot] = c.resource.split(":")[1].split("/").slice(1);
    const aria = await ariaExchange(B, T, { calendar: "interviews", area, request: req, slot });
    const packet = amepPacket({ H, Akey, Bkey, Tkey, aria, resource: c.resource, sentAt: aria.sentAt,
      revokedAt: c.revokeMandate ? aria.sentAt - 60e3 : undefined });
    const { verdict, results } = verifyPacket(packet, keys);
    const inv = verdict.invariant && verdict.invariant !== "-" ? ` (${verdict.invariant})` : "";
    const amep = `${verdict.outcome}${inv} - ${aria.executed ? verdict.reason : "nothing executed, so there is no effect to check"}`;
    rows.push({ case: c.title, aria: `${aria.admission}; receipt ${aria.receipt.outcome.state}/${aria.receipt.outcome.applies}${aria.receiptValid ? ", verified" : ", NOT verified"}`,
      amep, link: bridgeCheck(packet, aria, keys) });
    writeFileSync(join(OUT, `${c.slug}.json`), JSON.stringify({ case: c.title, aria_receipt: aria.receipt, amep_packet: packet, amep_result: { verdict, results } }, null, 2));
  }

  console.log("\nOne exchange, two questions: ARIA AP (who sent it, was it admitted) and AMEP (was it within the authority H delegated)\n");
  for (const r of rows) {
    console.log(`- ${r.case}`);
    console.log(`    ARIA AP : ${r.aria}`);
    console.log(`    AMEP    : ${r.amep}`);
    console.log(`    link    : ${r.link}`);
  }
  console.log("\nEvidence written to out/ (credentials from a local test issuer; not TrustLayer, not agent.bar)\n");
}

main().catch(e => { console.error(e); process.exit(1); });
