// A reference gateway: the client half of `io.github.stafordtituss/amep-evidence` (revision 0.3) on the MCP
// TypeScript SDK.
//
// For each tool call it signs an AMEP Invocation (what the agent declared it would do, under which mandate, with a
// digest of the exact arguments it sends), sends the invocation id and the digest of that signed invocation in the
// request's `_meta`, verifies the call statement and receipts the server returns against the server's published key
// set, recovers them with resources/read if the response is lost, and keeps everything as an AMEP 0.3 packet that an
// independent verifier can evaluate.
import { randomUUID } from "node:crypto";
import { Key, keyset, sdk, sigOk, verifyPacket, parseStrict, digest } from "@stafordtituss/amep";
import { ed25519StrictOk } from "@stafordtituss/amep/core";
import {
  INVOCATION_ID_KEY, INVOCATION_DIGEST_KEY, MANDATE_REF_KEY, RECEIPT_KEY, CALL_STATEMENT_KEY, RECEIPT_SCHEME, receiptSettings,
} from "./extension.mjs";

/**
 * Fetch a server's AMEP key set (spec 12.4) from the `keys` URL it advertised. HTTPS only.
 * Returns the observer keys only: a server's key set is trusted for receipts, never for mandates or approvals.
 */
export async function fetchKeySet(url, { fetch = globalThis.fetch, now = Math.floor(Date.now() / 1000) } = {}) {
  if (!/^https:\/\//.test(url ?? "")) throw new Error(`key set URL must be HTTPS: ${url}`);
  const res = await fetch(url, { headers: { accept: "application/json" }, redirect: "error" });
  if (!res.ok) throw new Error(`key set fetch failed: HTTP ${res.status}`);
  const set = parseStrict(await res.text());
  const out = {};
  for (const [kid, k] of Object.entries(set ?? {})) {
    if (!k || k.kid !== kid || k.alg !== "Ed25519" || !/^[0-9a-f]{64}$/.test(k.x ?? "")) continue;
    if (k.revoked === true || (k.nbf != null && now < k.nbf) || (k.exp != null && now >= k.exp)) continue;
    if (!Array.isArray(k.roles) || !k.roles.includes("observer")) continue;
    out[kid] = { ...k, roles: ["observer"] };
  }
  return out;
}

export class Gateway {
  /**
   * @param {import("@modelcontextprotocol/client").Client} client  a connected MCP client
   * @param {object} serverKeys  the server's observer keys (from fetchKeySet, or pinned)
   */
  constructor(client, serverKeys, { principal = "user:alice", actor = "agent:assistant-1", adapter = "mcp:tickets",
    actions = ["saas.*"], resources = ["tickets:issue/*"], ceiling = "write_shared", ttl = 3600 } = {}) {
    const now = Math.floor(Date.now() / 1000);
    this.client = client;
    this.actor = actor;
    this.issuer = Key.generate("issuer-1", ["issuer", "approver"]);
    this.host = Key.generate("gateway-host-1", ["host"]);
    // The verifier's key set: this gateway's own keys plus the server's observer keys.
    this.keys = { ...keyset(this.issuer, this.host), ...serverKeys };
    this.mandate = this.issuer.sign(sdk.mandate("m-1", principal, sdk.claims(actions, resources, ceiling, now + ttl)), { v: 2 });
    this.interpretation = this.host.sign(sdk.interpretation("a-1", adapter, "v1"), { v: 2 });
    this.invocations = [];
    this.statements = [];
    this.receipts = [];
    this.rejected = []; // statements and receipts that failed verification: kept for the record, never used as evidence
  }

  /** Connect-time helper: fetch the key set the connected server advertised. */
  static async discoverKeys(client, opts) {
    const s = receiptSettings(client);
    if (!s?.keys) throw new Error("server does not advertise amep-evidence receipts");
    return fetchKeySet(s.keys, opts);
  }

  /**
   * Call a tool, declaring the effect the agent intends. Returns the tool result unchanged. If the response is lost
   * (the call throws), the gateway asks the server for the call's evidence with resources/read, then rethrows.
   */
  async call(name, args, { action, resource, effect }) {
    const id = `i-${randomUUID()}`;   // unguessable and unique, so evidence can never be attached to another call
    const inv = this.host.sign(sdk.invocation(id, "m-1", "a-1", Math.floor(Date.now() / 1000), action, resource, effect,
      { actor: this.actor, argsDigest: sdk.argsDigest(args) }), { v: 2 });
    this.invocations.push(inv);
    const invDigest = digest(inv);
    let result;
    try {
      result = await this.client.callTool({ name, arguments: args,
        _meta: { [INVOCATION_ID_KEY]: id, [INVOCATION_DIGEST_KEY]: invDigest, [MANDATE_REF_KEY]: "m-1" } });
    } catch (e) {
      await this.recover(id);
      throw e;
    }
    this.#accept(result?._meta?.[CALL_STATEMENT_KEY], result?._meta?.[RECEIPT_KEY], id, invDigest);
    return result;
  }

  /** Fetch a call's evidence from the server (resources/read on amep-receipt://{id}). Returns true if found. */
  async recover(invocationId) {
    const inv = this.invocations.find(i => i.id === invocationId);
    if (!inv) throw new Error(`unknown invocation ${invocationId}`);
    let text;
    try {
      const r = await this.client.readResource({ uri: `${RECEIPT_SCHEME}://${encodeURIComponent(invocationId)}` });
      text = r?.contents?.[0]?.text;
    } catch {
      return false;   // no evidence: the call stays unresolved, never preserved
    }
    if (typeof text !== "string") return false;
    const evidence = parseStrict(text);
    this.#accept(evidence?.call_statement, evidence?.receipts, invocationId, digest(inv));
    return true;
  }

  #accept(statement, rawReceipts, invocationId, invDigest) {
    if (statement !== undefined && !this.statements.some(s => s.id === statement?.id))
      (this.#verifies(statement, "call_statement", invocationId, invDigest) ? this.statements : this.rejected).push(statement);
    for (const receipt of Array.isArray(rawReceipts) ? rawReceipts : rawReceipts ? [rawReceipts] : []) {
      if (this.receipts.some(r => r.id === receipt?.id)) continue;
      // SEP client rule 1: never trust evidence that does not verify against the server's published keys, or that
      // is bound to another invocation.
      (this.#verifies(receipt, "effect", invocationId, invDigest) ? this.receipts : this.rejected).push(receipt);
    }
  }

  #verifies(obj, kind, invocationId, invDigest) {
    try {
      const key = this.keys[obj?.proof?.kid];
      return obj.kind === kind && obj.invocation === invocationId && obj.invocation_digest === invDigest &&
        obj.proof.v === 2 && !!key && key.roles.includes("observer") && ed25519StrictOk(key.x, obj.proof.sig) && sigOk(obj, key);
    } catch {
      return false;
    }
  }

  packet() {
    return sdk.packet([this.mandate, this.interpretation, ...this.invocations, ...this.statements, ...this.receipts],
      { amepVersion: "0.3" });
  }

  /** Evaluate the collected evidence with the AMEP reference verifier. Returns { verdict, results }. */
  evaluate() {
    return verifyPacket(this.packet(), this.keys);
  }
}
