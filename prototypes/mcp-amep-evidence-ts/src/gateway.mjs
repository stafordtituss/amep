// A reference gateway: the client half of `io.github.stafordtituss/amep-evidence` on the MCP TypeScript SDK.
//
// For each tool call it signs an AMEP Invocation (what the agent declared it would do, under which mandate), sends
// the invocation id in the request's `_meta`, verifies any receipt the server returns against the server's published
// key set, and keeps everything as an AMEP packet that an independent verifier can evaluate.
import { Key, keyset, sdk, sigOk, verifyPacket, parseStrict } from "@stafordtituss/amep";
import { INVOCATION_ID_KEY, MANDATE_REF_KEY, RECEIPT_KEY, receiptSettings } from "./extension.mjs";

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
  #n = 0;

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
    this.mandate = this.issuer.sign(sdk.mandate("m-1", principal, sdk.claims(actions, resources, ceiling, now + ttl)));
    this.interpretation = this.host.sign(sdk.interpretation("a-1", adapter, "v1"));
    this.invocations = [];
    this.receipts = [];
    this.rejected = []; // receipts that failed verification: kept for the record, never used as evidence
  }

  /** Connect-time helper: fetch the key set the connected server advertised. */
  static async discoverKeys(client, opts) {
    const s = receiptSettings(client);
    if (!s?.keys) throw new Error("server does not advertise amep-evidence receipts");
    return fetchKeySet(s.keys, opts);
  }

  /** Call a tool, declaring the effect the agent intends. Returns the tool result unchanged. */
  async call(name, args, { action, resource, effect }) {
    const id = `i-${++this.#n}`;
    this.invocations.push(this.host.sign(sdk.invocation(id, "m-1", "a-1", Math.floor(Date.now() / 1000),
      action, resource, effect, { actor: this.actor })));
    const result = await this.client.callTool({ name, arguments: args,
      _meta: { [INVOCATION_ID_KEY]: id, [MANDATE_REF_KEY]: "m-1" } });
    const raw = result?._meta?.[RECEIPT_KEY];
    for (const receipt of Array.isArray(raw) ? raw : raw ? [raw] : []) {
      // SEP client rule 1: never trust a receipt that does not verify against the server's published keys.
      (this.#verifies(receipt, id) ? this.receipts : this.rejected).push(receipt);
    }
    return result;
  }

  #verifies(receipt, invocationId) {
    try {
      const key = this.keys[receipt?.proof?.kid];
      return receipt.kind === "effect" && receipt.invocation === invocationId &&
        !!key && key.roles.includes("observer") && sigOk(receipt, key);
    } catch {
      return false;
    }
  }

  packet() {
    return sdk.packet([this.mandate, this.interpretation, ...this.invocations, ...this.receipts]);
  }

  /** Evaluate the collected evidence with the AMEP reference verifier. Returns { verdict, results }. */
  evaluate() {
    return verifyPacket(this.packet(), this.keys);
  }
}
