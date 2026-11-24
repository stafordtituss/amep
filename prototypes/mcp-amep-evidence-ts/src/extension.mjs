// The MCP extension `io.github.stafordtituss/amep-evidence` (revision 0.3) on the official MCP TypeScript SDK (v2).
//
// Server side: `AmepEvidenceExtension` advertises the extension in the server's capabilities and wraps tool handlers.
// Tools report what they actually executed with `recordEffect(...)`, on the execution path, as it happens. When the
// handler returns, and before the result leaves the server, the wrapper:
//   1. signs each recorded effect as an AMEP ExecutedEffectReceipt (spec 5.9), bound to the exact signed invocation
//      the gateway sent (invocation_digest);
//   2. signs one call statement (spec 5.14) saying whether anything was executed, how many receipts belong to the
//      call, and the digest of the arguments the server received. "Nothing was executed" (not_executed) is signed only
//      when it is known: the handler returned normally with no effect recorded, or it refused before acting by
//      throwing `NotExecuted`. A handler that throws anything else after recording nothing may have acted without
//      recording it, so its outcome is unknown and no statement is signed: the call stays unresolved;
//   3. stores both (write-ahead), so a client whose response was lost can fetch them with resources/read on
//      amep-receipt://{invocation-id};
//   4. attaches them to the result's `_meta`.
// It does so only when the client opted in and sent an invocation id.
//
// Client side: `clientCapabilities()` advertises the extension with `wantsReceipts`, and `receiptSettings()` /
// `supportsReceipts()` let a client discover, before calling any tool, whether a server signs receipts.
//
// Works on both protocol eras the SDK serves: 2025-era sessions (capabilities exchanged in `initialize`) and
// 2026-07-28 per-request sessions (client capabilities in each request's `_meta` envelope, server capabilities in
// `server/discover`).
import { AsyncLocalStorage } from "node:async_hooks";
import { ResourceTemplate } from "@modelcontextprotocol/server";
import { sdk } from "@stafordtituss/amep";

export const EXTENSION_ID = "io.github.stafordtituss/amep-evidence";
export const INVOCATION_ID_KEY = "io.github.stafordtituss/amep-invocation-id";
export const INVOCATION_DIGEST_KEY = "io.github.stafordtituss/amep-invocation-digest";
export const MANDATE_REF_KEY = "io.github.stafordtituss/amep-mandate-ref";
export const RECEIPT_KEY = "io.github.stafordtituss/amep-effect-receipt";
export const CALL_STATEMENT_KEY = "io.github.stafordtituss/amep-call-statement";
export const RECEIPT_SCHEME = "amep-receipt";
export const REVISION = "0.3";

const CLIENT_CAPABILITIES_KEY = "io.modelcontextprotocol/clientCapabilities";
const MAX_ID_LENGTH = 256;
const HEX64 = /^[0-9a-f]{64}$/;

// Effects recorded by the tool call currently running. AsyncLocalStorage keeps concurrent tool calls apart.
const recording = new AsyncLocalStorage();

/** Called by a tool to report an effect it actually executed (AMEP spec 5.9). Outside a receipted tool it does nothing. */
export function recordEffect(action, resource, effect, { released = [], reversible, accessed, recipient, value } = {}) {
  const effects = recording.getStore();
  if (effects) effects.push(sdk.effectBody(action, resource, effect, Math.floor(Date.now() / 1000),
    { released, reversible, accessed, recipient, value }));
}

/**
 * The extension settings the client advertised for this request, or undefined.
 * 2026-07-28 requests carry the client's capabilities in their own `_meta` envelope, and that envelope is
 * authoritative for the request. 2025-era sessions advertise them once, in `initialize`.
 */
export function clientSettings(ctx, server) {
  const envelope = ctx?.mcpReq?.envelope;
  if (envelope && CLIENT_CAPABILITIES_KEY in envelope) return envelope[CLIENT_CAPABILITIES_KEY]?.extensions?.[EXTENSION_ID];
  return server.getClientCapabilities()?.extensions?.[EXTENSION_ID];
}

function wantsReceipts(ctx, server) {
  const s = clientSettings(ctx, server);
  return !!(s && typeof s === "object" && s.wantsReceipts === true);
}

/**
 * Where a server keeps the evidence of recent calls, so a client whose response was lost can fetch it. The default
 * keeps the most recent `max` calls in memory; a production server supplies a durable store with the same interface.
 */
/**
 * Thrown by a tool handler that refuses before doing anything (validation failed, precondition not met): the only
 * failure the wrapper may report as "nothing was executed". Throw it before any effect, never after one.
 */
export class NotExecuted extends Error {
  constructor(message = "refused before execution") { super(message); this.name = "NotExecuted"; }
}

export class MemoryReceiptStore {
  #m = new Map();
  constructor({ max = 10_000 } = {}) { this.max = max; }
  async put(invocationId, evidence) {
    this.#m.delete(invocationId);
    this.#m.set(invocationId, evidence);
    while (this.#m.size > this.max) this.#m.delete(this.#m.keys().next().value);
  }
  async get(invocationId) { return this.#m.get(invocationId); }
}

export class AmepEvidenceExtension {
  id = EXTENSION_ID;
  #attached = new WeakSet();
  #counter = 0;

  /**
   * @param {object} o
   * @param {import("@stafordtituss/amep").Key} o.observerKey  this server's signing key; its roles must include `observer`
   * @param {string} o.observedBy  identifier of this server, for example `server:tickets.example`
   * @param {string} o.keysUrl     HTTPS URL where this server publishes its AMEP key set
   * @param {string} [o.assurance] L0-L3 (spec 5.1.4); L3 only when this server itself executes the effect
   * @param {object} [o.store]     receipt store with async put(id, evidence) / get(id); in memory by default
   */
  constructor({ observerKey, observedBy, keysUrl, assurance = "L3", store = new MemoryReceiptStore() }) {
    if (!observerKey?.roles?.includes("observer")) throw new Error("observerKey must hold the observer role (spec 12.5)");
    if (!/^https:\/\//.test(keysUrl ?? "")) throw new Error("keysUrl must be an HTTPS URL");
    if (!sdk.ASSURANCE.includes(assurance)) throw new Error(`unknown assurance level ${assurance}`);
    Object.assign(this, { observerKey, observedBy, keysUrl, assurance, store });
  }

  settings() {
    return { revision: REVISION, effectReceipts: true, callStatements: true,
      receiptRecovery: `${RECEIPT_SCHEME}://{invocation}`, keys: this.keysUrl };
  }

  /** Advertise the extension on an McpServer and register receipt recovery. Call before connecting, once per server. */
  attach(mcp) {
    if (this.#attached.has(mcp)) return this;
    if (mcp.isConnected()) throw new Error("attach the amep-evidence extension before connecting the server");
    mcp.server.registerCapabilities({ extensions: { [EXTENSION_ID]: this.settings() } });
    // Receipt recovery through the existing resources/read method: no new protocol method. Invocation ids are
    // unguessable (at least 128 random bits), are never listed, and receipts carry identifiers, not payloads.
    mcp.registerResource("amep-receipt", new ResourceTemplate(`${RECEIPT_SCHEME}://{invocation}`, { list: undefined }),
      { title: "AMEP evidence for one tool call", mimeType: "application/json" },
      async (uri, { invocation }) => {
        const evidence = await this.store.get(decodeURIComponent(String(invocation)));
        if (!evidence) throw new Error(`no AMEP evidence for ${uri.href}`);
        return { contents: [{ uri: uri.href, mimeType: "application/json", text: JSON.stringify(evidence) }] };
      });
    this.#attached.add(mcp);
    return this;
  }

  /** `mcp.registerTool(name, config, handler)` with receipts for the effects the handler records. */
  registerTool(mcp, name, config, handler) {
    return mcp.registerTool(name, config, this.wrap(mcp, handler));
  }

  /** Wrap a tool handler for `mcp` so that its recorded effects come back as signed evidence. */
  wrap(mcp, handler) {
    this.attach(mcp);
    return async (...args) => {
      const ctx = args.at(-1);
      // SDK 2.4.0 gives handlers the arguments after schema validation, not the raw request. The digest therefore
      // covers what the tool received; a schema that strips or defaults fields makes it differ from what the host
      // sent. The ctx.use('tools/call') middleware of typescript-sdk#2820 sees the raw request and removes this limit.
      const received = args.length > 1 ? args[0] : {};
      const recorded = [];
      let result, failure;
      try {
        result = await recording.run(recorded, () => handler(...args));
      } catch (e) {
        failure = e;
      }
      const meta = ctx?.mcpReq?._meta ?? {};
      const invocationId = meta[INVOCATION_ID_KEY];
      const invocationDigest = HEX64.test(meta[INVOCATION_DIGEST_KEY] ?? "") ? meta[INVOCATION_DIGEST_KEY] : undefined;
      const optedIn = typeof invocationId === "string" && invocationId.length > 0 && invocationId.length <= MAX_ID_LENGTH &&
        wantsReceipts(ctx, mcp.server);
      if (!optedIn) {
        if (failure) throw failure;
        return result;
      }
      const now = Math.floor(Date.now() / 1000);
      const receipts = recorded.map(body => this.observerKey.sign(sdk.effect(`${this.observedBy}:e-${++this.#counter}`,
        invocationId, this.observedBy, this.assurance, body, { invocationDigest }), { v: 2 }));
      const failed = !!failure || result?.isError === true;
      // "No effect was recorded" is "no effect occurred" only if the handler ran to the end (every effect on its path
      // was recorded) or refused before acting. An exception after an effect but before recordEffect would otherwise
      // become a signed, false not_executed, which also releases holds (spec 5.10, 7.6). Reported by Andrii
      // (Radiolaria) on openid-aiim, 24 Nov 2026.
      const unknown = receipts.length === 0 && !!failure && !(failure instanceof NotExecuted);
      const disposition = receipts.length === 0 ? "not_executed" : failed ? "failed_after_effects" : "completed";
      const statement = unknown ? undefined : this.observerKey.sign(sdk.callStatement(`${this.observedBy}:c-${++this.#counter}`,
        invocationId, this.observedBy, disposition, receipts.length, now, { invocationDigest, argsDigest: sdk.argsDigest(received) }), { v: 2 });
      // write-ahead, before returning; an unknown outcome is stored as such, so a later fetch doesn't read it as "none"
      await this.store.put(invocationId, statement ? { call_statement: statement, receipts } : { receipts, outcome: "unknown" });
      const evidence = statement ? { [CALL_STATEMENT_KEY]: statement } : {};
      if (receipts.length) evidence[RECEIPT_KEY] = receipts.length === 1 ? receipts[0] : receipts;
      if (failure) return { content: [{ type: "text", text: String(failure?.message ?? failure) }], isError: true, _meta: evidence };
      return { ...result, _meta: { ...(result?._meta ?? {}), ...evidence } };
    };
  }
}

// ---- client side ----

/** Client capabilities that advertise the extension. Merge into `new Client(info, { capabilities })`. */
export function clientCapabilities({ wantsReceipts = true } = {}) {
  return { extensions: { [EXTENSION_ID]: { revision: REVISION, wantsReceipts } } };
}

/** The server's advertised settings for the extension (from `initialize` or `server/discover`), or undefined. */
export function receiptSettings(client) {
  return client.getServerCapabilities()?.extensions?.[EXTENSION_ID];
}

/** Discovery and filtering: true when a connected server says it signs effect receipts. */
export function supportsReceipts(client) {
  const s = receiptSettings(client);
  return !!(s && s.effectReceipts === true && typeof s.keys === "string");
}
