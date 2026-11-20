// The MCP extension `io.github.stafordtituss/amep-evidence` on the official MCP TypeScript SDK (v2).
//
// Server side: `AmepEvidenceExtension` advertises the extension in the server's capabilities and wraps tool handlers.
// Tools report what they actually executed with `recordEffect(...)`; after the tool returns, the wrapper signs those
// effects as AMEP ExecutedEffectReceipts (spec section 5.9) and attaches them to the result's `_meta`, but only when
// the client asked for receipts and sent an invocation id.
//
// Client side: `clientCapabilities()` advertises the extension with `wantsReceipts`, and `receiptSettings()` /
// `supportsReceipts()` let a client discover, before calling any tool, whether a server signs receipts.
//
// Works on both protocol eras the SDK serves: 2025-era sessions (capabilities exchanged in `initialize`) and
// 2026-07-28 per-request sessions (client capabilities in each request's `_meta` envelope, server capabilities in
// `server/discover`). See proposals/mcp-sep-amep-evidence.md in the AMEP repository.
import { AsyncLocalStorage } from "node:async_hooks";
import { sdk } from "@stafordtituss/amep";

export const EXTENSION_ID = "io.github.stafordtituss/amep-evidence";
export const INVOCATION_ID_KEY = "io.github.stafordtituss/amep-invocation-id";
export const MANDATE_REF_KEY = "io.github.stafordtituss/amep-mandate-ref";
export const RECEIPT_KEY = "io.github.stafordtituss/amep-effect-receipt";
export const REVISION = "0.2";

const CLIENT_CAPABILITIES_KEY = "io.modelcontextprotocol/clientCapabilities";
const MAX_ID_LENGTH = 256;

// Effects recorded by the tool call currently running. AsyncLocalStorage keeps concurrent tool calls apart.
const recording = new AsyncLocalStorage();

/** Called by a tool to report an effect it actually executed (AMEP spec 5.9). Outside a receipted tool it does nothing. */
export function recordEffect(action, resource, effect, { released = [], reversible, accessed, recipient } = {}) {
  const effects = recording.getStore();
  if (effects) effects.push(sdk.effectBody(action, resource, effect, Math.floor(Date.now() / 1000),
    { released, reversible, accessed, recipient }));
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

export class AmepEvidenceExtension {
  id = EXTENSION_ID;
  #attached = new WeakSet();
  #counter = 0;

  /**
   * @param {object} o
   * @param {import("@stafordtituss/amep").Key} o.observerKey  this server's signing key; its roles must include `observer`
   * @param {string} o.observedBy  identifier of this server, for example `server:tickets.example`
   * @param {string} o.keysUrl     HTTPS URL where this server publishes its AMEP key set
   * @param {string} [o.assurance] L0-L3 (spec 5.1.4); L3 when the server itself executes the effect
   */
  constructor({ observerKey, observedBy, keysUrl, assurance = "L3" }) {
    if (!observerKey?.roles?.includes("observer")) throw new Error("observerKey must hold the observer role (spec 12.5)");
    if (!/^https:\/\//.test(keysUrl ?? "")) throw new Error("keysUrl must be an HTTPS URL");
    if (!sdk.ASSURANCE.includes(assurance)) throw new Error(`unknown assurance level ${assurance}`);
    Object.assign(this, { observerKey, observedBy, keysUrl, assurance });
  }

  settings() {
    return { revision: REVISION, effectReceipts: true, keys: this.keysUrl };
  }

  /** Advertise the extension on an McpServer. Call before connecting, once per server instance. */
  attach(mcp) {
    if (this.#attached.has(mcp)) return this;
    if (mcp.isConnected()) throw new Error("attach the amep-evidence extension before connecting the server");
    mcp.server.registerCapabilities({ extensions: { [EXTENSION_ID]: this.settings() } });
    this.#attached.add(mcp);
    return this;
  }

  /** `mcp.registerTool(name, config, handler)` with receipts for the effects the handler records. */
  registerTool(mcp, name, config, handler) {
    return mcp.registerTool(name, config, this.wrap(mcp, handler));
  }

  /** Wrap a tool handler for `mcp` so that its recorded effects come back as signed receipts. */
  wrap(mcp, handler) {
    this.attach(mcp);
    return async (...args) => {
      const ctx = args.at(-1);
      const recorded = [];
      const result = await recording.run(recorded, () => handler(...args));
      const invocationId = ctx?.mcpReq?._meta?.[INVOCATION_ID_KEY];
      // SEP: receipts only when the client opted in and sent an invocation id; never when nothing was executed.
      if (typeof invocationId !== "string" || !invocationId || invocationId.length > MAX_ID_LENGTH) return result;
      if (recorded.length === 0 || !wantsReceipts(ctx, mcp.server)) return result;
      const receipts = recorded.map(body => this.observerKey.sign(
        sdk.effect(`${this.observedBy}:e-${++this.#counter}`, invocationId, this.observedBy, this.assurance, body)));
      return { ...result, _meta: { ...(result?._meta ?? {}), [RECEIPT_KEY]: receipts.length === 1 ? receipts[0] : receipts } };
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
