// The MCP extension `io.github.stafordtituss/amep-evidence` (revision 0.3), on the MCP TypeScript SDK's extension API
// (`{ id, setup(ctx) }`, typescript-sdk#2820).
//
// Server side: `amepEvidence(options)` is a server extension. Its setup advertises the extension with
// `ctx.capability(...)`, registers receipt recovery as a resource template, and wraps `tools/call` with
// `ctx.use(...)`. Tools stay plain `mcp.registerTool` tools; they report what they actually executed with
// `recordEffect(...)`, on the execution path, as it happens. Around each call the middleware:
//   1. digests the arguments exactly as the client sent them (the raw request, before schema validation);
//   2. signs each recorded effect as an AMEP ExecutedEffectReceipt (spec 5.9), bound to the exact signed invocation
//      the gateway sent (invocation_digest);
//   3. signs one call statement (spec 5.14). "Nothing was executed" (not_executed) is signed only when it is known:
//      the call returned a normal result with no effect recorded, or the tool refused before acting by throwing
//      `NotExecuted`. An error result with nothing recorded may come from a tool that acted without recording it
//      (the SDK turns thrown errors into error results before middleware sees them), so its outcome is unknown and no
//      statement is signed: the call stays unresolved;
//   4. stores the evidence (write-ahead), so a client whose response was lost can fetch it with resources/read on
//      amep-receipt://{invocation-id};
//   5. attaches it to the result's `_meta`, never changing `content` or `structuredContent`.
// It does so only when the client opted in (wantsReceipts) and sent an invocation id.
//
// Client side: `amepEvidenceClient()` is a client extension that advertises `wantsReceipts`; `receiptSettings()` and
// `supportsReceipts()` let a client discover, before calling any tool, whether a server signs receipts.
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

// The call in progress: the effects its tool recorded, and whether it refused before acting. AsyncLocalStorage keeps
// concurrent tool calls apart.
const recording = new AsyncLocalStorage();

/** Called by a tool to report an effect it actually executed (AMEP spec 5.9). Outside a receipted call it does nothing. */
export function recordEffect(action, resource, effect, { released = [], reversible, accessed, recipient, value } = {}) {
  const call = recording.getStore();
  if (call) call.effects.push(sdk.effectBody(action, resource, effect, Math.floor(Date.now() / 1000),
    { released, reversible, accessed, recipient, value }));
}

/**
 * Thrown by a tool that refuses before doing anything (validation failed, a precondition wasn't met): the only error
 * the extension reports as "nothing was executed". Throw it before any effect, never after one. Creating it marks the
 * call in progress as refused, because the SDK turns the thrown error into an error result before middleware sees it.
 */
export class NotExecuted extends Error {
  constructor(message = "refused before execution") {
    super(message);
    this.name = "NotExecuted";
    const call = recording.getStore();
    if (call && call.effects.length === 0) call.refused = true;
  }
}

/**
 * Where a server keeps the evidence of recent calls, so a client whose response was lost can fetch it. The default
 * keeps the most recent `max` calls in memory; a production server supplies a durable store with the same interface.
 */
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

/**
 * The extension settings the client advertised for this request, or undefined. 2026-07-28 requests carry the client's
 * capabilities in their own `_meta` envelope, which is authoritative for the request; 2025-era sessions advertise them
 * once, in `initialize`.
 */
function clientSettings(request, ctx, server) {
  const envelope = ctx?.mcpReq?.envelope ?? request?.params?._meta;
  if (envelope && CLIENT_CAPABILITIES_KEY in envelope) return envelope[CLIENT_CAPABILITIES_KEY]?.extensions?.[EXTENSION_ID];
  return server.getClientCapabilities()?.extensions?.[EXTENSION_ID];
}

/**
 * The server half, as an MCP server extension: `new McpServer(info, { extensions: [amepEvidence({...})] })`.
 *
 * @param {object} o
 * @param {import("@stafordtituss/amep").Key} o.observerKey  this server's signing key; its roles must include `observer`
 * @param {string} o.observedBy  identifier of this server, for example `server:tickets.example`
 * @param {string} o.keysUrl     HTTPS URL where this server publishes its AMEP key set
 * @param {string} [o.assurance] L0-L3 (spec 5.1.4); L3 only when this server itself executes the effect
 * @param {object} [o.store]     receipt store with async put(id, evidence) / get(id); in memory by default
 */
export function amepEvidence({ observerKey, observedBy, keysUrl, assurance = "L3", store = new MemoryReceiptStore() }) {
  if (!observerKey?.roles?.includes("observer")) throw new Error("observerKey must hold the observer role (spec 12.5)");
  if (!/^https:\/\//.test(keysUrl ?? "")) throw new Error("keysUrl must be an HTTPS URL");
  if (!sdk.ASSURANCE.includes(assurance)) throw new Error(`unknown assurance level ${assurance}`);
  let counter = 0;
  const settings = { revision: REVISION, effectReceipts: true, callStatements: true,
    receiptRecovery: `${RECEIPT_SCHEME}://{invocation}`, keys: keysUrl };

  return {
    id: EXTENSION_ID,
    settings,
    store,
    setup(ctx) {
      ctx.capability(settings);
      // Receipt recovery through the existing resources/read method: no new protocol method. Invocation ids are
      // unguessable (at least 128 random bits), are never listed, and evidence carries identifiers, not payloads.
      ctx.mcp.registerResource("amep-receipt", new ResourceTemplate(`${RECEIPT_SCHEME}://{invocation}`, { list: undefined }),
        { title: "AMEP evidence for one tool call", mimeType: "application/json" },
        async (uri, { invocation }) => {
          const evidence = await store.get(decodeURIComponent(String(invocation)));
          if (!evidence) throw new Error(`no AMEP evidence for ${uri.href}`);
          return { contents: [{ uri: uri.href, mimeType: "application/json", text: JSON.stringify(evidence) }] };
        });

      ctx.use("tools/call", async (request, requestCtx, next) => {
        const params = request?.params ?? {};
        const meta = params._meta ?? {};
        const invocationId = meta[INVOCATION_ID_KEY];
        const s = clientSettings(request, requestCtx, ctx.mcp.server);
        const optedIn = typeof invocationId === "string" && invocationId.length > 0 && invocationId.length <= MAX_ID_LENGTH &&
          !!(s && typeof s === "object" && s.wantsReceipts === true);
        if (!optedIn) return next(request, requestCtx);

        const call = { effects: [], refused: false };
        // The raw arguments, as the client sent them: what the signed invocation's args_digest covers.
        const argsDigest = sdk.argsDigest(params.arguments ?? {});
        const result = await recording.run(call, () => next(request, requestCtx));

        const invocationDigest = HEX64.test(meta[INVOCATION_DIGEST_KEY] ?? "") ? meta[INVOCATION_DIGEST_KEY] : undefined;
        const now = Math.floor(Date.now() / 1000);
        const receipts = call.effects.map(body => observerKey.sign(sdk.effect(`${observedBy}:e-${++counter}`,
          invocationId, observedBy, assurance, body, { invocationDigest }), { v: 2 }));
        const failed = result?.isError === true;
        // "No effect recorded" means "no effect occurred" only for a normal result, or a refusal before acting.
        // An error result with nothing recorded may hide an effect the tool didn't record: outcome unknown, nothing
        // signed (from Andrii's review, Radiolaria, openid-aiim, 24 Nov 2026).
        const unknown = receipts.length === 0 && failed && !call.refused;
        const disposition = receipts.length === 0 ? "not_executed" : failed ? "failed_after_effects" : "completed";
        const statement = unknown ? undefined : observerKey.sign(sdk.callStatement(`${observedBy}:c-${++counter}`,
          invocationId, observedBy, disposition, receipts.length, now, { invocationDigest, argsDigest }), { v: 2 });
        // Write-ahead, before the result leaves the server. An unknown outcome is stored as such, so a later fetch
        // doesn't read it as "nothing happened".
        await store.put(invocationId, statement ? { call_statement: statement, receipts } : { receipts, outcome: "unknown" });
        const evidence = statement ? { [CALL_STATEMENT_KEY]: statement } : {};
        if (receipts.length) evidence[RECEIPT_KEY] = receipts.length === 1 ? receipts[0] : receipts;
        return { ...result, _meta: { ...(result?._meta ?? {}), ...evidence } };
      });
    },
  };
}

// ---- client side ----

/** The client half, as an MCP client extension: `new Client(info, { extensions: [amepEvidenceClient()] })`. */
export function amepEvidenceClient({ wantsReceipts = true } = {}) {
  return {
    id: EXTENSION_ID,
    setup(ctx) { ctx.capability({ revision: REVISION, wantsReceipts }); },
  };
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
