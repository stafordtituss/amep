// AMEP: Agentic Mandate Evidence Protocol, for Node.js.
//   import { verifyPacket, Key, keyset, sdk } from "amep";
// The evaluation core alone (no node: imports, also usable in browsers) is at "amep/core".
export { evaluate, verdict, canon, digest, approvalDigest, toTime, isGuardrail } from "./core.mjs";
export { sigOk, verifyPacket, Key, keyset, ROLES } from "./node.mjs";
export * as sdk from "./sdk.mjs";
export const VERSION = "0.2.0-alpha.4";
export const SPEC_VERSION = "0.2.0-draft.4";
