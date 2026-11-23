// AMEP: Agentic Mandate Evidence Protocol, for Node.js.
//   import { verifyPacket, Key, keyset, sdk } from "amep";
// The evaluation core alone (no node: imports, also usable in browsers) is at "amep/core".
export { evaluate, evaluateText, verdict, canon, digest, approvalDigest, signingInput, toTime, isGuardrail, parseStrict, unsafeNumber } from "./core.mjs";
export { sigOk, verifyPacket, Key, keyset, ROLES } from "./node.mjs";
export * as sdk from "./sdk.mjs";
export * as verdicts from "./verdict.mjs";
export const VERSION = "0.3.0-alpha.2";
export const SPEC_VERSION = "0.3.0-draft.1";
