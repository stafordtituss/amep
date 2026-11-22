// Import profile for AER-1 execution receipts (draft-zambo-aer1-26, B. Zambo).
//
// AER-1 commits to a tool call's output bytes (output_hash) and to its metadata (metadata_hash), and is served at a
// public URL. It is not signed, so it does not authenticate its issuer; the profile reports what the hashes do and do
// not establish, and the adapter caps the assurance of anything it derives (spec 5.14, minting rule).
import { createHash } from "node:crypto";

const sha256 = b => "sha256:" + createHash("sha256").update(b).digest("hex");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const FIXED_CLASSES = ["OBSERVED VIA GATEWAY", "LOGGED BY AGENT"];

/** AER-1 Section 7.1 string escaping: Python json.dumps with ensure_ascii=True. */
function aerString(s) {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (c === 8) out += "\\b"; else if (c === 9) out += "\\t"; else if (c === 10) out += "\\n";
    else if (c === 12) out += "\\f"; else if (c === 13) out += "\\r";
    else if (c >= 0x20 && c <= 0x7e) out += ch;
    else if (c > 0xffff) { const v = c - 0x10000; out += `\\u${(0xd800 + (v >> 10)).toString(16).padStart(4, "0")}\\u${(0xdc00 + (v & 0x3ff)).toString(16).padStart(4, "0")}`; }
    else out += `\\u${c.toString(16).padStart(4, "0")}`;
  }
  return out + '"';
}
function aerJson(v) {   // member names sorted by code point, no whitespace; every value in the block is a string
  if (typeof v === "string") return aerString(v);
  const keys = Object.keys(v).sort((a, b) => { const A = [...a].map(c => c.codePointAt(0)), B = [...b].map(c => c.codePointAt(0));
    for (let i = 0; i < Math.min(A.length, B.length); i++) if (A[i] !== B[i]) return A[i] - B[i]; return A.length - B.length; });
  return "{" + keys.map(k => aerString(k) + ":" + aerJson(v[k])).join(",") + "}";
}

function validTimestamp(s) {
  const m = RFC3339.exec(s ?? "");
  if (!m) return "not RFC 3339";
  const [, y, mo, d, h, mi, se] = m.map(Number);
  if (se === 60) return "leap-second timestamp";
  const dim = [31, (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (mo < 1 || mo > 12 || d < 1 || d > dim[mo - 1] || h > 23 || mi > 59 || se > 59) return "not a real calendar date and time";
  return null;
}

function strictBase64(s) {
  if (typeof s !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s)) return null;
  const b = Buffer.from(s, "base64");
  return b.toString("base64") === s ? b : null;   // canonical spelling only: zero pad bits
}

const versionAtLeast = (v, min) => { const a = String(v).split(".").map(Number), b = min.split(".").map(Number);
  for (let i = 0; i < Math.max(a.length, b.length); i++) { const d = (a[i] ?? 0) - (b[i] ?? 0); if (d) return d > 0; } return true; };

export const aer1 = {
  id: "aer1",
  title: "AER-1 execution receipt (draft-zambo-aer1)",
  detect: r => typeof r?.id === "string" && typeof r?.output_hash === "string" && "canonical_bytes" in r && "provenance_class" in r,

  /** The structural checks of AER-1 Section 6 that need no network. Returns { verdict, checks }. */
  check(r, { expectedId } = {}) {
    const checks = [];
    const add = (rule, pass, detail) => checks.push({ rule, pass, detail });
    let rejected = null, failed = null;
    const reject = why => { rejected ??= why; };
    if (!UUID.test(r.id ?? "") || r.id === "00000000-0000-0000-0000-000000000000") reject("id is not a lowercase, non-nil UUID");
    add("id format (Section 3)", UUID.test(r.id ?? ""), r.id);
    const ts = validTimestamp(r.created_at);
    if (ts) reject(`created_at: ${ts}`);
    add("created_at valid (Section 6)", !ts, r.created_at);
    const pc = r.provenance_class;
    const pcOk = typeof pc === "string" && !/[\u0000-\u001f\u007f]/.test(pc) && (FIXED_CLASSES.includes(pc) || /^EXECUTED BY \S.*$/.test(pc));
    if (!pcOk) reject("provenance_class is not one of the three classes");
    add("provenance class (Section 5)", pcOk, pc);
    const bytes = strictBase64(r.canonical_bytes);
    let text = null;
    if (!bytes) reject("canonical_bytes is not canonical base64");
    else { try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { reject("canonical bytes are not valid UTF-8"); } }
    add("canonical bytes: canonical base64, strict UTF-8 (Section 4)", !!bytes && text !== null, bytes ? `${bytes.length} bytes` : "invalid");
    if (bytes) {
      const ok = sha256(bytes) === r.output_hash;
      if (!ok) failed ??= "output_hash does not match the canonical bytes";
      add("output_hash = SHA-256(canonical bytes) (Section 4)", ok, r.output_hash);
    }
    const needMeta = versionAtLeast(r.receipt_schema_version ?? "0", "0.4");
    if ("metadata_hash" in r || needMeta) {
      let ok = false;
      if (typeof r.metadata_hash === "string" && r.tool && typeof r.tool === "object") {
        const block = { created_at: r.created_at, id: r.id, output_hash: r.output_hash, provenance_class: r.provenance_class,
          receipt_schema_version: r.receipt_schema_version, tool: { name: r.tool.name, scope: r.tool.scope, version: r.tool.version } };
        ok = sha256(Buffer.from(aerJson(block), "utf8")) === r.metadata_hash;
      }
      if (!ok) failed ??= "metadata_hash does not match the canonical metadata block";
      add("metadata_hash = SHA-256(metadata block) (Section 3.1)", ok, r.metadata_hash ?? "missing");
    }
    const id_verdict = expectedId === undefined ? "unverified" : expectedId === r.id ? "matched" : "mismatched";
    const verdict = rejected ? `rejected: ${rejected}` : failed ? "verification failed" : "pass";
    return { verdict, id_verdict, checks, committed: text };
  },

  /** What the record says, for mapping. Only fields covered by output_hash or metadata_hash are marked committed. */
  extract(r, committedText) {
    let committed = {};
    try { committed = JSON.parse(committedText ?? "{}"); } catch { /* not JSON: nothing committed beyond the bytes */ }
    return {
      record_id: r.id, time: r.created_at,
      tool: { name: r.tool?.name ?? r.tool, version: r.tool?.version, committed: "metadata_hash" in r },
      provenance: r.provenance_class,
      side_effects: committed?.side_effects?.declared ?? null,      // inside the output commitment
      // Since -25 a receipt is issued for every call, including calls a gateway refused. A deployment's output can say
      // so; only a statement inside the output commitment counts (a hosted display field such as steps[].status is
      // not committed and could be edited).
      executed: committed?.output && typeof committed.output === "object" ? committed.output.executed : undefined,
      output_status: committed?.output && typeof committed.output === "object" ? committed.output.status : undefined,
      input_hash: r.input_hash ?? null, input_hash_layout: r.input_hash_layout ?? null,
      fields: r,
    };
  },

  /** A record whose committed output says the call was not executed (for example a gateway refusal) describes no
   * effect, so no AMEP effect is produced. AMEP's confirmed non-execution is a call statement signed by the server
   * (disposition not_executed, spec 5.14); an unsigned AER-1 record cannot supply that, so the call stays unresolved. */
  importable: info => info.executed === false
    ? `the record's committed output says the call was not executed${info.output_status ? ` (status ${JSON.stringify(info.output_status)})` : ""}: there is no effect to import; a confirmed non-execution needs the server's signed not_executed call statement`
    : null,

  /** AMEP assurance for the derived receipt (spec 5.1.4), capped at L1: AER-1 is unsigned, so this is a reconstruction. */
  assurance: provenance => (provenance === "LOGGED BY AGENT" ? "L0" : "L1"),
  observer: (r, provenance) => provenance === "LOGGED BY AGENT" ? "aer1:agent-report" : `aer1:${String(provenance).replace(/^EXECUTED BY /, "").replace(/^OBSERVED VIA /, "").toLowerCase().replace(/\s+/g, "-")}`,

  /** AMEP needs these; say plainly which ones an AER-1 receipt supplies. */
  gaps(info, mapped) {
    return [
      { need: "origin authentication (who produced the record)", status: "missing",
        detail: "AER-1 receipts are not signed; hashes show integrity of the served bytes, not who served them. The importer's key becomes the AMEP observer, and assurance is capped at L1." },
      { need: "canonical action, resource and effect class", status: mapped.mappedFrom,
        detail: mapped.mappedFrom === "map" ? "taken from the deployment's published tool map" : "no tool map entry: cannot be derived" },
      { need: "binding to the authorizing call (AMEP invocation)", status: mapped.binding,
        detail: info.input_hash ? `input_hash uses layout "${info.input_hash_layout}"; AMEP binds with SHA-256 of RFC 8785 arguments (args_digest). With that layout, input_hash would equal args_digest.` : "no input_hash" },
      { need: "quantities (amounts, record counts)", status: "missing", detail: "no quantity member in AER-1; limits cannot be evaluated" },
      { need: "data classes released", status: mapped.released ? "map" : "missing",
        detail: mapped.released ? "declared by the deployment's tool map" : "no data-flow labels; the adapter refuses to import effects of class external_send or above without a declared release" },
    ];
  },
};
