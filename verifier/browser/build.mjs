// Builds verifier/browser/amep-verify.html: a single offline page that runs the shared evaluation core
// (verifier/typescript/amep_core.mjs) with WebCrypto Ed25519, embeds the conformance suite, and lets anyone
// paste a packet. Run from the repo root: node verifier/browser/build.mjs
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const core = readFileSync(join(root, "verifier/typescript/amep_core.mjs"), "utf8").replace(/^export /gm, "");
const keys = JSON.parse(readFileSync(join(root, "vectors/keys.json"), "utf8"));
const suite = [];
for (const sub of ["positive", "must-reject"])
  for (const f of readdirSync(join(root, "vectors", sub)).filter(f => f.endsWith(".json")).sort())
    suite.push({ file: `${sub}/${f}`, ...JSON.parse(readFileSync(join(root, "vectors", sub, f), "utf8")) });
const embed = JSON.stringify({ keys, suite }).replace(/</g, "\\u003c");

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AMEP Verifier</title>
<style>
:root { --bg:#f7f8fa; --panel:#ffffff; --text:#1b1f24; --muted:#5b6470; --line:#dde1e6; --accent:#2457c5;
  --ok:#1a7f45; --ok-bg:#e6f4ec; --bad:#b42318; --bad-bg:#fdecea; --warn:#9a6700; --warn-bg:#fff4d6; }
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { --bg:#0f1216; --panel:#171b21; --text:#e6e9ee;
  --muted:#9aa4b0; --line:#2a3039; --accent:#7aa2ff; --ok:#56d08a; --ok-bg:#12291d; --bad:#ff8a80; --bad-bg:#2e1513; --warn:#f2c14e; --warn-bg:#2b2310; } }
:root[data-theme="dark"] { --bg:#0f1216; --panel:#171b21; --text:#e6e9ee; --muted:#9aa4b0; --line:#2a3039; --accent:#7aa2ff;
  --ok:#56d08a; --ok-bg:#12291d; --bad:#ff8a80; --bad-bg:#2e1513; --warn:#f2c14e; --warn-bg:#2b2310; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; }
main { max-width:960px; margin:0 auto; padding:32px 16px 64px; }
h1 { font-size:24px; margin:0 0 4px; } h2 { font-size:17px; margin:0 0 12px; }
p.lead { color:var(--muted); margin:0 0 24px; }
section { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:20px; margin-bottom:20px; }
button { font:inherit; background:var(--accent); color:#fff; border:0; border-radius:7px; padding:8px 14px; cursor:pointer; }
button:focus-visible, textarea:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
textarea { width:100%; min-height:160px; font:12.5px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; background:var(--bg);
  color:var(--text); border:1px solid var(--line); border-radius:7px; padding:10px; resize:vertical; }
label { display:block; font-weight:600; margin:12px 0 6px; }
.summary { margin:12px 0; font-weight:600; }
.table-wrap { overflow-x:auto; }
table { width:100%; border-collapse:collapse; font-size:13.5px; }
th, td { text-align:left; padding:7px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; }
code { font:12.5px ui-monospace, SFMono-Regular, Menlo, monospace; }
.pill { display:inline-block; padding:1px 8px; border-radius:999px; font-size:12.5px; font-weight:600; white-space:nowrap; }
.preserved { color:var(--ok); background:var(--ok-bg); } .violated { color:var(--bad); background:var(--bad-bg); }
.unresolved { color:var(--warn); background:var(--warn-bg); }
.note { color:var(--muted); font-size:13px; }
#unsupported { display:none; color:var(--bad); }
</style>
</head>
<body>
<main>
<h1>AMEP Verifier</h1>
<p class="lead">Checks AMEP v0.2 evidence packets entirely in this page. Nothing is uploaded. Signatures are verified with your browser's WebCrypto Ed25519.</p>
<p id="unsupported">This browser does not support Ed25519 in WebCrypto, so signatures cannot be checked here. Use a current Chrome, Edge, Safari or Firefox, or the command-line verifiers.</p>

<section>
<h2>Conformance suite</h2>
<p class="note">Runs every embedded vector and compares the verdict and deciding invariant with the expected result.</p>
<button id="run-suite">Run all vectors</button>
<div class="summary" id="suite-summary" aria-live="polite"></div>
<div class="table-wrap"><table id="suite-table" hidden><thead><tr><th>Vector</th><th>Expected</th><th>Got</th><th>Reason</th></tr></thead><tbody></tbody></table></div>
</section>

<section>
<h2>Check a packet</h2>
<label for="packet">Packet (JSON)</label>
<textarea id="packet" spellcheck="false" placeholder='{ "mandates": [...], "invocations": [...], "effects": [...] }'></textarea>
<label for="keys">Key set (JSON, as served at /.well-known/amep-keys.json)</label>
<textarea id="keys" spellcheck="false"></textarea>
<p><button id="run-packet">Verify packet</button> <button id="load-example" style="background:transparent;color:var(--accent);border:1px solid var(--line)">Load an example</button></p>
<div class="summary" id="packet-summary" aria-live="polite"></div>
<div class="table-wrap"><table id="packet-table" hidden><thead><tr><th>Object</th><th>Outcome</th><th>Invariant</th><th>Reason</th></tr></thead><tbody></tbody></table></div>
</section>
<p class="note">AMEP v0.2.0-draft.3 · evaluation code generated from <code>verifier/typescript/amep_core.mjs</code> · suite of ${suite.length} vectors.</p>
</main>
<script id="amep-data" type="application/json">${embed}</script>
<script>
${core}
const DATA = JSON.parse(document.getElementById("amep-data").textContent);
const hex = h => Uint8Array.from(h.match(/../g) || [], b => parseInt(b, 16));
const enc = new TextEncoder();

// WebCrypto is async; the core is synchronous. Verify every signed object first, then evaluate.
async function precompute(packet, keys) {
  const cache = new WeakMap(), imported = {};
  const objects = Object.values(packet).filter(Array.isArray).flat().filter(o => o && typeof o === "object" && o.proof);
  for (const o of objects) {
    const k = keys[o.proof.kid];
    if (!k || k.alg !== "Ed25519" || o.proof.alg !== "Ed25519") { cache.set(o, false); continue; }
    try {
      imported[k.kid] ??= await crypto.subtle.importKey("raw", hex(k.x), { name: "Ed25519" }, false, ["verify"]);
      cache.set(o, await crypto.subtle.verify({ name: "Ed25519" }, imported[k.kid], hex(o.proof.sig), enc.encode(canon(stripProof(o)))));
    } catch { cache.set(o, false); }
  }
  return (o) => cache.get(o) === true;
}
async function run(packet, keys) { return evaluate(packet, keys, await precompute(packet, keys)); }
const pill = o => '<span class="pill ' + o + '">' + o + '</span>';
const esc = s => String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

async function ed25519Supported() {
  try { await crypto.subtle.importKey("raw", new Uint8Array(32), { name: "Ed25519" }, false, ["verify"]); return true; } catch { return false; }
}

document.getElementById("run-suite").onclick = async () => {
  const body = document.querySelector("#suite-table tbody"); body.innerHTML = ""; let ok = 0;
  for (const v of DATA.suite) {
    const r = verdict(await run(v.packet, DATA.keys));
    const pass = r.outcome === v.expect.outcome && r.invariant === v.expect.invariant; ok += pass;
    body.insertAdjacentHTML("beforeend", "<tr><td><code>" + esc(v.file) + "</code></td><td>" + pill(v.expect.outcome) + " " + esc(v.expect.invariant) +
      "</td><td>" + pill(r.outcome) + " " + esc(r.invariant) + (pass ? "" : " ✗") + "</td><td>" + esc(r.reason) + "</td></tr>");
  }
  document.getElementById("suite-table").hidden = false;
  document.getElementById("suite-summary").textContent = "Agrees with expected outcomes on " + ok + "/" + DATA.suite.length + " vectors.";
};

document.getElementById("load-example").onclick = () => {
  const v = DATA.suite.find(v => v.file.includes("revoked-root-with-live-child")) || DATA.suite[0];
  document.getElementById("packet").value = JSON.stringify(v.packet, null, 2);
  document.getElementById("keys").value = JSON.stringify(DATA.keys, null, 2);
};

document.getElementById("run-packet").onclick = async () => {
  const summary = document.getElementById("packet-summary"), table = document.getElementById("packet-table");
  let packet, keys;
  try { packet = JSON.parse(document.getElementById("packet").value); keys = JSON.parse(document.getElementById("keys").value); }
  catch (e) { summary.textContent = "Not valid JSON: " + e.message; table.hidden = true; return; }
  const res = await run(packet, keys), v = verdict(res);
  table.querySelector("tbody").innerHTML = res.map(r => "<tr><td><code>" + esc(r.id) + "</code></td><td>" + pill(r.outcome) + "</td><td>" + esc(r.invariant) + "</td><td>" + esc(r.reason) + "</td></tr>").join("");
  table.hidden = false;
  summary.innerHTML = "Packet verdict: " + pill(v.outcome) + " " + esc(v.invariant);
};

ed25519Supported().then(ok => { if (!ok) document.getElementById("unsupported").style.display = "block"; });
</script>
</body>
</html>
`;
writeFileSync(join(root, "verifier/browser/amep-verify.html"), html);
console.log(`wrote verifier/browser/amep-verify.html (${suite.length} vectors, ${Math.round(html.length / 1024)} KB)`);
