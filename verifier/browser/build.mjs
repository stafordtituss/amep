// Builds verifier/browser/amep-verify.html: a single offline page that runs the shared evaluation core
// (packages/js/src/core.mjs) with WebCrypto Ed25519, embeds the conformance suite, and lets anyone
// paste a packet. Run from the repo root: node verifier/browser/build.mjs
// Optional arguments build the same page over another vector set (a folder with keys.json, positive/, must-reject/):
//   node verifier/browser/build.mjs <vectors dir> <output .html> "<page title>"
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const [argDir, argOut, argTitle] = process.argv.slice(2);
const vecDir = argDir ? resolve(argDir) : join(root, "vectors");
const outFile = argOut ? resolve(argOut) : join(root, "verifier/browser/amep-verify.html");
const title = argTitle || "AMEP Verifier";
const core = readFileSync(join(root, "packages/js/src/core.mjs"), "utf8").replace(/^export /gm, "");
const keys = JSON.parse(readFileSync(join(vecDir, "keys.json"), "utf8"));
const suite = [];
for (const sub of ["positive", "must-reject"])
  for (const f of readdirSync(join(vecDir, sub)).filter(f => f.endsWith(".json")).sort())
    suite.push({ file: `${sub}/${f}`, ...JSON.parse(readFileSync(join(vecDir, sub, f), "utf8")) });
const htmlEsc = s => s.replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const embed = JSON.stringify({ keys, suite }).replace(/</g, "\\u003c");

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${htmlEsc(title)}</title>
<style>
/* The site's design language (docs/index.html): ink ground, condensed display, mono for anything checkable.
   No web fonts or other outside requests, so the page stays fully offline. */
:root { --bg:#0a0e13; --panel:#111821; --panel-2:#17212d; --text:#ece8df; --muted:#8c99a8; --line:#243140; --accent:#8fc3ff; --warm:#e08a3c;
  --ok:#67d39b; --ok-bg:rgba(103,211,155,.12); --bad:#ff6b57; --bad-bg:rgba(255,107,87,.12); --warn:#f2c14e; --warn-bg:rgba(242,193,78,.12);
  --display:"Big Shoulders Display","Avenir Next Condensed","Arial Narrow","Roboto Condensed",sans-serif;
  --body:"Instrument Sans",system-ui,-apple-system,"Segoe UI",sans-serif;
  --mono:"JetBrains Mono",ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace; color-scheme:dark; }
@media (prefers-color-scheme: light) { :root:not([data-theme="dark"]) { --bg:#f4f1ea; --panel:#fbfaf6; --panel-2:#ffffff; --text:#121a26; --muted:#586474;
  --line:#d6d0c2; --accent:#1f5fa6; --warm:#b65f14; --ok:#1d8350; --ok-bg:#e3f2e9; --bad:#c4321e; --bad-bg:#fbe7e3; --warn:#9a6a00; --warn-bg:#fbf0d4; color-scheme:light; } }
:root[data-theme="light"] { --bg:#f4f1ea; --panel:#fbfaf6; --panel-2:#ffffff; --text:#121a26; --muted:#586474; --line:#d6d0c2; --accent:#1f5fa6; --warm:#b65f14;
  --ok:#1d8350; --ok-bg:#e3f2e9; --bad:#c4321e; --bad-bg:#fbe7e3; --warn:#9a6a00; --warn-bg:#fbf0d4; color-scheme:light; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.55 var(--body); }
a { color:inherit; }
header.site { border-bottom:1px solid var(--line); }
header.site div { max-width:1040px; margin:0 auto; display:flex; justify-content:space-between; align-items:center; gap:16px; flex-wrap:wrap;
  padding:14px max(16px, env(safe-area-inset-right, 0px)) 14px max(16px, env(safe-area-inset-left, 0px)); }
header.site a.mark { text-decoration:none; font:900 22px/1 var(--display); letter-spacing:.06em; }
header.site nav { display:flex; gap:18px; flex-wrap:wrap; font-size:14px; }
header.site nav a { color:var(--muted); text-decoration:none; } header.site nav a:hover { color:var(--text); }
main { max-width:1040px; margin:0 auto; padding:40px max(16px, env(safe-area-inset-right, 0px)) 72px max(16px, env(safe-area-inset-left, 0px)); }
.kicker { font:500 11.5px/1 var(--mono); letter-spacing:.16em; text-transform:uppercase; color:var(--muted); margin:0 0 10px; }
h1 { font:900 clamp(40px, 7vw, 76px)/.9 var(--display); text-transform:uppercase; margin:0 0 14px; letter-spacing:-.005em; }
h1 span { color:var(--accent); }
h2 { font:800 26px/1 var(--display); text-transform:uppercase; letter-spacing:.02em; margin:0 0 8px; }
p.lead { color:var(--muted); margin:0 0 32px; max-width:40em; font-size:16px; }
section { background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:24px; margin-bottom:20px; }
button { font:700 17px/1 var(--display); text-transform:uppercase; letter-spacing:.05em; background:var(--accent); color:var(--bg); border:0; border-radius:3px; padding:12px 16px; cursor:pointer; }
button.ghost { background:transparent; color:var(--accent); border:1px solid var(--line); }
button:focus-visible, textarea:focus-visible, a:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
textarea { width:100%; min-height:170px; font:12.5px/1.5 var(--mono); background:var(--panel-2); color:var(--text); border:1px solid var(--line); border-radius:4px; padding:12px; resize:vertical; }
label { display:block; font:500 11.5px/1 var(--mono); letter-spacing:.12em; text-transform:uppercase; color:var(--muted); margin:18px 0 8px; }
.summary { margin:14px 0; font:600 14px/1.4 var(--mono); }
.table-wrap { overflow-x:auto; }
table { width:100%; border-collapse:collapse; font:12.5px/1.45 var(--mono); font-variant-numeric:tabular-nums; }
th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:500; text-transform:uppercase; letter-spacing:.1em; font-size:10.5px; }
code { font:12.5px var(--mono); }
.pill { display:inline-block; padding:2px 8px; border-radius:3px; font:700 11px/1.5 var(--mono); text-transform:uppercase; letter-spacing:.06em; white-space:nowrap; }
.preserved { color:var(--ok); background:var(--ok-bg); } .violated { color:var(--bad); background:var(--bad-bg); }
.unresolved { color:var(--warn); background:var(--warn-bg); }
.note { color:var(--muted); font-size:13px; }
#unsupported { display:none; color:var(--bad); }
</style>
</head>
<body>
<header class="site"><div>
<a class="mark" href="../">AMEP</a>
<nav aria-label="Main"><a href="../#mandate">Mandate</a><a href="../#evidence">Evidence</a><a href="../#verdict">Verdict</a><a href="https://github.com/stafordtituss/amep">GitHub</a></nav>
</div></header>
<main>
<p class="kicker">Verifier · runs in this page</p>
<h1>Check the <span>evidence.</span></h1>
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
<p><button id="run-packet">Verify packet</button> <button id="load-example" class="ghost">Load an example</button></p>
<div class="summary" id="packet-summary" aria-live="polite"></div>
<div class="table-wrap"><table id="packet-table" hidden><thead><tr><th>Object</th><th>Outcome</th><th>Invariant</th><th>Reason</th></tr></thead><tbody></tbody></table></div>
</section>
<p class="note">AMEP v0.3.0-draft.1 · evaluation code generated from <code>packages/js/src/core.mjs</code> · suite of ${suite.length} vectors.</p>
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
      cache.set(o, await crypto.subtle.verify({ name: "Ed25519" }, imported[k.kid], hex(o.proof.sig), enc.encode(signingInput(o))));
    } catch { cache.set(o, false); }
  }
  return (o) => cache.get(o) === true;
}
async function run(packet, keys, state) { return evaluate(packet, keys, await precompute(packet, keys), [], state ? structuredClone(state) : {}); }
const pill = o => '<span class="pill ' + o + '">' + o + '</span>';
const esc = s => String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

async function ed25519Supported() {
  try { await crypto.subtle.importKey("raw", new Uint8Array(32), { name: "Ed25519" }, false, ["verify"]); return true; } catch { return false; }
}

document.getElementById("run-suite").onclick = async () => {
  const body = document.querySelector("#suite-table tbody"); body.innerHTML = ""; let ok = 0;
  for (const v of DATA.suite) {
    let pk = v.packet, r;
    if (v.packet_text !== undefined) { try { pk = parseStrict(v.packet_text); } catch (e) { r = { outcome: "unresolved", invariant: "I7", reason: "malformed packet text: " + e.message }; } }
    r ??= verdict(await run(pk, DATA.keys, v.state));
    const pass = r.outcome === v.expect.outcome && r.invariant === v.expect.invariant; ok += pass;
    body.insertAdjacentHTML("beforeend", "<tr><td><code>" + esc(v.file) + "</code></td><td>" + pill(v.expect.outcome) + " " + esc(v.expect.invariant) +
      "</td><td>" + pill(r.outcome) + " " + esc(r.invariant) + (pass ? "" : " ✗") + "</td><td>" + esc(r.reason) + "</td></tr>");
  }
  document.getElementById("suite-table").hidden = false;
  document.getElementById("suite-summary").textContent = "Agrees with expected outcomes on " + ok + "/" + DATA.suite.length + " vectors.";
};

document.getElementById("load-example").onclick = () => {
  const v = DATA.suite.find(v => v.file.includes("revoked-root-with-live-child") || v.file.includes("root-revoked-before-action")) || DATA.suite.find(v => v.packet);
  document.getElementById("packet").value = JSON.stringify(v.packet, null, 2);
  document.getElementById("keys").value = JSON.stringify(DATA.keys, null, 2);
};

document.getElementById("run-packet").onclick = async () => {
  const summary = document.getElementById("packet-summary"), table = document.getElementById("packet-table");
  let packet, keys;
  try { keys = JSON.parse(document.getElementById("keys").value); }
  catch (e) { summary.textContent = "Keys are not valid JSON: " + e.message; table.hidden = true; return; }
  // the packet is parsed strictly (spec 12.1): duplicate member names and inexact number literals are malformed
  try { packet = parseStrict(document.getElementById("packet").value); }
  catch (e) { summary.innerHTML = "Packet verdict: " + pill("unresolved") + " I7 (malformed packet text: " + esc(e.message) + ")"; table.hidden = true; return; }
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
writeFileSync(outFile, html);
// The same page is served by GitHub Pages from docs/verify/ (https://stafordtituss.github.io/amep/verify/), so anyone can try AMEP
// in a browser without installing anything. Written only for the default build, so it never drifts from the checked page.
if (!argOut) { mkdirSync(join(root, "docs/verify"), { recursive: true }); writeFileSync(join(root, "docs/verify/index.html"), html); writeFileSync(join(root, "docs/.nojekyll"), ""); }
console.log(`wrote ${outFile} (${suite.length} vectors, ${Math.round(html.length / 1024)} KB)`);
