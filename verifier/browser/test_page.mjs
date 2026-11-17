// Headless test of amep-verify.html: runs the page's own inline script in a VM with WebCrypto (Node >= 22)
// and a minimal DOM stub, clicks "Run all vectors" and "Verify packet", and checks the results.
// Run from the repo root: node verifier/browser/test_page.mjs
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const html = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "amep-verify.html"), "utf8");
const data = html.match(/<script id="amep-data" type="application\/json">([\s\S]*?)<\/script>/)[1];
const script = html.match(/<script>\n([\s\S]*?)<\/script>/)[1];

const els = {};
const el = id => (els[id] ??= { id, style: {}, hidden: true, textContent: id === "amep-data" ? data : "", innerHTML: "", value: "",
  insertAdjacentHTML(_, s) { this.innerHTML += s; }, querySelector() { return el(id + ":tbody"); } });
const document = { getElementById: el, querySelector: sel => el(sel) };
const ctx = vm.createContext({ document, crypto: globalThis.crypto, TextEncoder, console, Uint8Array, WeakMap, Promise, JSON });
vm.runInContext(script, ctx);

await el("run-suite").onclick();
const suite = el("suite-summary").textContent;
console.log("suite:", suite);
const failed = (el("#suite-table tbody").innerHTML.match(/✗/g) || []).length;

el("load-example").onclick();
await el("run-packet").onclick();
const packet = el("packet-summary").innerHTML.replace(/<[^>]+>/g, "");
console.log("example packet:", packet);

const total = JSON.parse(data).suite.length;
const ok = suite.includes(`${total}/${total}`) && failed === 0 && packet.includes("violated I6");
console.log(ok ? "PASS" : "FAIL"); process.exit(ok ? 0 : 1);
