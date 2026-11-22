#!/usr/bin/env node
// amep-protocol command-line tool (JavaScript). Same commands and exit codes as the Python package:
//   amep-protocol verify PACKET --keys KEYS [--state FILE] [--state-out FILE] [--protected PATH ...] [--json]
//   amep-protocol check-suite DIR
//   amep-protocol keygen --kid KID --roles issuer,approver --out PREFIX
//   amep-protocol sign OBJECT --key PEM --kid KID [--roles ROLES]
//   amep-protocol approval-digest BODY
//   amep-protocol version
// verify exits 0 preserved, 1 violated, 2 unresolved, 3 usage or input error.
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { evaluate, evaluateText, verdict, approvalDigest, parseStrict } from "../src/core.mjs";
import { sigOk, Key, ROLES } from "../src/node.mjs";
import { VERSION, SPEC_VERSION } from "../src/index.mjs";
import { statement, signEnvelope } from "../src/verdict.mjs";

const EXIT = { preserved: 0, violated: 1, unresolved: 2 };
const load = p => parseStrict(readFileSync(p === "-" ? 0 : p, "utf8"));   // spec 12.1: strict number literals
const roleList = s => (s || "").split(",").filter(Boolean);

function run(argv) {
  const [cmd, ...rest] = argv;
  const { values: o, positionals: pos } = parseArgs({ args: rest, allowPositionals: true, options: {
    keys: { type: "string" }, state: { type: "string" }, "state-out": { type: "string" },
    protected: { type: "string", multiple: true }, json: { type: "boolean" },
    kid: { type: "string" }, roles: { type: "string" }, out: { type: "string" }, key: { type: "string" },
    "verdict-out": { type: "string" }, "sign-with": { type: "string" }, "sign-kid": { type: "string" } } });
  switch (cmd) {
    case "verify": {
      if (!pos[0] || !o.keys) throw new Error("usage: amep-protocol verify PACKET --keys KEYS");
      const state = o.state ? load(o.state) : {};
      // the packet is parsed strictly inside evaluateText, so malformed text yields unresolved (I7) instead of an exception
      const bytes = readFileSync(pos[0] === "-" ? 0 : pos[0]), keySet = load(o.keys);
      const results = evaluateText(bytes.toString("utf8"), keySet, sigOk, o.protected || [], state);
      const v = verdict(results);
      if (o["state-out"]) writeFileSync(o["state-out"], JSON.stringify(state, null, 1));
      if (o["verdict-out"]) { // spec 10.8: an in-toto statement of this verdict, signed in a DSSE envelope with --sign-with
        let stmt = statement(bytes, keySet, results, { name: "@stafordtituss/amep", version: VERSION });
        if (o["sign-with"]) { const k = Key.fromPem(readFileSync(o["sign-with"]), o["sign-kid"] || "verifier", ["observer"]); stmt = signEnvelope(stmt, k.keyObject, k.kid); }
        writeFileSync(o["verdict-out"], JSON.stringify(stmt, null, 1));
      }
      if (o.json) console.log(JSON.stringify({ verdict: v, results }, null, 1));
      else { for (const r of results) console.log(`${r.id}\t${r.outcome}\t${r.invariant}\t${r.reason}`); console.log(`verdict: ${v.outcome} ${v.invariant}`); }
      return EXIT[v.outcome];
    }
    case "check-suite": {
      const dir = pos[0]; const keys = load(join(dir, "keys.json")); let n = 0, ok = 0;
      for (const sub of ["positive", "must-reject"]) for (const f of readdirSync(join(dir, sub)).filter(f => f.endsWith(".json")).sort()) {
        const v = load(join(dir, sub, f)); const st = v.state ? structuredClone(v.state) : {};
        const r = verdict(v.packet_text !== undefined ? evaluateText(v.packet_text, keys, sigOk, [], st) : evaluate(v.packet, keys, sigOk, [], st));
        n++; if (r.outcome === v.expect.outcome && r.invariant === v.expect.invariant) ok++; else console.log(`FAIL ${sub}/${f}: got ${r.outcome}/${r.invariant} (${r.reason})`);
      }
      console.log(`amep ${VERSION} agrees with expected outcomes on ${ok}/${n} vectors`);
      return ok === n && n ? 0 : 1;
    }
    case "keygen": {
      if (!o.kid || !o.roles || !o.out) throw new Error("usage: amep-protocol keygen --kid KID --roles ROLES --out PREFIX");
      const k = Key.generate(o.kid, roleList(o.roles)); k.save(`${o.out}.key.pem`);
      console.log(JSON.stringify({ [o.kid]: k.publicEntry() }, null, 1));
      console.error(`private key written to ${o.out}.key.pem (mode 0600); add the entry above to your key set`);
      return 0;
    }
    case "sign": {
      if (!pos[0] || !o.key || !o.kid) throw new Error("usage: amep-protocol sign OBJECT --key PEM --kid KID");
      const k = Key.fromPem(readFileSync(o.key, "utf8"), o.kid, roleList(o.roles).length ? roleList(o.roles) : ROLES);
      console.log(JSON.stringify(k.sign(load(pos[0])), null, 1));
      return 0;
    }
    case "approval-digest": console.log(approvalDigest(load(pos[0]))); return 0;
    case "version": console.log(`amep ${VERSION} (AMEP ${SPEC_VERSION})`); return 0;
    default: throw new Error("commands: verify, check-suite, keygen, sign, approval-digest, version");
  }
}

try { process.exitCode = run(process.argv.slice(2)); }
catch (e) { console.error(`amep-protocol: ${e.message}`); process.exitCode = 3; }
