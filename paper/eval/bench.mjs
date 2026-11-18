// Per-vector evaluation time of the JavaScript verifier (Node.js, signature checks included).
// Run from the repository root: node paper/eval/bench.mjs
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { verifyPacket } from "../../packages/js/src/index.mjs";

const median = a => { const s = [...a].sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
for (const [name, dir] of [["core", "vectors"], ["delegation", "interop/w3c-agent-identity/delegation-continuity"]]) {
  const keys = JSON.parse(readFileSync(join(dir, "keys.json"), "utf8"));
  const per = [];
  for (const sub of ["positive", "must-reject"])
    for (const f of readdirSync(join(dir, sub)).filter(f => f.endsWith(".json")).sort()) {
      const v = JSON.parse(readFileSync(join(dir, sub, f), "utf8"));
      const run = () => verifyPacket(v.packet, keys, { state: v.state ? structuredClone(v.state) : {} }).verdict;
      run();
      const ts = [];
      for (let i = 0; i < 50; i++) { const t = performance.now(); run(); ts.push(performance.now() - t); }
      per.push(median(ts));
    }
  console.log(`suite ${name.padEnd(10)} n=${per.length}  median ${median(per).toFixed(3)} ms  max ${Math.max(...per).toFixed(3)} ms  total ${per.reduce((a, b) => a + b, 0).toFixed(1)} ms`);
}
