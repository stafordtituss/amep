// Completeness from an Observed Effect record: reconcile() against two statements from the predicate's own corpus.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { reconcile } from "../src/observed-effect.mjs";

const fx = f => JSON.parse(readFileSync(new URL(`./fixtures/observed-effect/${f}`, import.meta.url), "utf8"));
const SRC = fx("SOURCE.json"), observer = SRC.keys.observer;
const BASE = fx("authoritative-baseline.json"), VOL = fx("voluntary-self-vantage.json");
const pathMap = [{ resource: "repo:app/", path: "/srv/app/" }];
const keys = { "host-1": { kid: "host-1", alg: "Ed25519", x: "00".repeat(32), roles: ["host"] } };
const inv = (id, file, t) => ({ id, kind: "invocation", t, declared: { action: "fs.write", resource: `repo:app/${file}`, effect: "write_local" } });
const eff = (id, invocation, file, t) => ({ id, kind: "effect", invocation, observed_by: "hook:host",
  executed: { action: "fs.write", resource: `repo:app/${file}`, effect: "write_local", released: [], t } });
const T1 = "2026-09-19T00:00:01Z", T2 = "2026-09-19T00:00:02Z", T3 = "2026-09-19T00:00:03Z";
const run = (packet, over = {}) => reconcile({ envelope: BASE, observer, oeVerdict: SRC.expected["authoritative-baseline"], packet, keys, pathMap, ...over });

test("both writes have receipts: accounted, absence established, authority not bound to this packet", () => {
  const r = run({ invocations: [inv("i-1", "main.py", T1), inv("i-2", "handler.py", T2)],
    effects: [eff("e-1", "i-1", "main.py", T1), eff("e-2", "i-2", "handler.py", T2)] });
  assert.equal(r.usable, true);
  assert.equal(r.absence, true);
  assert.deepEqual(r.accounted.map(a => a.path), ["/srv/app/main.py", "/srv/app/handler.py"]);
  assert.deepEqual([r.unaccounted_writes, r.unobserved_receipts, r.settled], [[], [], []]);
  assert.equal(r.authority.bound, false);
});

test("a write with no receipt and no call is reported as unaccounted (I11)", () => {
  const r = run({ invocations: [inv("i-1", "main.py", T1)], effects: [eff("e-1", "i-1", "main.py", T1)] });
  assert.deepEqual(r.unaccounted_writes.map(w => w.path), ["/srv/app/handler.py"]);
});

test("a call with no receipt whose write the observer saw: its outcome is settled as wrote", () => {
  const r = run({ invocations: [inv("i-1", "main.py", T1), inv("i-2", "handler.py", T2)], effects: [eff("e-1", "i-1", "main.py", T1)] });
  assert.deepEqual(r.settled.map(s => [s.invocation, s.outcome]), [["i-2", "wrote"]]);
  assert.deepEqual(r.unaccounted_writes, []);
});

test("an in-scope call with no write anywhere: settled as no write, because absence is established", () => {
  const r = run({ invocations: [inv("i-1", "main.py", T1), inv("i-2", "handler.py", T2), inv("i-3", "other.py", T3)],
    effects: [eff("e-1", "i-1", "main.py", T1), eff("e-2", "i-2", "handler.py", T2)] });
  assert.deepEqual(r.settled.map(s => [s.invocation, s.outcome]), [["i-3", "no write in scope"]]);
});

test("a receipt for a write the observer never saw is a contradiction", () => {
  const r = run({ invocations: [inv("i-1", "main.py", T1), inv("i-2", "handler.py", T2), inv("i-3", "other.py", T3)],
    effects: [eff("e-1", "i-1", "main.py", T1), eff("e-2", "i-2", "handler.py", T2), eff("e-3", "i-3", "other.py", T3)] });
  assert.deepEqual(r.unobserved_receipts.map(u => u.effect), ["e-3"]);
  assert.match(r.unobserved_receipts[0].finding, /contradict/);
});

test("nothing is concluded outside the scope or the interval", () => {
  const r = run({ invocations: [inv("i-9", "../etc/passwd", T1), inv("i-8", "late.py", "2026-09-19T00:01:00Z")], effects: [] });
  assert.deepEqual(r.settled, []);
  assert.equal(r.not_concluded.length, 2);
});

test("a voluntary record (self vantage): writes count, but a missing write proves nothing", () => {
  const r = reconcile({ envelope: VOL, observer, oeVerdict: SRC.expected["voluntary-self-vantage"], keys, pathMap,
    packet: { invocations: [inv("i-3", "other.py", T3)], effects: [] } });
  assert.equal(r.usable, true);
  assert.equal(r.absence, false);
  assert.ok(r.settled.every(s => s.outcome !== "no write in scope"));
});

test("a tampered payload, an observer that is the host, or a verdict other than valid: unusable", () => {
  const bad = { ...BASE, payload: Buffer.from(Buffer.from(BASE.payload, "base64").toString().replace("main.py", "mainx.py")).toString("base64") };
  assert.equal(run({ effects: [] }, { envelope: bad }).usable, false);
  assert.equal(run({ effects: [] }, { keys: { h: { x: observer.publicKey, roles: ["host"] } } }).usable, false);
  assert.equal(run({ effects: [] }, { oeVerdict: { verdict: "malformed" } }).usable, false);
});
