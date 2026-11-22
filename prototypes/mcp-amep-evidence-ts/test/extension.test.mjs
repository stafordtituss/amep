// Integration tests for the amep-evidence extension on the official MCP TypeScript SDK (v2).
// Run:  npm test
// Each test runs a real MCP session (in process, over the SDK's HTTP handler, or over stdio) and checks the evidence
// with the AMEP reference verifier. Both protocol eras are covered: 2025-era (`initialize`) and 2026-07-28
// (`server/discover` plus a per-request `_meta` envelope).
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { McpServer, createMcpHandler } from "@modelcontextprotocol/server";
import { Client, InMemoryTransport, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { keyset, digest } from "@stafordtituss/amep";
import {
  EXTENSION_ID, INVOCATION_ID_KEY, RECEIPT_KEY, CALL_STATEMENT_KEY, clientCapabilities, receiptSettings, supportsReceipts,
} from "../src/extension.mjs";
import { Gateway, fetchKeySet } from "../src/gateway.mjs";
import { ticketServer, KEYS_URL } from "../src/tickets-server.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const UPDATE = { action: "saas.update", resource: "tickets:issue/4821", effect: "write_shared" };
const MODERN = "2026-07-28";

/** Connect a client to a server factory. era: "legacy" (2025, in memory) or "modern" (2026-07-28, HTTP handler). */
async function connect(factory, { era, wants = true, capabilities } = {}) {
  const caps = capabilities ?? clientCapabilities({ wantsReceipts: wants });
  if (era === "legacy") {
    const [a, b] = InMemoryTransport.createLinkedPair();
    await factory().connect(a);
    const client = new Client({ name: "gateway", version: "0" }, { capabilities: caps });
    await client.connect(b);
    return client;
  }
  const handler = createMcpHandler(factory);
  const transport = new StreamableHTTPClientTransport(new URL("http://tickets.test/mcp"),
    { fetch: (url, init) => handler.fetch(new Request(url, init)) });
  const client = new Client({ name: "gateway", version: "0" },
    { capabilities: caps, versionNegotiation: { mode: { pin: MODERN } } });
  await client.connect(transport);
  return client;
}

async function runUpdate({ era, buggy = false, wants = true, tamper = false, rewrite = false, lose = false, replayFrom = null }) {
  const { factory, observerKey } = ticketServer({ buggy });
  const client = await connect(factory, { era, wants });
  if (rewrite) { // something between the gateway and the server changes the arguments after the gateway signed them
    const original = client.callTool.bind(client);
    client.callTool = (params, ...rest) => original({ ...params, arguments: { ...params.arguments, ticket_id: "4822" } }, ...rest);
  }
  if (lose) { // the tool runs, but the response never reaches the gateway
    const original = client.callTool.bind(client);
    client.callTool = async (...a) => { await original(...a); throw new Error("connection reset"); };
  }
  if (replayFrom) { // a genuine receipt from another call is presented as the receipt for this one
    const original = client.callTool.bind(client);
    client.callTool = async (...a) => {
      const r = await original(...a);
      return { ...r, _meta: { ...r._meta, [RECEIPT_KEY]: replayFrom } };
    };
  }
  if (tamper) { // a man-in-the-middle rewrites the receipt after the server signed it
    const original = client.callTool.bind(client);
    client.callTool = async (...a) => {
      const r = await original(...a);
      const receipt = r._meta?.[RECEIPT_KEY];
      if (receipt) receipt.executed.resource = "tickets:issue/9999";
      return r;
    };
  }
  const gw = new Gateway(client, keyset(observerKey));
  let result, error;
  try {
    result = await gw.call("update_ticket", { ticket_id: "4821", status: "closed" }, UPDATE);
  } catch (e) {
    error = e;
  }
  await client.close();
  return { gw, result, error };
}

const outcome = gw => { const { verdict } = gw.evaluate(); return [verdict.outcome, verdict.invariant]; };

for (const era of ["legacy", "modern"]) {
  describe(`protocol era: ${era === "legacy" ? "2025 (initialize)" : MODERN}`, () => {
    test("the server advertises the extension, and the client can discover it before calling a tool", async () => {
      const client = await connect(ticketServer().factory, { era });
      assert.deepEqual(receiptSettings(client), { revision: "0.3", effectReceipts: true, callStatements: true,
        receiptRecovery: "amep-receipt://{invocation}", keys: KEYS_URL });
      assert.equal(supportsReceipts(client), true);
      await client.close();
    });

    test("an honest server: signed receipt, verdict preserved", async () => {
      const { gw, result } = await runUpdate({ era });
      assert.equal(result.content[0].text, "ticket 4821 is now closed"); // result content unchanged
      assert.equal(gw.receipts.length, 1);
      assert.deepEqual(outcome(gw), ["preserved", "-"]);
    });

    test("a server that changes a different ticket than requested is exposed by its own receipt: violated I2", async () => {
      const { gw } = await runUpdate({ era, buggy: true });
      assert.deepEqual(outcome(gw), ["violated", "I2"]);
    });

    test("a client that did not opt in gets no receipt, and missing evidence is never permission: unresolved I7", async () => {
      const { gw, result } = await runUpdate({ era, wants: false });
      assert.equal(result._meta?.[RECEIPT_KEY], undefined);
      assert.deepEqual(outcome(gw), ["unresolved", "I7"]);
    });

    test("a receipt tampered with in transit is rejected: unresolved I7", async () => {
      const { gw } = await runUpdate({ era, tamper: true });
      assert.deepEqual([gw.receipts.length, gw.rejected.length], [0, 1]);
      assert.deepEqual(outcome(gw), ["unresolved", "I7"]);
    });

    test("a tool that executes nothing returns no receipt, and a signed statement that nothing was executed", async () => {
      const client = await connect(ticketServer().factory, { era });
      const r = await client.callTool({ name: "validate_only", arguments: { ticket_id: "4821" },
        _meta: { [INVOCATION_ID_KEY]: "i-1" } });
      assert.equal(r._meta?.[RECEIPT_KEY], undefined);
      assert.deepEqual([r._meta[CALL_STATEMENT_KEY].disposition, r._meta[CALL_STATEMENT_KEY].effect_count], ["not_executed", 0]);
      await client.close();
    });

    test("a no-op call is provably preserved, not unresolved: the verifier can tell 'nothing ran' from 'no receipt'", async () => {
      const { factory, observerKey } = ticketServer();
      const client = await connect(factory, { era });
      const gw = new Gateway(client, keyset(observerKey));
      await gw.call("validate_only", { ticket_id: "4821" }, { action: "saas.read", resource: "tickets:issue/4821", effect: "read" });
      await client.close();
      assert.deepEqual([gw.receipts.length, gw.statements.length], [0, 1]);
      assert.deepEqual(outcome(gw), ["preserved", "-"]);
    });

    test("evidence is bound to the exact signed invocation and to the arguments the server received", async () => {
      const { gw } = await runUpdate({ era });
      const [inv] = gw.invocations, [st] = gw.statements, [rc] = gw.receipts;
      assert.match(inv.id, /^i-[0-9a-f-]{36}$/);   // 122 random bits (UUIDv4): never reused, never guessable
      assert.equal(st.invocation_digest, digest(inv));
      assert.equal(rc.invocation_digest, digest(inv));
      assert.equal(st.args_digest, inv.args_digest);
      assert.deepEqual([st.disposition, st.effect_count, inv.proof.v, st.proof.v, rc.proof.v], ["completed", 1, 2, 2, 2]);
      assert.equal(gw.packet().amep_version, "0.3");
    });

    test("arguments changed in transit are exposed by the server's own statement: violated I2", async () => {
      const { gw } = await runUpdate({ era, rewrite: true });
      assert.notEqual(gw.statements[0].args_digest, gw.invocations[0].args_digest);
      assert.deepEqual(outcome(gw), ["violated", "I2"]);
    });

    test("a genuine receipt from another call is rejected; the statement shows one receipt missing: unresolved I7", async () => {
      const first = await runUpdate({ era });
      const { gw } = await runUpdate({ era, replayFrom: first.gw.receipts[0] });
      assert.equal(gw.rejected.length, 1);
      assert.deepEqual(outcome(gw), ["unresolved", "I7"]);
    });

    test("a lost response is recovered with resources/read, and the call is still verified", async () => {
      const { gw, error } = await runUpdate({ era, lose: true });
      assert.match(String(error), /connection reset/);
      assert.deepEqual([gw.statements.length, gw.receipts.length], [1, 1]);
      assert.deepEqual(outcome(gw), ["preserved", "-"]);
    });

    test("a server without the extension works exactly as in core MCP", async () => {
      const plain = () => {
        const mcp = new McpServer({ name: "plain", version: "0" });
        mcp.registerTool("ping", {}, async () => ({ content: [{ type: "text", text: "pong" }] }));
        return mcp;
      };
      const client = await connect(plain, { era });
      assert.equal(supportsReceipts(client), false);
      const r = await client.callTool({ name: "ping", arguments: {}, _meta: { [INVOCATION_ID_KEY]: "i-1" } });
      assert.equal(r.content[0].text, "pong");
      assert.equal(r._meta?.[RECEIPT_KEY], undefined);
      await client.close();
    });

    test("a client that does not know the extension sees plain results", async () => {
      const client = await connect(ticketServer().factory, { era, capabilities: {} });
      const r = await client.callTool({ name: "update_ticket", arguments: { ticket_id: "4821", status: "closed" },
        _meta: { [INVOCATION_ID_KEY]: "i-1" } });
      assert.equal(r._meta?.[RECEIPT_KEY], undefined);
      await client.close();
    });
  });
}

test("over the real stdio transport (serveStdio), a signed receipt arrives in the result's _meta", async () => {
  const client = new Client({ name: "gateway", version: "0" }, { capabilities: clientCapabilities() });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [join(HERE, "..", "src", "tickets-server.mjs")] }));
  assert.ok(Object.hasOwn(client.getServerCapabilities().extensions, EXTENSION_ID));
  const r = await client.callTool({ name: "update_ticket", arguments: { ticket_id: "4821", status: "closed" },
    _meta: { [INVOCATION_ID_KEY]: "i-1" } });
  await client.close();
  const receipt = r._meta[RECEIPT_KEY];
  assert.deepEqual([receipt.invocation, receipt.executed.resource, receipt.proof.alg], ["i-1", "tickets:issue/4821", "Ed25519"]);
});

describe("key discovery (spec 12.4)", () => {
  const serve = body => async url => {
    assert.equal(url, KEYS_URL);
    return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  };

  test("the gateway fetches the advertised key set and verifies receipts with it", async () => {
    const { factory, observerKey } = ticketServer();
    const client = await connect(factory, { era: "modern" });
    const keys = await Gateway.discoverKeys(client, { fetch: serve(keyset(observerKey)) });
    const gw = new Gateway(client, keys);
    await gw.call("update_ticket", { ticket_id: "4821", status: "closed" }, UPDATE);
    await client.close();
    assert.deepEqual(outcome(gw), ["preserved", "-"]);
  });

  test("only usable observer keys are kept: other roles, revoked and expired keys are dropped", async () => {
    const { observerKey } = ticketServer();
    const good = observerKey.publicEntry();
    const now = 1_800_000_000;
    const set = {
      [good.kid]: good,
      "issuer-x": { ...good, kid: "issuer-x", roles: ["issuer"] },
      "revoked-x": { ...good, kid: "revoked-x", revoked: true },
      "expired-x": { ...good, kid: "expired-x", exp: now - 1 },
      "mismatch": { ...good },
    };
    const keys = await fetchKeySet(KEYS_URL, { fetch: serve(set), now });
    assert.deepEqual(Object.keys(keys), [good.kid]);
  });

  test("a key set is only fetched over HTTPS", async () => {
    await assert.rejects(fetchKeySet("http://tickets.example/.well-known/amep-keys.json"), /HTTPS/);
  });

  test("a server key cannot vouch for a mandate: role pinning in the gateway", async () => {
    const { observerKey } = ticketServer();
    const set = { [observerKey.kid]: { ...observerKey.publicEntry(), roles: ["observer", "issuer"] } };
    const keys = await fetchKeySet(KEYS_URL, { fetch: serve(set) });
    assert.deepEqual(keys[observerKey.kid].roles, ["observer"]);
  });
});

test("the Python reference verifier returns the same verdicts on the packets this gateway produces", async (t) => {
  const repo = join(HERE, "..", "..", "..");
  const probe = spawnSync("python3", ["-c", "import amep_protocol"], { env: { ...process.env, PYTHONPATH: join(repo, "packages/python/src") } });
  if (probe.status !== 0) return t.skip("python3 with the AMEP Python package's dependencies is not available");
  const dir = mkdtempSync(join(tmpdir(), "amep-ts-"));
  for (const [name, opts, expected] of [
    ["honest", {}, ["preserved", "-"]],
    ["buggy", { buggy: true }, ["violated", "I2"]],
    ["no-receipt", { wants: false }, ["unresolved", "I7"]],
    ["rewritten-arguments", { rewrite: true }, ["violated", "I2"]],
    ["lost-response-recovered", { lose: true }, ["preserved", "-"]],
  ]) {
    for (const era of ["legacy", "modern"]) {
      const { gw } = await runUpdate({ era, ...opts });
      const p = join(dir, `${name}-${era}.packet.json`), k = join(dir, `${name}-${era}.keys.json`);
      writeFileSync(p, JSON.stringify(gw.packet()));
      writeFileSync(k, JSON.stringify(gw.keys));
      const r = spawnSync("python3", ["-m", "amep_protocol.cli", "verify", p, "--keys", k, "--json"],
        { env: { ...process.env, PYTHONPATH: join(repo, "packages/python/src") }, encoding: "utf8" });
      const v = JSON.parse(r.stdout).verdict;
      assert.deepEqual([v.outcome, v.invariant], expected, `${name} (${era}): ${r.stderr}`);
      assert.deepEqual(outcome(gw), expected);
    }
  }
});
