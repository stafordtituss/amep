# amep-conformance (experimental)

Test any AMEP implementation against the conformance suites, and bring execution records from other formats into AMEP evidence.

> **Status: experimental**, version 0.1.0-experimental.1. The command-line interface may change. Results name the exact suites they ran (SHA-256 of every vector file), so they stay reproducible.

## `verify`: test your verifier, in any language

Your verifier only needs to read a packet and a key set and print its verdict as JSON. The tool runs every vector of every suite through it:

```bash
node packages/conformance/bin/amep-conformance.mjs verify \
  --name my-verifier --version 1.2.0 \
  --cmd "my-verifier check {packet} --keys {keys} {state}" \
  --json results.json --md results.md
```

**Placeholders in `--cmd`.** No shell is used, so quote paths that contain spaces:

| Placeholder | Replaced by |
|---|---|
| `{packet}` | a file holding the packet as JSON text. For parser vectors these are the exact bytes, including duplicate member names. |
| `{keys}` | the key set |
| `{state}` | `--state <file>` when a vector carries verifier state from earlier packets, otherwise nothing |

**What the command must print.** On stdout: `{"outcome": "...", "invariant": "..."}`, or the same object under `"verdict"`. A crash, a timeout or output that isn't JSON counts as a miss, never a pass.

**Suites.** By default the tool runs three: `vectors/`, `interop/approval-path-attacks/` and `interop/w3c-agent-identity/delegation-continuity/`, 282 vectors in all. Add `--suite DIR` to run others.

**Results.** `results.json` records the implementation, the tool version, each suite's SHA-256 and pass counts, and every disagreement. `results.md` is a summary ready to paste into an [implementation report](https://github.com/stafordtituss/amep/issues/new?template=implementation-report.yml).

**Reference results (2026-11-24):**

| Verifier | Result |
|---|---|
| Python `amep-protocol` | 306/306 |
| JavaScript `@stafordtituss/amep` | 306/306 |
| A verifier that answers "preserved" to everything | 82/306: every positive vector, no must-reject vector |

## `import`: bring your own records

AMEP evaluates whether executed effects stayed within delegated authority. Other formats record what happened. The import adapter checks a record by its own format's rules, maps it to an AMEP effect, and reports what AMEP needs that the record does not carry. With an AMEP packet that holds the authorizing mandate and invocation, it also gives the verdict.

From a fresh clone, install the tool's one dependency (the JavaScript reference package in this repository) first:

```bash
(cd packages/conformance && npm install)
node packages/conformance/bin/amep-conformance.mjs import receipt.json --map toolmap.json \
  --packet gateway-packet.json --keys gateway-keys.json --invocation i-1
```

### Profiles

A profile teaches the adapter one format:
- how to recognize it;
- its own integrity rules;
- what it records;
- the assurance level and observer for what it produces;
- its gaps.

| Profile | Format | Integrity checks |
|---|---|---|
| `aer1` | AER-1 execution receipts (draft-zambo-aer1) | id, `created_at` (including leap seconds and impossible dates), provenance class, canonical base64, strict UTF-8, `output_hash`, `metadata_hash` |
| `oidf-action-receipt` | OpenID DA execution layer action receipts (`delegation:action-receipt`, v0.2 §6.4; the format AuthZEN #795 names) | statement class, `audit_id`, delegation references, action descriptor, outcome, the decision attestation's `audit_id`, and no executed action under a non-permit decision. Mapping and results: [`interop/oidf-delegated-authorization/MAPPING.md`](../../interop/oidf-delegated-authorization/MAPPING.md) |

Adding a format means adding one profile file to `src/profiles/`. Nothing else changes.

### Books of records: `import-book`

Some formats record a whole session as one file: a permission, then every action, with countersignatures and seals. `import-book` checks every record by the format's own rules first, re-expresses the verified records as AMEP evidence signed by the importer, and gives the AMEP verdict for every action:

```bash
node packages/conformance/bin/amep-conformance.mjs import-book book.jsonl --json report.json
```

| Profile | Format | Integrity checks |
|---|---|---|
| `provared` | Provared books (draft-izmaylov-agent-permission-receipts, github.com/provared/provared) | envelope, protected-header labels, canonical form, both hybrid signatures (Ed25519 under AMEP's strict acceptance rule, and ML-DSA-87), the slip's and approvals' passkey (WebAuthn) signatures, fingerprints, the chain, countersignature and approval binding. ML-DSA-87 needs Node 24.7 or later; on an older runtime the profile reports it as not checked and never passes it. Comparison with the format's own checker on its sample book: [`interop/provared/`](../../interop/provared/README.md) |

### The tool map

What a tool call means in AMEP terms is not recorded by these formats. It comes from a map the deployment publishes:

```json
{ "tools": { "live_price": { "action": "market.read", "resource": "market:price/{provenance.request.symbol}", "effect": "read" } } }
```

Templates fill from the record's own fields.

### What the adapter refuses to do

- **Invent a value.** If the map has no entry for a tool, or the record lacks a field the resource template needs, the effect is not produced, and the call stays `unresolved`.
- **Accept a record that fails its own format's checks.**
- **Understate a call.** If the record's committed side effects contradict a `read` mapping, the import is refused.
- **Import a call that did not run.** If the record's committed output says the call was not executed (for example, an AER-1 record of a call a gateway refused), no effect is produced. An unsigned record can't confirm non-execution either, which needs the server's signed `not_executed` call statement, so the call stays `unresolved`. Only committed content counts; display fields outside the record's hash are ignored. Reported by Brennan Zambo in [amep#11](https://github.com/stafordtituss/amep/issues/11).
- **Import high-impact effects without a declared release.** An effect of class `external_send` or above needs `released` in the map.
- **Claim more than it knows.** AER-1 records are unsigned, so derived effects are reconstructions: assurance is capped at L1, and the importer's own key signs them as the AMEP observer.
- **Map a limit inexactly.** A Provared limit AMEP can't express exactly (a cap an approval can't lift, a count, or a sliding window) is reported as a gap instead of being approximated.

### Binding to the authorizing call

- **By digest.** If a record's input commitment equals the invocation's `args_digest` (SHA-256 of the RFC 8785 form of the arguments), the binding is made by digest.
- **Asserted.** Otherwise the caller names the invocation with `--invocation`, and the report says the binding is asserted by the importer.

## Tests

```bash
cd packages/conformance && npm install && npm test
```

The tests include synthetic AER-1 receipts for each AER-1 rule. The tool was also run against a live public AER-1 receipt, which passed all its format checks, mapped to `market.read market:price/ETH` and came out `preserved` under a mandate for `market:price/*`, and `violated` (I2) under one for `market:price/BTC` only. That receipt is not included in the repository.
