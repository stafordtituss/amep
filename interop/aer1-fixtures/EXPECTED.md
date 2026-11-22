# Expected results for the AER-1 RFC 8785 fixtures, written before either side runs them

Protocol agreed in [stafordtituss/amep#11](https://github.com/stafordtituss/amep/issues/11):
1. Zambo publishes two fixtures under the new layout `rfc8785-jcs-utf8-v1`.
2. AMEP posts the expected results before either side runs them: this file, committed before any run.
3. Both sides run, and link their outputs, disagreements included.

The fixtures are Brennan Zambo's, at https://rambozambodotdev.gitlab.io/aer1-hub/fixtures/amep/. These expectations come from three things:
- the layout definition on that page;
- the statement that each fixture is its live record with only `input_hash_layout` changed;
- the code of `amep-conformance` at the commit that adds this file.

The fixtures themselves were not downloaded or run before this file was committed.

## How to run

From a clone of this repository at the commit that adds this file, after `(cd packages/conformance && npm install)`. `toolmap.json` is Zambo's published tool map from the 12-record run (gist `a70a6df5…`, revision `6668e558`).

```bash
node packages/conformance/bin/amep-conformance.mjs import completed-call-0bc28781.json --map toolmap.json \
  --expected-id 0bc28781-e16a-4232-b05e-ef4f19238e69 \
  --packet interop/aer1-fixtures/gateway-packet.json --keys interop/aer1-fixtures/gateway-keys.json
node packages/conformance/bin/amep-conformance.mjs import refusal-38a410ab.json --map toolmap.json \
  --expected-id 38a410ab-597e-45e0-9549-0b3bf2916b39
```

`gateway-packet.json` holds a mandate allowing `market.read` on `market:price/*` until 2026-12-31. It also holds the gateway's signed invocation `i-1`: `market.read market:price/BTC (read)`, at `2026-11-21T23:55:40Z`, with `args_digest` = SHA-256 of the RFC 8785 form of `{"symbol":"BTC"}`. Both are signed with deterministic test keys (`make-packet.mjs` regenerates them).

## Expected: fixture 1, completed call (receipt `0bc28781`, `live_price` BTC)

- **`input_hash`:** `sha256:f4a0911390334f5fb4042fc3ebdec2a0cebc5bb3862bdbb6b2ec0ecb9231be26`, with `input_hash_layout` `rfc8785-jcs-utf8-v1`. This is `args_digest({"symbol":"BTC"})`.
- **Format checks:** `pass (id matched)`, all six `ok`. `input_hash_layout` is not in the metadata block.
- **Mapping:** `mapped to AMEP: market.read market:price/BTC (read), assurance L1, binding digest`. The binding is made because `input_hash` equals the invocation's `args_digest`.
- **Verdict:** `AMEP verdict for the call: preserved -`, exit status 0.

## Expected: fixture 2, refusal (receipt `38a410ab`, `live_price`, OBSERVED VIA GATEWAY)

- **Format checks:** `pass (id matched)`, all six `ok`.
- **Mapping:** `not imported: the record's committed output says the call was not executed (status "payment_required"): there is no effect to import; a confirmed non-execution needs the server's signed not_executed call statement`.
- **Verdict:** exit status 1, and no AMEP verdict is computed. With any packet holding an invocation for the attempt, that call stays `unresolved` (gap `receipt`): an unsigned record can neither show an effect nor confirm that nothing ran.

## One thing to know before running

The importer binds by **digest equality**: an `input_hash` that equals the invocation's `args_digest` binds the record to it. It doesn't read `input_hash_layout`. Two consequences:
- **For this argument shape, the old layout already binds.** A single string member serializes to the same bytes under `zambo-json-sorted-keys-utf8-v1` and RFC 8785. The live record `0bc28781` has the same `input_hash` and gives the same result. What the fixture shows is that the labelled layout carries the binding for any argument shape, where the old layout coincides only for some.
- **The importer's gap text.** For a record whose layout already declares RFC 8785, the text still describes the old layout's relation to `args_digest`. That's a wording issue in the report, not a change in the result; it will be fixed after the run, not before.
