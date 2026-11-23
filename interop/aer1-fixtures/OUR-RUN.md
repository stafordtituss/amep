# AMEP's run of the AER-1 RFC 8785 fixtures

The run of Brennan Zambo's two fixtures, following the protocol in [stafordtituss/amep#11](https://github.com/stafordtituss/amep/issues/11). The expected results were committed in `5f59f88` ([EXPECTED.md](EXPECTED.md)) before the fixtures were downloaded. Zambo's own run: https://rambozambodotdev.gitlab.io/aer1-hub/fixtures/amep/our-run-2026-11-22.md

**Result: both fixtures came out exactly as expected, on every point, and match Zambo's run.**

| Fixture | Expected (5f59f88) | AMEP's run | Zambo's run |
|---|---|---|---|
| Completed call `0bc28781` | `input_hash` = `args_digest({"symbol":"BTC"})`; six checks ok; binding by digest; `preserved`; exit 0 | the same | same `input_hash`; six checks pass; anchor verified |
| Refusal `38a410ab` | six checks ok; not imported (not executed, `payment_required`); exit 1 | the same | six checks pass; not executed; no import, unresolved |

## Inputs

| File | Source | SHA-256 |
|---|---|---|
| `completed-call-0bc28781.json` | https://rambozambodotdev.gitlab.io/aer1-hub/fixtures/amep/completed-call-0bc28781.json | `49f552c1848ec74258e543ca53a11dab5d86607ddf7fc41cc411bad4ad666e70` |
| `refusal-38a410ab.json` | https://rambozambodotdev.gitlab.io/aer1-hub/fixtures/amep/refusal-38a410ab.json | `fa5230aa9cb10e940d65d6fc0ad066834c1a17472f4f12ba6a38e96d771c9383` |
| `toolmap.json` | Zambo's tool map from the 12-record run (gist `a70a6df5…`, revision `6668e558`) | `16231e8bd465a410cb6a53a7502df9cc15146c1d8549bbae1175b0720c6be0e3` |

## Output, verbatim

Run from a checkout of this repository at `5f59f88`, the commit that holds the expected results, with Node.js 26.

```
$ git rev-parse HEAD
5f59f8831e7700a9e9563d66bea48fe13504a006
$ node --version
v26.13.1

$ node packages/conformance/bin/amep-conformance.mjs import completed-call-0bc28781.json --map toolmap.json --expected-id 0bc28781-e16a-4232-b05e-ef4f19238e69 --packet interop/aer1-fixtures/gateway-packet.json --keys interop/aer1-fixtures/gateway-keys.json
profile aer1: format checks pass (id matched)
  ok   id format (Section 3)
  ok   created_at valid (Section 6)
  ok   provenance class (Section 5)
  ok   canonical bytes: canonical base64, strict UTF-8 (Section 4)
  ok   output_hash = SHA-256(canonical bytes) (Section 4)
  ok   metadata_hash = SHA-256(metadata block) (Section 3.1)
mapped to AMEP: market.read market:price/BTC (read), assurance L1, binding digest
what AMEP needs that this record does not carry:
  [missing] origin authentication (who produced the record): AER-1 receipts are not signed; hashes show integrity of the served bytes, not who served them. The importer's key becomes the AMEP observer, and assurance is capped at L1.
  [map] canonical action, resource and effect class: taken from the deployment's published tool map
  [digest] binding to the authorizing call (AMEP invocation): input_hash uses layout "rfc8785-jcs-utf8-v1"; AMEP binds with SHA-256 of RFC 8785 arguments (args_digest). With that layout, input_hash would equal args_digest.
  [missing] quantities (amounts, record counts): no quantity member in AER-1; limits cannot be evaluated
  [missing] data classes released: no data-flow labels; the adapter refuses to import effects of class external_send or above without a declared release
AMEP verdict for the call: preserved - (continuity preserved)
[exit status: 0]

$ node packages/conformance/bin/amep-conformance.mjs import refusal-38a410ab.json --map toolmap.json --expected-id 38a410ab-597e-45e0-9549-0b3bf2916b39
profile aer1: format checks pass (id matched)
  ok   id format (Section 3)
  ok   created_at valid (Section 6)
  ok   provenance class (Section 5)
  ok   canonical bytes: canonical base64, strict UTF-8 (Section 4)
  ok   output_hash = SHA-256(canonical bytes) (Section 4)
  ok   metadata_hash = SHA-256(metadata block) (Section 3.1)
not imported: the record's committed output says the call was not executed (status "payment_required"): there is no effect to import; a confirmed non-execution needs the server's signed not_executed call statement
what AMEP needs that this record does not carry:
  [missing] origin authentication (who produced the record): AER-1 receipts are not signed; hashes show integrity of the served bytes, not who served them. The importer's key becomes the AMEP observer, and assurance is capped at L1.
  [map] canonical action, resource and effect class: taken from the deployment's published tool map
  [missing] binding to the authorizing call (AMEP invocation): input_hash uses layout "rfc8785-jcs-utf8-v1"; AMEP binds with SHA-256 of RFC 8785 arguments (args_digest). With that layout, input_hash would equal args_digest.
  [missing] quantities (amounts, record counts): no quantity member in AER-1; limits cannot be evaluated
  [missing] data classes released: no data-flow labels; the adapter refuses to import effects of class external_send or above without a declared release
[exit status: 1]
```

## Noted before the run, and seen in it

The gap text for binding still describes the old layout's relation to `args_digest`, even for a record whose layout already declares RFC 8785. That's wording only; the result is unchanged. It was deliberately left until after the run, so that the code that ran is the code the expectations were written against. It was fixed afterwards in `2b54ebd`.

## Regression check (added 2026-11-23)

[`regress.mjs`](regress.mjs) reruns both fixtures and checks the results that [EXPECTED.md](EXPECTED.md) (`5f59f88`) requires:
- for `0bc28781`: six format checks, binding by digest, `preserved`, exit status 0;
- for `38a410ab`: six format checks, **not imported** because nothing executed, no verdict, exit status 1.

It checks results, not wording, so the later fix to the gap text doesn't trip it.

```bash
(cd packages/conformance && npm install)
node interop/aer1-fixtures/regress.mjs            # fetches the fixtures and the tool map
node interop/aer1-fixtures/regress.mjs --dir DIR  # or uses local copies
```

- The inputs are pinned by the SHA-256 values above. If a fixture or the tool map changes upstream, the check stops with exit status 2 and names it, because the expectations were written for those bytes. Exit status 1 is a regression.
- It was tested against a mutant importer that imports the refusal as an effect: the check fails on `38a410ab` with exit status 1.
- The importer (`amep-conformance`) runs from this repository, because it isn't published yet. The verifier it uses can be pinned to the release: install `@stafordtituss/amep@0.3.0-alpha.2` from npm in `packages/conformance` and pass `--amep 0.3.0-alpha.2`. The check then refuses to run on anything else, including the in-repo package. It prints the commit and the verifier version and source it used. Both ways pass on 2026-11-23.
