# OWASP Agentic Evidence: authorization-to-outcome scenarios as AMEP packets

The scenarios are OWASP/Agentic-Evidence#2 (A1 to A3, B1, B2, C) and #21 (D1 to D3, E1, E2), as their author, AngeYobo, defined them there. [`run.mjs`](run.mjs) encodes each evidence variant as an AMEP packet and evaluates it with AMEP's reference verifier. [`results.json`](results.json) holds every verdict and each packet's digest.

```bash
node interop/owasp-agentic-evidence/run.mjs
```

**What this is:** AMEP's reading of the scenario text, not the OWASP project's. The project defers signed evidence (OD-3), so its trust levels (`asserted`, `observed`, `verified`) appear here only as AMEP keys and operators:
- the executing side's own record is a key under the host's operator;
- the runner's effect oracle is a key under another operator.

The mapping is stated at the top of `run.mjs`.

**Two AMEP gaps this mapping found, both fixed:**
1. **A1:** an asserted `tool.result` beside an independent observation of the same write came out `unresolved`, because each receipt was judged on its own. Extra evidence weakened the verdict. It is now corroborated (I10, spec 10.2).
2. **D1 `unordered-revocation`:** AMEP ordered a revocation and a write timed by different operators' clocks as if one clock had produced both. A key may now declare `clock_skew`. Within the combined skew of the deciding boundary, the result is `unresolved` with gap `ordering` (spec 5.12.2, #43).
