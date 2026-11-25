# Where the vectors came from

Many vectors exist because someone outside the project found a case AMEP got wrong, or asked "what happens if…". This file names them, group by group, with the public record. Names match [`CONTRIBUTORS.md`](../CONTRIBUTORS.md). Being credited here doesn't imply endorsement of AMEP.

The generator, `verifier/python/amep_verifier.py`, carries the same credit in a comment above each group.

| Vectors | From | Record |
|---|---|---|
| Revocation between invocation and effect, exactly at the effect, and between two effects of one call (the three "Singletary case" vectors) | Cliff Singletary (Cerydora) | IETF audit list, 19 November 2026 |
| Quantities and limits: per call, per effect, per observer, the counting observer, integer on-chain amounts, independent totals per limit, order-independent limits, totals for the wrong window | Carlos Vendrell Felici (Zealynx Security) | [#10](https://github.com/stafordtituss/amep/issues/10) |
| Call statements and binding to the exact invocation; a host's own `fail_mode` never settling "nothing executed" | Brennan Zambo | Review of the MCP extension proposal; [#15](https://github.com/stafordtituss/amep/issues/15) |
| Key status: revoked keys, and keys used outside their interval | Andrii (Radiolaria) | OpenID AIIM list, 24 November 2026; [#22](https://github.com/stafordtituss/amep/pull/22) |
| Operation identity: retries under fresh authorization, double execution, release of a hold | Andrii (Radiolaria); review by Brennan Zambo | [#24](https://github.com/stafordtituss/amep/pull/24) |
| Operation approvals | Takao Sato (VATE case 1) | openid/authzen#795 |
| Held approvals | Takao Sato (VATE case 2) | openid/authzen#795; Poke-nushi/Verifiable-Agent-Trust-Envelope#139 |
| Holds for unknown outcomes against period limits | Participants in the FINOS AI Governance Framework discussion | finos/ai-governance-framework#421 |
| Grants (a union of action and resource products) | The comparison with the Delegation Receipt Protocol | `interop/drp/` |
| Audience binding | Found with delegation-control-bench, scenario VC-03 | [#16](https://github.com/stafordtituss/amep/issues/16) |

**To add a vector of your own:** open an issue with the case. If it turns out to be right, it becomes a vector, credited here.
