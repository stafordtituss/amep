# Contributors

AMEP is written and edited by Staford Titus Selvaraj. Much of what it gets right came from other people: reviews that found real bugs, test cases written from other systems, and independent runs that checked it against itself. Each entry below links to the public record. Being listed credits a contribution; it doesn't imply endorsement of AMEP.

To be added, or to change how you're described, open an issue or a pull request.

## Implementations and independent runs

- **Brennan Zambo** (Zambo): the first independent implementation of the AMEP verifier, zambo-amep-verify, written from the specification and the vectors alone ([#19](https://github.com/stafordtituss/amep/issues/19)). Also the AER-1 conformance run ([#11](https://github.com/stafordtituss/amep/issues/11)), the review that removed the fail-closed shortcut ([#15](https://github.com/stafordtituss/amep/issues/15)), four specification clarifications, and the review of operation identity that tightened what releases a hold ([#24](https://github.com/stafordtituss/amep/pull/24)).
- **nmatt1** (paymnts): the APAF-1 verifier column over AMEP's AP2 fixtures, and the `payment.reference` finding that led to AP2 checkout binding ([AP2 #402](https://github.com/google-agentic-commerce/AP2/issues/402)).

## Reviews and findings that changed the specification

- **Cliff Singletary** (Cerydora): revocation evaluated at each effect's time, not only at the invocation. The three `singletary-case-*` vectors carry his name (IETF audit list, 19 November 2026; spec 5.12).
- **Carlos Vendrell Felici** (Zealynx Security): the payments review of quantity limits ([#10](https://github.com/stafordtituss/amep/issues/10)).
- **Andrii** (Radiolaria): revoked keys accepted by both verifiers, a false `not_executed` from the MCP producer, and the operation-identity gap (OpenID AIIM list, 24 November 2026; [#22](https://github.com/stafordtituss/amep/pull/22), [#24](https://github.com/stafordtituss/amep/pull/24)).
- **Takao Sato** (VATE): the lost-response and accepted-but-interrupted cases behind held approvals (openid/authzen#795; Poke-nushi/Verifiable-Agent-Trust-Envelope#138, #139).
- **Tom Farley** (ScopeBlind): the protect-mcp wire format and the meaning of `policy_digest` ([ScopeBlind #31](https://github.com/ScopeBlind/scopeblind-gateway/issues/31)).
- **Sankalp Gilda**: the verdict predicate's subject should be the admitted artifact ([in-toto/attestation#625](https://github.com/in-toto/attestation/pull/625)).
- **yuzhou** (ZYZ666-RGB): what Teleport's MCP audit events establish, with code references ([gravitational/teleport#70011](https://github.com/gravitational/teleport/discussions/70011)).

## Collaborations

- **Tania Aizenman and David Luna** (EAGF): contributors to AMEP-Proposal-1 (EvaluationRecord), and co-workers on the EAGF test appendix.

## Thanks

Everyone who asked a hard question on a list or in an issue. Several of the vectors exist because someone asked "what happens if…".
