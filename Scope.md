# Scope

This Scope applies to the AMEP project, which acts as the "Working Group" under the Community Specification License 1.0 (`LICENSE-SPEC.md`, section 9.13).

The **AMEP project** develops the Agentic Mandate Evidence Protocol in this repository. It is maintained by Staford Titus Selvaraj, the original author of AMEP. It is an open-source project, not a working group of a standards body such as the IETF or W3C.

## In scope

The project develops specifications, schemas, conformance vectors and reference verifiers for:

1. evidence objects that record how authority is delegated to and exercised by automated agents: mandates, delegations, intents, interpretations, invocations, executed effects, approvals, revocations, revocation status, content findings and decisions;
2. the claim model, attenuation rules and invariants used to evaluate that evidence, and the evaluation procedure that returns preserved, violated or unresolved;
3. canonicalization, signing, signer roles and key discovery for that evidence;
4. bindings of that evidence to other protocols (such as OAuth, OpenID AuthZEN, the Model Context Protocol, agent host hooks and OpenTelemetry), and profiles for carrying it in other token and envelope formats (such as Biscuit, Macaroons, PASETO and W3C Verifiable Credentials);
5. conformance levels and the conformance suite.

## Out of scope

- Issuing identities or credentials to agents.
- General-purpose policy languages and decision engines.
- Methods for detecting prompt injection or other model-level attacks. AMEP records such findings but does not define how they are made.
- Storage and transport of logs, except as needed for the bindings above.
