# AMEP Profile: Verifiable Credentials (`AMEP-VC`)

| | |
|---|---|
| **Document** | `amep-profile-vc` |
| **Version** | 0.2.0-draft.4 |
| **Status** | Public Draft. Companion to `spec/amep-v0.2.md` (the "core"). |
| **Author** | Staford Titus Selvaraj |

The key words MUST, SHOULD and MAY are used as in BCP 14 (RFC 2119, RFC 8174).

## 1. Purpose

Auditors, regulators and customers increasingly accept evidence as W3C Verifiable Credentials (VC Data Model 2.0). This profile wraps AMEP evidence as a credential for that kind of exchange. The wrapper does not replace the AMEP proofs inside it.

## 2. Credential shape

| Member | Value |
|---|---|
| `@context` | the VC 2.0 context, then the AMEP context (its URL is a placeholder until the specification has a permanent home) |
| `type` | `VerifiableCredential`, `AmepEvidenceCredential` |
| `issuer` | the party exporting the evidence, as a DID or URL |
| `validFrom` | the export time |
| `credentialSubject.type` | `AmepPacket` |
| `credentialSubject.amepVersion` | `"0.2"` |
| `credentialSubject.packet` | the AMEP packet, every object keeping its own proof |
| `credentialSubject.verdict` | OPTIONAL: `{ outcome, invariant, suite }` as evaluated by the issuer |
| `proof` | a Data Integrity proof |

The cryptosuite `eddsa-jcs-2022` is RECOMMENDED, because it uses the same primitives as AMEP itself (JCS and Ed25519). A `verdict` is the issuer's own result; relying parties SHOULD re-run the evaluation rather than trust it.

## 3. Processing

A relying party:

1. verifies the credential's Data Integrity proof against its issuer;
2. extracts `credentialSubject.packet`;
3. evaluates it per core 10 with the AMEP key set.

The credential proof shows who exported the evidence. The AMEP proofs inside show who produced each piece of it, and only they determine the outcome.

## 4. Privacy

Exports to third parties SHOULD use selective disclosure or redaction of payload fields (core 18). Digests and canonical identifiers are enough for evaluation.
