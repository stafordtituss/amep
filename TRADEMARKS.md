# AMEP Trademark Policy

*Draft, 2026-11-17. Have an IP lawyer review this before publishing it.*

AMEP is an open specification. Anyone may read it, implement it, and build products on it, free of charge, under the licenses in `LICENSE-SPEC.md` and `LICENSE-CODE`.

**The names are different.** The licenses cover the text and the code. They do **not** grant rights to the following marks, which belong to **Staford Titus Selvaraj**, the original author of AMEP:

- **AMEP** (word mark)
- **Agentic Mandate Evidence Protocol**
- **AMEP Conformant** and the AMEP Conformant badge

This policy exists so that "AMEP" always means one thing: the specification published in the official repository, and implementations that actually pass its conformance suite.

## What you may do without asking

- **Refer to the specification:** "implements AMEP v0.2", "supports AMEP evidence export", "an AMEP verifier written in Rust".
- **Name a compatible project descriptively:** "amep-verifier-go", "Foo's AMEP adapter", provided it is clear the project is not the official one.
- **Write about AMEP:** articles, talks, papers, courses and comparisons.
- **Fork the spec or code** under their licenses, **under a different name** (see below).

## What requires passing the conformance suite

You may say **"AMEP Conformant"** or use the badge only if all of the following are true:

1. Your implementation passes **every** vector in a published conformance suite version.
2. Your claim names the spec version, the conformance level (0 to 5) and any "Attested" qualifier, the profile(s) and the suite version. For example: *"AMEP v0.2 Conformant: Level 4 (Verifier), suite 0.2.0"* or *"AMEP v0.2 Conformant: Level 2, Attested, AMEP-Coding, suite 0.2.0"*.
3. You list the result in the public conformance registry in the repository (a pull request with your test output).

Self-certification is enough while the suite is the authority. If a listing turns out to be false, it is removed and the claim must stop.

## What you may not do

- Call a **modified** version of the specification "AMEP", "AMEP 2", "AMEP+", "Open AMEP" or anything confusingly similar. Forks must use a different name and must state that they are derived from AMEP.
- Claim conformance without passing the suite, or after your implementation stops passing it.
- Suggest that your product, company or fork is endorsed by, or is the official home of, AMEP.
- Use the marks in a company name, product name, or domain name in a way that suggests it is the official AMEP.
- Register "AMEP" or a confusingly similar mark, domain or social handle for agent-security or authorization goods and services.

## Transfer to a foundation

The marks are intended to transfer to a neutral foundation when AMEP joins one (see `CHARTER.md`). This policy will continue to apply under the new owner.

## Contact

Questions or permission requests: open an issue in the official AMEP repository with the label `trademark`.
