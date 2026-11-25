# Completeness from an Observed Effect record

**The source:** the [Observed Effect predicate](https://github.com/in-toto/attestation/pull/607) (in-toto/attestation#607, by probityai). It records what changed in a file tree over an interval, as seen by an observer the agent doesn't control. The test statements used here come from its corpus, probityai/agent-evidence-vectors v0.17.5 (Apache-2.0).

**The question it answers for AMEP:** AMEP checks the records it's given. It can't see an effect nobody recorded (`LIMITS.md`, section A). An Observed Effect record that its own verifier grades `authoritative`, with absence established, says what else happened, or didn't, in a path scope over an interval.

## What `reconcile()` does

`packages/conformance/src/observed-effect.mjs` takes one Observed Effect statement and an AMEP packet, and reports:

| Finding | Meaning |
|---|---|
| **accounted** | A write in the record matches an AMEP receipt at the same path, in the interval. |
| **unaccounted write** | The observer saw a write that no receipt and no call accounts for. The presented evidence is incomplete, or an effect had no authorized call (I11). |
| **unobserved receipt** | An AMEP receipt for a write the observer didn't see. With absence established, the two contradict each other. |
| **settled: wrote** | A call with no receipt, whose write the observer saw. Its outcome is known, and the missing receipt is the gap. |
| **settled: no write in scope** | A call with no receipt and no write in the record, with absence established. The call wrote nothing in the record's scope. |
| **not concluded** | Anything outside the scope or the interval, or a path that doesn't normalize. |

## Who checks what

- **The record's own validity** (its write chain, prior commitment, tier recompute and the rest of its 41 conditions) is checked by the predicate's verifier. The caller passes that verifier's result in, and `reconcile()` never upgrades it.
- **`reconcile()` checks what AMEP relies on:**
  - the DSSE signature under the observer key the caller names;
  - the predicate type;
  - that the subject is the after-state;
  - that the observer key isn't one of the agent host's keys.

  It also reports whether the record's `authorityDigest` is the digest of a mandate or delegation in the packet.
- **Paths are normalized before any scope test.** A resource such as `repo:app/../etc/passwd` is refused, not read as inside `/srv/app/`. The test suite found this case.

## Limits

- **Only what the record asserts.** The record's own `doesNotAssert` list is passed through. For example, it says nothing about actions outside its path scope.
- **"No write observed" is absence only when the supplied verdict established absence.** A `voluntary` record can confirm writes, but not their absence.
- **Mapping resources to paths** comes from a prefix map the deployment declares, not from either record.
