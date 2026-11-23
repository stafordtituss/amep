# Audit exercise: pre-registration

Registered on 23 November 2026, before any reviewer has seen a case.

**Question.** After an AI agent acts, can a competent reviewer establish three things:
1. what the agent was authorized to do;
2. what actually happened;
3. what remains unknown?

And does it make a difference whether they have the records a team ordinarily keeps (the agent's log, the tool gateway's access log, the policy file), or signed AMEP evidence for the same events?

**Design.** Nine synthetic cases in three sets of three, each built from one ground truth in both forms:

| | Set A (documents) | Set B (payments) | Set C (invoice matching) |
|---|---|---|---|
| 1 | Refused email send | Refused over-cap payment | Match recorded; payment not approved |
| 2 | Timed-out write, retried | Timed-out payment, retried | Approval attempt refused |
| 3 | Helper outside its delegation | Helper outside its delegation | Timed-out match write, reconciled |

**Counterbalancing.** Each reviewer reads one set as ordinary records and a matched set as AMEP evidence:
- general reviewers: A and B;
- finance reviewers: B and C.

The order alternates between reviewers. No reviewer sees both forms of one case.

**Measures, per case and question:**
- correct, partly correct, or incorrect against the sealed key;
- whether an unknown was correctly identified, or the source that would settle it was named;
- minutes taken;
- stated confidence.

Each reviewer's free-text answers are quoted, including where the signed evidence added work or changed nothing, and whether they'd change a procedure. Results are reported per reviewer, as a small case study, not as averages.

**Disclosure.** Each reviewer's relationship to the author (none; colleague; prospective employer; earlier reviewer of AMEP) is recorded and reported beside their results.

**Sealed materials.** The kit and its answer key are held privately until each reviewer has finished. Their SHA-256 digests are fixed here, so that anyone can check later that neither changed:

| File | SHA-256 |
|---|---|
| `answer-key.json` | `b2a85e3a62abfb50074921c3c89e83ded3c0879ef72fd39b695c6f58749dd83a` |
| `kit-manifest.sha256` (67 files) | `4d042a7f613edc97150db43ed44b10981b8977442e87ffdb6c61677ed1eb2a2f` |
| `build.py` (generates the kit from ground truth) | `0870274abda29081762d299f9566801ab978275b27dc19078f41eb611e3c2b52` |

The cases were generated with AMEP at `505fe06`; reviewers who re-check the evidence use the published `amep-protocol` 0.3.0a2. After scoring, the kit, the key, the build script and the anonymized or named responses (each reviewer's choice) are published here. Any change to the kit after this date is reported as a deviation, with the new digests.

**Known limitation.** The author designed the cases and the ordinary-record baseline. Reviewers may name any further record they'd normally consult, and that counts toward "what remains unknown", so that a thin baseline can't favour the signed evidence.
