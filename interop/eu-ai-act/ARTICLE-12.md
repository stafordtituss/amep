# AMEP and EU AI Act Article 12 (record-keeping)

**Who it's for:** auditors and providers of high-risk AI systems that act through agents and tools.

**What it isn't:** legal advice or a conformity claim.
- AMEP doesn't make a system compliant.
- No harmonised standard for Article 12 logging is final; the drafts in progress include prEN 18229-1 and ISO/IEC DIS 24970.
- The application dates for high-risk obligations have been changed by the Digital Omnibus. Check the Official Journal for the dates that apply to you.

## What Article 12 asks, and what AMEP records

Article 12(1) requires that a high-risk system technically allows the **automatic recording of events (logs)** over its lifetime. Article 12(2) asks that the logging allow recording the events relevant for three purposes.

| Article 12(2) purpose | What AMEP evidence records |
|---|---|
| (a) identifying situations that may result in a risk, or in a substantial modification | Every tool call an agent makes, with the authority it acted under. A call outside that authority is a named finding (`violated`, with the invariant and the party that departed first), not a line to search for. |
| (b) post-market monitoring (Article 72) | Packets are portable and offline-checkable, so they can be collected across deployments and re-evaluated as rules tighten. |
| (c) monitoring the operation of the system (Article 26(5), deployers) | What was executed, signed by the system that executed it, kept apart from what the agent declared. A tool that did something other than requested is caught. |

## What AMEP adds to a log

- **Integrity and origin.** Each record is signed by the party that made it: the person or organization granting authority, the agent's host, the executing tool. A log line can be edited by whoever holds the log.
- **A deterministic reading.** Two auditors with the same records and keys reach the same verdict. A missing record is reported as `unresolved` with the record named, never as "fine".
- **Independence where it matters.** For high-impact effects, the record of what happened must come from a party other than the agent's host (I10).

## What it doesn't cover

- **Completeness.** AMEP can't show that no unrecorded action happened. For file systems, an Observed Effect record from an observer below the agent closes part of this (`interop/in-toto/OBSERVED-EFFECT.md`).
- **Retention, access control and the biometric minimums of Article 12(3).** These are properties of where the records are kept, and outside the format.
- **Accountable owner.** Who answers for an agent is proposed in AMEP-Proposal-2, not yet in the core.
