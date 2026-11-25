# What can be established about an agent's actions: an evidence-gap worksheet

**For:** anyone trying to understand afterwards what an AI agent did on their behalf, such as a user, an investigator or a support team. It assumes no access to the provider's systems.

**How to use it:** take each question in turn and fill in the last three columns from what you hold. The worksheet won't tell you what happened. It tells you, question by question, what *can* be established, from which record, and which records are missing.

**Two rules run through it:**
- **A missing record is a named gap, never an answer.** "No log of it" does not mean "it didn't happen", and it does not mean "the control worked".
- **Permission inside the operator's environment is not the user's authorization.** A system that allowed an action shows what the system allowed. It doesn't show what the user agreed to.

This is general guidance, not legal advice. It doesn't refer to any particular case.

## The five questions

| # | Question | Records that would settle it | Usually held by | What you hold | Established? | Gap, if any |
|---|---|---|---|---|---|---|
| 1 | **What was the agent documented or configured to do?** | The product documentation for the version in use. The configuration in effect at the time: enabled tools, permission settings and auto-approve options. The agent's own instructions, such as a system prompt or rules file. | Configuration: often on the user's device, as settings files. Documentation: public, but versions change, so save a dated copy. The system prompt: the provider. | | | |
| 2 | **What did the environment permit?** | The permission settings (allow, ask, deny), sandbox settings, and the operating-system account the agent ran under. The access that account had to files, network and other apps. | The user's device (settings, OS account), and the provider for hosted parts. | | | |
| 3 | **What can be established from preserved records?** | Records from a party other than the agent of what actually changed (see "Below the agent" below), and the agent's own transcript or log, labelled as the agent's own account. | The device (OS records, file history, backups); the provider (server logs); third parties (email servers, banks, websites). | | | |
| 4 | **Did the user explicitly authorize this action?** | A record of the approval bound to *this* action and its details, such as the recipient, the file and the amount, at the time it was made: an approval prompt and its answer, not a general setting. | The app (approval history, if kept), the provider, or the user's own screenshots. | | | |
| 5 | **What can the user verify independently, afterwards?** | Anything on this list that doesn't depend on the provider's word: device records, third-party records, and signed records whose signature anyone can check. | The user, and third parties. | | | |

## Below the agent: records that don't depend on the agent's account

The boundary between the agent's execution environment and the device's operating system is where an independent record most often exists without anyone having planned it. Places to look, depending on the system:
- **File system:** modification and creation times, version history (for example a cloud drive's file versions), and local snapshots or backups from before and after the period.
- **Operating-system logs:** process start and stop, and security and audit logs where enabled. These can show which program ran and when, even if they don't show why.
- **Version control:** commits, reflogs and remote push records. The remote host keeps its own record of what arrived.
- **Third parties:** sent-mail folders and the receiving server, bank and payment records, and the access logs of the websites or services the agent used. Each is held by someone other than the agent's provider.

**Preserve first, then analyse.** Copy logs and snapshots before they rotate or expire, and note when and how each was copied.

## For each record you find, note four things

1. **Who wrote it,** and whether that party is the agent or its operator (the "actor"), or someone else.
2. **Whether it can be checked,** for example signed, held by a third party or timestamped by someone other than the actor.
3. **What it covers,** and what it doesn't. An approval prompt covers one action, not every later one.
4. **When it was preserved,** and by whom.

## Reading the result

For each question, the honest answer is one of:
- **Established:** a record from a party other than the actor settles it.
- **Contradicted:** a record from a party other than the actor shows the opposite of what was claimed.
- **Not established:** the record that would settle it is missing or held only by the actor. Name the missing record.

A question that comes out "not established" is still a finding. It tells you exactly which record to ask for, and from whom.

## Where this comes from

These five questions were set out in a discussion of the AI Safety Working Group. The method is the one AMEP's verifier uses: each conclusion rests on a named record from a named party, and a missing record is reported as a gap, not as success (`LIMITS.md`; `interop/in-toto/OBSERVED-EFFECT.md` for records from below the agent).
