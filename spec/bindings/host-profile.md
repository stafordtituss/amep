# AMEP Binding: Agent Host Profile (`amep-host`)

| | |
|---|---|
| **Document** | `amep-binding-host` |
| **Version** | 0.2.0-draft.4 |
| **Status** | Public Draft. Companion to `spec/amep-v0.2.md` (the "core"). |

This profile maps agent-host lifecycle hooks (in coding agents and similar hosts) onto AMEP objects, and defines how a PEP running as a hook must declare and record what the host can enforce.

The key words MUST, SHOULD and MAY are used as in BCP 14 (RFC 2119, RFC 8174).

## 1. Event mapping

| Host event (generic) | AMEP object | Notes |
|---|---|---|
| Session start | — | Load the mandate for the session; check revocation status (core 5.12). |
| Prompt submitted | IntentCertificate | `prompt_ref` = SHA-256 of the prompt and session id. `derivation` is `template` or `judge` unless the user confirmed it. |
| Instructions or files loaded into context | ContentFinding | One per untrusted source (repository files, web pages, tool output). |
| Sub-agent started | Delegation | Claims MUST be narrower than the parent's (I1). |
| Before tool use | Invocation + ContinuityDecision | The hook is the PEP. Mediation uses the host's input-rewrite capability. |
| After tool use | ExecutedEffectReceipt | Assurance L1 (recorded by the host, outside the model). |
| Configuration changed | — | Any change to protected resources is an I9 event. |

The hook process signs Invocations, Decisions and Findings with a `host`-role key that the model cannot read. It SHOULD sign effect receipts with a separate `observer`-role key, so that a compromise of one key does not let an attacker both act and attest.

## 2. Capability declaration

Hosts differ in what a hook can do. A host binding MUST declare these capabilities, and every ContinuityDecision MUST record them in `enforcement` (core 5.13.1):

| Capability | Meaning |
|---|---|
| `ask` | The hook can pause and ask the person in the host UI. |
| `deny` | The hook can block the call. |
| `rewrite_input` | The hook can replace the call's input (needed for `mediate`). |
| `replace_output` | The hook can replace the tool's output before the model sees it (content quarantine). |
| `fail_closed` | The host blocks the call when the hook errors or times out. |

### 2.1 Informative: capabilities observed in November 2026

The table below records implementation experience. Hosts change quickly. Implementers MUST check the host's current documentation, and SHOULD test fail-closed behaviour directly (kill the hook mid-call and see whether the action runs).

| Capability | Claude Code | Cursor | Codex | Gemini CLI |
|---|---|---|---|---|
| `ask` | yes | shell/MCP yes; file read no | no (treated as a hook failure, so the action runs) | no |
| `deny` | yes | yes | yes | yes |
| `rewrite_input` | yes | yes | yes (command) | yes |
| `replace_output` | yes (output shape must match) | not documented | not documented | deny with reason only |
| `fail_closed` | yes (configurable) | yes (configurable) | no | no (exit code 2 only) |

## 3. Encoding rules

- **No `ask`.** A `step_up` or `hold` MUST be encoded as `deny` with a link to an out-of-band approval, recorded as `encoded_as: "deny+approval_link"`. The retry MUST cite an ApprovalBinding that satisfies I8. Bind the approval to the command's canonical form, the working directory, the session and the resource versions.
- **No `fail_closed`.** `enforcement.fail_mode` MUST be `open`, and the deployment MUST NOT claim conformance Level 2 or above without a compensating control (sandbox, egress proxy or credential broker) that is itself recorded in `enforcement.pep`.
- **Hook errors.** The hook MUST return a deny response on internal error or timeout, never exit with a transport-level failure that the host treats as non-blocking.
- **Contradiction.** If an after-tool-use event arrives for a call the hook denied, the hook MUST record the effect and set `applied: "contradicted"` on the decision. Verifiers treat this as I11 (core 10.3).

## 4. Canonical resources

Hooks receive tool inputs in host-specific forms. Before building an Invocation the hook MUST canonicalize resources (core 6.2): expand `~`, resolve relative paths against the session's working directory, collapse `..`, and resolve symbolic links where possible. Shell commands MUST be interpreted by a curated adapter (I3). A command the adapter cannot fully interpret (pipelines into `sh`, `eval`, encoded payloads, script indirection) MUST be interpreted with `source: "none"`, which yields `unresolved`.

## 5. Protected resources

The host profile adds to the core registry (core 19.7): the host's own hook configuration, the PEP's configuration and keys, and the evidence store. A deployment MUST pass these to its verifier as protected paths.
