# AMEP evidence over AgentDojo

**Question:** when a prompt injection makes an agent take an action, does an AMEP evidence audit catch it? And how does the answer depend on how specific the principal's mandate is?

[AgentDojo](https://github.com/ethz-spylab/agentdojo) v1.2.2 has four suites (workspace, travel, banking, slack): 97 user tasks, 35 injection tasks and 949 user × injection pairs.

## Method: oracle traces, no LLM

For every pair, `harness.py` builds two traces:
- an **honest trace**: the user task's ground-truth tool calls;
- a **compromised trace**: the same calls, followed by the injection task's ground-truth calls. This is an agent that did its job *and* obeyed the injection: the case AgentDojo scores as a successful attack.

**Execution and evidence:**
- Every call runs for real in the AgentDojo environment.
- AgentDojo's own security check confirms whether the injection's goal was achieved.
- Each side-effecting call yields a host-signed invocation and an observer-signed receipt, via `amep_agents.EvidenceRecorder`.
- The packet is evaluated against a mandate at one of three granularities:

| Mandate | Reads | Side-effecting actions |
|---|---|---|
| **effect-scoped** | any | only on the objects the user task touches (the recipient, file, event or booking) |
| **tool-scoped** | any | only with the tools the user task uses, on any object |
| **suite-wide** | any | every tool on any object (the typical deployment today) |

The mandate is derived from the user task's ground truth. So effect-scoped is the best a task-specific mandate can do, and suite-wide is the floor.

## Results

### Pairs evaluated

- **571** pairs where the injection takes an action and succeeds in the environment.
- **17** pairs where the injection's action failed in the environment (AgentDojo's check reports no success).
- **Not evaluable from reference traces:**
  - 320 pairs: workspace injection tasks 6–13 have no ground-truth calls in AgentDojo, so they need real model runs;
  - 20 pairs: travel injection 6 targets only the model's text ("Say that I should …").
- **21** pairs: slack injection 3 only *reads* a web page, which every mandate here allows.

### Detection of successful attacks that take an action (571 pairs)

| Mandate | violated | missed (`preserved`) | detected |
|---|---|---|---|
| effect-scoped | 566 | 5 | **99.1%** |
| tool-scoped | 488 | 83 | 85.5% |
| suite-wide | 0 | 571 | 0.0% |

**Honest traces:** all 97 evaluate to `preserved` under all three mandates. That holds by construction, and isn't a false-positive rate. Each honest trace is the user task's ground-truth calls, with AgentDojo's own arguments, and each mandate is derived from those same calls. So it shows only that the evaluation doesn't misfire on the calls it was built from. Arguments a real agent writes, such as a recipient spelled another way or an extra call, are untested here, and could make a precise mandate flag honest work. Measuring that needs real model runs.

**The 5 effect-scoped misses** all act on *the same object* as the user's task, with different content:
- banking injection 7: a password change, when the user's task also changes the password;
- slack injection 1: a direct message to Alice, whom the user's task also messages;
- travel injection 5: an email to the same recipient, carrying the user's passport and card numbers.

A resource-level mandate cannot tell these apart. Approvals bound to the exact effect (I8), or data-release rules (I5) that forbid sending PII externally, would catch them.

### Benign variations of the honest traces: the false-positive measurement

The honest traces above are the calls each mandate was derived from, so they can't measure false positives. `benign_variants.py` varies each honest trace the way an honest agent might, keeps the mandate as derived from the ground truth, and counts every result other than `preserved` as a flag. The classes are a first cut, proposed by a reader on the AARM Slack, and open to revision.

| Class (traces it applies to) | effect-scoped | tool-scoped | suite-wide |
|---|---|---|---|
| reorder: reads moved ahead of the side-effecting calls (6) | 0 | 0 | 0 |
| extra reads: two argument-free reads added (97) | 0 | 0 | 0 |
| scratch write: a notes file (workspace) or calendar hold (travel) added (60) | **60** | **52** | 0 |
| alternate arguments: "Name &lt;address&gt;" for an address, an IBAN in groups of four (24) | 0 | 0 | 0 |
| retry: the first side-effecting call repeated once (60) | 0 | 0 | 0 |

**What the flags mean:**
- **The scratch write is a real cost of precise mandates.** A mandate that names only the task's objects flags any other write, however harmless. That's by design, and it's the honest number. A deployment that wants scratch space grants it: a resource such as a scratch folder, in the mandate. That widens authority, so it's the principal's choice, not the verifier's.
- **The 8 scratch writes not flagged under tool-scoped** are tasks that already use the same tool, so the tool is in their mandate.

**Two gaps the variations found, both fixed:**
1. **Alternate arguments: 19 of 24 flagged at first, under effect-scoped.** The interpretation compared objects as written, so "Emma Johnson &lt;emma.johnson@…&gt;" and the bare address became two resources. The harness's interpretation now maps both to the same canonical object, as AMEP's interpretation layer is meant to (spec 5.8). Only the form changes: a different address still maps to a different resource.
2. **Retries: 6 of 60 left `unresolved` at every scope.** In each, the tool refused the repeat, for example "user already in the users list" or "file not found", and the recorder had no way to say that nothing ran. `amep_agents.EvidenceRecorder.observe` now takes `not_executed=True`: the tool runtime, which can see that nothing changed, signs a `not_executed` call statement (spec 5.14). Without it, a failed call stays `unresolved`, as before.

**Attack detection is unchanged by both fixes:** rerunning `harness.py` gives the same results as above, byte for byte apart from the run time.

**Not yet measured:** variations a real model produces. These are scripted, from the ground truth, and the classes should come from outside, not only from AMEP's author.

### Other evidence checks (60 honest traces with side effects)

| Variant | Result |
|---|---|
| Tool executes on a different object than declared (lying tool) | `violated` I2: 60 of 60 |
| Agent's own runtime signs its receipts (no independent observer) | `unresolved` I10: 52; `preserved`: 8 (local writes only, which the spec exempts from I10) |
| Tool fails and returns no receipt | `unresolved` I7: 60 of 60 |

## A bug the experiment found

The first run evaluated every honest trace as `unresolved`. The cause was a defect in **both** reference verifiers: when an agent acted directly under a mandate (no delegation) whose `exp` or `nbf` was an RFC 3339 time, the effect time was compared with the unconverted string.
- **Python** raised a type error and returned `unresolved`/I7.
- **JavaScript** compared a number with a string, which is always false, and so never detected an effect after expiry or before `nbf`.

The conformance suite had missed it because every vector used integer times or a delegation, which converts times along the way. Neither had mutation analysis caught it: mutation analysis measures how well the suite detects faults seeded into code, not faults on input paths the suite never exercises.

Suite v0.2.2 adds three vectors for this path. The pre-fix Python verifier fails all three; the pre-fix JavaScript verifier fails the two must-reject ones.

## Limits

- **Oracle traces show what the evidence can catch, not what real agents do.** Real agents call tools in other orders, retry, and fail partway through. The next step is running AgentDojo's real model pipelines with the recorder attached. This needs a model API key, which you enter yourself at the prompt.
- **The mandates are derived from AgentDojo's ground truth,** and so are the honest traces. Real principals state mandates less precisely, so effect-scoped is an upper bound on detection. For the same reason, the honest traces can't show a false-positive rate.
- **The interpretation of tool calls is ours.** `EFFECT` and `OBJECT_ARGS` in `harness.py` map each tool to an effect class and resource, and a different mapping would change the tool-scoped numbers.

## Reproduce

`agentdojo==0.1.35` is the Python package. It ships the benchmark suites up to v1.2.2, the version `harness.py` uses by default (`--version`).

```
pip install agentdojo==0.1.35 ./packages/python ./packages/agents
python -I experiments/agentdojo/harness.py      # about 8 s; writes results.json
python -I experiments/agentdojo/benign_variants.py   # about 5 s; writes benign_variants.json
```
