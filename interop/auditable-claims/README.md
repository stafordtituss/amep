# "Auditable Claims about AI Agents": the worked case as AMEP evidence

**The source:** Yue Zhao, Jiate Li, Li Li, Yi Nian, Jinbo Liu, Xiaolin Zhou and Xiyang Hu, *Auditable Claims about AI Agents*, [arXiv:2610.07459](https://arxiv.org/abs/2610.07459) (University of Southern California and Arizona State University). Its Section 4 follows one claim, "a person approves every external email", through five evidence states. The authors' companion repository is [yzhao062/auditable-claims](https://github.com/yzhao062/auditable-claims).

**What this is:** each evidence state encoded as an AMEP packet, with AMEP's verdict beside the paper's finding (its Table 4). [`run.mjs`](run.mjs) builds and evaluates them, and [`results.json`](results.json) holds the verdicts and each packet's digest. This is AMEP's reading of the paper, not the authors'. Like theirs, the records are constructed for teaching.

```bash
node interop/auditable-claims/run.mjs
```

## The mapping

| The paper | AMEP | Signed by (operator) |
|---|---|---|
| A grant from the authorization server, naming recipient and attachment hash, approved by `user:alvarez` (P-7) | a mandate whose resource is `mail:<recipient>/sha256:<attachment hash>` | the authorization server (the identity team) |
| The agent's standing authority over the matter folder | a mandate with `docs.read` and `docs.summarize`, and no `email.send` | the authorization server |
| An agent log entry for a send | an invocation naming the authority it acted under | the agent's host (the agent team: the audited party) |
| A gateway delivery | an effect receipt | the mail gateway (IT: the independent writer) |

## Results

| State | The paper (Table 4) | AMEP |
|---|---|---|
| A (PRE): tool manifest and approval configuration only | March claim UNDECIDABLE | `unresolved`: nothing was invoked, so there is nothing to judge (gap `invocation`) |
| B, `tx-19`: agent, server and gateway logs agree | this email meets P-7 | `preserved` |
| C, `tx-23`: an interface confirmation, no grant; the gateway delivered | violates P-7; March claim CONTRADICTED | `violated` (I2): the send is outside the authority the agent acted under. It names the agent's call as the first departure |
| D, `tx-31`: no grant and no correlation identifier; the server's log lost | UNDECIDABLE for this email | `unresolved` (I7): the grant the call names is not in the record (gap `root_mandate`). The gateway's delivery can't be joined to the call either |
| E, 4th email: a signed agent log verifies for three emails; the gateway shows a fourth | UNDECIDABLE for this email | `unresolved` (I11): a delivery whose call is in no record. It may be a bypass, or an entry the log left out; no one is blamed (gap `invocation`) |

**The verdicts agree in all five states.**

## Where the reasoning differs

1. **State C rests on a different premise.**
   - The paper's CONTRADICTED needs the server's grant log to be complete for the period (its Proposition 1).
   - AMEP's `violated` needs instead that the agent's own signed call names the authority it acted under. Here that's its standing authority, which has no `email.send`. The independent gateway records the send.
   - So AMEP reaches the verdict without a completeness record, but only because the agent declared its authority. Had the call named a grant that the record doesn't contain, AMEP would say `unresolved`, as in state D.
   - The two premises are complementary. A complete grant log settles C even when the agent names nothing.
2. **"Blame" is not responsibility.** AMEP names the party whose signed record departed first: in C, the agent's call. That matches the paper's limit that a verdict "does not by itself decide legal compliance or liability", and does not show what `user:alvarez` understood or intended.
3. **State E is AMEP's I11 rule, corrected this month.** Until 0.3.1, AMEP read a delivery whose call is in no record as proof of a bypass, charged to the host. A reviewer's finding (stafordtituss/amep#36) changed it to `unresolved` with no blame, which is the paper's reading of state E. The paper's three conditions line up with AMEP's rules:
   - independent coverage is I10;
   - authorization bound to arguments is the resource naming recipient and hash, and approvals bound to the executed effect;
   - completeness beyond integrity is this rule.
