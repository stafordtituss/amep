# A Kilo Code session, checked afterwards

Kilo Code decides **before** each tool call. A rule per tool and pattern says `allow`, `ask` or `deny`, and the call either starts or doesn't. That answers "may this call start?". It can't answer the question an auditor, a teammate or the user asks afterwards: what did the call actually do, and was it allowed?

This demo answers that second question for one session, with a verdict per call that anyone can recompute offline.

## The session

Five tool calls in a repository, under this permission config ([`kilo.json`](kilo.json)):

```json
"permission": {
  "read": "allow",
  "edit": { "*": "ask", "src/*": "allow", "config/prod/*": "deny" },
  "bash": { "*": "ask", "npm *": "allow", "npm run deploy*": "deny" }
}
```

| Call | What the agent ran | What Kilo decided | What changed, seen from outside the agent | AMEP verdict |
|---|---|---|---|---|
| 1 | `read README.md` | allowed | nothing | **preserved** |
| 2 | `edit src/auth.ts` | allowed | `src/auth.ts` | **preserved** |
| 3 | `bash npm install` | allowed (`npm *`) | `node_modules/…`, `package-lock.json`, **and `Makefile`**: a dependency's install script rewrote it | **violated** (I2): the `Makefile` write is outside what the user allowed. The other writes are fine. |
| 4 | `bash npm run deploy` | denied by a rule | nothing; the deployment target signs that it received no deployment | **preserved**. Without the deployment target's record: **unresolved** (I10), because only the agent's own side says the deny held |
| 5 | `edit config/prod/settings.json` | denied by a rule | nothing; the workspace observer signs that there was no write | **preserved** |

**Session verdict: violated,** charged to the agent's call 3, naming the file.

## What each layer can see

- **Kilo's rules were right every time.** `npm install` was allowed, and it should have been. The rules can't see that its install scripts would write the `Makefile`: no rule about commands can, because the command doesn't know either.
- **Kilo's own record says call 3 completed.** It doesn't say what was written. The session's patch and snapshot parts would, but they are Kilo's own record of its own run.
- **An observer outside the agent sees the writes.** That's the workspace's host: a sandbox, a dev container, or the build machine. With the user's grant, AMEP turns those writes into a verdict, and names the one write that departed.
- **For a denied call, the agent's own "denied" is not proof.** For a local file, the workspace observer's record of no write settles it. For a deploy, only the deployment target can say nothing arrived. Without it the verdict stays **unresolved** and names the missing record, rather than assuming the best.

## How the pieces map

| Kilo | AMEP | Signed by |
|---|---|---|
| The `permission` config | a mandate. `allow` rules become grants, `deny` rules become a deny list. `ask` becomes nothing: the user's answer to an ask isn't in the export, so a call allowed that way needs the answer as a signed approval. | the user |
| What an allowed command may write | `commandScopes` in [`run.mjs`](run.mjs) (`npm *`: `node_modules/*`, `package-lock.json`). Kilo has no such setting, so the deployment states it. | the user, with the mandate |
| Each tool part of `kilo export` | an invocation. A shell command declares the workspace as its scope (spec 5.8.2), since it can't name its writes in advance. | Kilo's host |
| `PermissionDeniedError`, `PermissionRejectedError` | a pre-execution deny decision | Kilo's host |
| The workspace observer's record | effects (writes) and `not_executed` statements | the workspace host, another operator |
| The deployment target's record | a `not_executed` statement | the deployment target, another operator |

The mapping is never wider than Kilo's. Where the two differ, AMEP is stricter, and the run lists where:
- an `ask` grants nothing;
- a `deny` always wins, even where Kilo's last-match rule would let a later `allow` win.

## Found along the way: a gap in AMEP, now fixed

AMEP 0.3 required every effect of a call to match the call's declared effect exactly. A shell command can't name its writes in advance. So every write by `npm install`, including the harmless ones, read as a departure charged to the server, and the verdict was right for the wrong reason. Spec section 5.8.2 now lets such a call declare a **scope**: each effect inside it is judged against the grant like any other. Six new conformance vectors cover it (suite v0.3.3, 283 core vectors), and both reference verifiers agree on all of them.

## Status of the inputs, stated plainly

- **The session isn't a recorded Kilo session.** [`session.json`](session.json) is written in the shape of `kilo export` (Kilo-Org/kilocode at `b12e612`, `packages/schema/src/v1/session.ts`), with Kilo's exact `PermissionDeniedError` text. [`make-session.py`](make-session.py) generates it.
- **The observer records are constructed too.** In [`workspace-observer.json`](workspace-observer.json), the workspace observer and the deployment target stand for records a real deployment would collect, for example from a sandbox's file watcher.
- **Keys are deterministic test keys,** one per party.

The next step is a recorded session: run Kilo in a container whose host records writes, export the session, and run this unchanged.

## Run it

```bash
python3 interop/kilo/make-session.py
node interop/kilo/run.mjs --write-packet
python -m amep_protocol.cli verify interop/kilo/packet.json --keys interop/kilo/keys.json --json
```

`packet.json` and `keys.json` are the full evidence. Both reference verifiers, Python and JavaScript, give the same five verdicts from them.
