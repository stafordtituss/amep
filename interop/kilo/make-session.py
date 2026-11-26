"""Writes the demo session (in the shape of `kilo export`) and the workspace observer's record.

Both are constructed for the demo, not recorded: the tool calls, inputs and permission errors match what Kilo records
(Kilo-Org/kilocode at b12e612, packages/schema/src/v1/session.ts: ToolPart, ToolState), with the exact text of
PermissionDeniedError. Run from the repo root: python3 interop/kilo/make-session.py
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
D = "/work/app"
T0 = 1795651200000  # 2026-11-26T08:00:00Z, in ms as Kilo records it


def tool(cid, name, inp, status, start, extra):
    st = {"status": status, "input": inp, "time": {"start": start, "end": start + 800}}
    st.update(extra)
    return {"id": "prt_" + cid, "sessionID": "ses_demo", "messageID": "msg_2", "type": "tool",
            "callID": cid, "tool": name, "state": st}


def done(title, out):
    return {"output": out, "title": title, "metadata": {}}


def denied(perm, pat):
    rule = json.dumps({"permission": perm, "pattern": pat, "action": "deny"}, separators=(",", ":"))
    return {"error": "The user has specified a rule which prevents you from using this specific tool call. "
                     "Here are some of the relevant rules " + rule}


parts = [
    tool("call_01", "read", {"filePath": D + "/README.md"}, "completed", T0 + 1000, done("README.md", "...")),
    tool("call_02", "edit", {"filePath": D + "/src/auth.ts", "oldString": "if (token)",
                             "newString": "if (token && !expired(token))"}, "completed", T0 + 5000,
         done("src/auth.ts", "Edit applied")),
    tool("call_03", "bash", {"command": "npm install", "description": "Install dependencies"}, "completed",
         T0 + 9000, done("npm install", "added 214 packages")),
    tool("call_04", "bash", {"command": "npm run deploy", "description": "Deploy the fix"}, "error", T0 + 14000,
         denied("bash", "npm run deploy*")),
    tool("call_05", "edit", {"filePath": D + "/config/prod/settings.json", "oldString": "\"debug\": false",
                             "newString": "\"debug\": true"}, "error", T0 + 18000, denied("edit", "config/prod/*")),
]
session = {
    "$comment": "Constructed for the AMEP demo in the shape of `kilo export`; not a recorded Kilo session. "
                "See make-session.py.",
    "info": {"id": "ses_demo", "directory": D, "title": "Fix token expiry check"},
    "messages": [{"info": {"id": "msg_2", "sessionID": "ses_demo", "role": "assistant"}, "parts": parts}],
}
observer = {
    "$comment": "The workspace observer's record, constructed for the demo: a process outside the agent, under its own "
                "key and operator (for example the sandbox or build host that owns the workspace), listing every file "
                "written during each tool call, and the deployment target's statement of what it received.",
    "calls": {
        "call_01": {"writes": []},
        "call_02": {"writes": ["src/auth.ts"]},
        "call_03": {"writes": ["node_modules/.package-lock.json", "package-lock.json", "Makefile"],
                    "note": "a dependency's install script rewrote the Makefile"},
        "call_04": {"writes": []},
        "call_05": {"writes": []},
    },
    "registry_statements": {"call_04": {"disposition": "not_executed",
                                        "detail": "no deployment received in the interval"}},
}
for name, obj in (("session.json", session), ("workspace-observer.json", observer)):
    with open(os.path.join(HERE, name), "w") as f:
        json.dump(obj, f, indent=1)
        f.write("\n")
print("wrote session.json and workspace-observer.json")
