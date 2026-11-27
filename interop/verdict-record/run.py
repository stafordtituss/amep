"""Run the reference checker of draft-wright-verdict-record over these vectors, holding the AMEP rule, and compare.

    git clone https://github.com/diggertydog/verdict-record-test-vectors vrtv
    VRTV=vrtv python3 -I interop/verdict-record/run.py      # writes results.json; exit 0 when every vector agrees

Needs the cryptography package (AMEP's verifier imports it). Nothing else is installed or fetched.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VRTV = Path(os.environ.get("VRTV", "vrtv")).resolve()


def named(got):
    """How the reference repository's run_all.py names what a check decided."""
    if got["state"] == "no verdict":
        return None
    if got.get("steps") is None:
        return "Section " + got["refused_by_section"] if got.get("refused_by_section") else "?"
    n = got.get("named_step")
    return "PASS" if n is None else "%s at step %s" % (got["steps"][n], n)


def main():
    vectors = sorted((HERE / "vectors").glob("*.json"))
    out = subprocess.run([sys.executable, "-I", str(VRTV / "vrcheck.py"), "--hold", str(HERE / "held" / "amep_evaluate.py"),
                          *map(str, vectors)], cwd=VRTV, capture_output=True, text=True, check=True,
                         env={**os.environ, "AMEP_REPO": str(HERE.parents[1])}).stdout
    commit = subprocess.run(["git", "-C", str(VRTV), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    rows, ok = [], 0
    for line in out.splitlines():
        i = line.index(" {")
        got = json.loads(line[i + 1:])
        v = json.loads(Path(line[:i]).read_text())
        same = got["state"] == v["expected"]["state"] and named(got) == v["expected"]["named"]
        ok += same
        rows.append({"vector": v["name"], "source": v["source"], "expected": v["expected"], "state": got["state"],
                     "steps": got["steps"], "named": named(got), "re_run_result": got.get("re_run_result"),
                     "agrees": same})
        print(("ok  " if same else "DIFF"), v["name"], got["state"], named(got))
    (HERE / "results.json").write_text(json.dumps({"checker": "vrcheck.py", "checker_commit": commit,
                                                    "agree": f"{ok} of {len(rows)}", "vectors": rows}, indent=1) + "\n")
    print(f"{ok} of {len(rows)} as expected")
    return 0 if ok == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
