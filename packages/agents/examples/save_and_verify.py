"""How-to: save the evidence from a run, and check it later, anywhere.

No agent framework is needed: this drives the recorder by hand, the way an adapter does. Run:
    python examples/save_and_verify.py
then check the files it writes with the command line tool:
    amep-protocol verify packet.json --keys keys.json
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from amep_protocol import evaluate, verdict  # noqa: E402
from _setup import KEYS, get_ticket, new_recorder, update_ticket  # noqa: E402


def main(out_dir=None):
    rec = new_recorder()
    # 1. the agent's host declares each call before it runs ...
    rec.declare("call-1", "update_ticket", {"ticket_id": "4821", "status": "closed"})
    # ... 2. the tool runs, and its runtime observes what it did
    rec.observe("call-1", update_ticket("4821", "closed"))
    rec.declare("call-2", "get_ticket", {"ticket_id": "4822"})
    rec.observe("call-2", get_ticket("4822"))

    # 3. save the packet and the public keys; neither contains a secret
    out_dir = out_dir or tempfile.mkdtemp(prefix="amep-")
    with open(os.path.join(out_dir, "packet.json"), "w") as fh:
        json.dump(rec.packet(), fh, indent=1)
    with open(os.path.join(out_dir, "keys.json"), "w") as fh:
        json.dump(KEYS, fh, indent=1)

    # 4. later, anyone with the two files gets the same answer
    with open(os.path.join(out_dir, "packet.json")) as fh:
        packet = json.load(fh)
    with open(os.path.join(out_dir, "keys.json")) as fh:
        keys = json.load(fh)
    v = verdict(evaluate(packet, keys))
    print(f"{v.outcome} {v.invariant}  (files in {out_dir})")
    return {"outcome": v.outcome, "invariant": v.invariant, "dir": out_dir}


if __name__ == "__main__":
    main()
