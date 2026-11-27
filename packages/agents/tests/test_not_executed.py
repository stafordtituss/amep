"""A refused call: the tool runtime states "not executed" instead of leaving the outcome unknown (spec 5.14)."""
import unittest

from amep_protocol.core import digest
from common import KEYS, recorder


class NotExecuted(unittest.TestCase):
    def test_failed_call_without_statement_stays_unresolved(self):
        rec = recorder("not-executed-test")
        rec.declare("c1", "update_ticket", {"ticket_id": "4821", "status": "closed"})
        self.assertIsNone(rec.observe("c1", error="ValueError: ticket locked"))
        v, _ = rec.evaluate(KEYS)
        self.assertEqual((v.outcome, v.invariant), ("unresolved", "I7"))

    def test_refused_call_with_statement_is_settled(self):
        rec = recorder("not-executed-test")
        inv = rec.declare("c1", "update_ticket", {"ticket_id": "4821", "status": "closed"})
        stmt = rec.observe("c1", error="ValueError: ticket locked", not_executed=True)
        self.assertEqual((stmt["kind"], stmt["disposition"], stmt["effect_count"]), ("call_statement", "not_executed", 0))
        self.assertEqual(stmt["invocation_digest"], digest(inv))
        self.assertEqual(rec.packet()["call_statements"], [stmt])
        v, _ = rec.evaluate(KEYS)
        self.assertEqual(v.outcome, "preserved")

    def test_statement_on_one_call_does_not_clear_another(self):
        # The statement settles only its own call: a later effect outside authority is still a violation.
        rec = recorder("not-executed-test")
        rec.declare("c1", "update_ticket", {"ticket_id": "4821", "status": "closed"})
        rec.observe("c1", error="timeout", not_executed=True)
        rec.declare("c2", "update_ticket", {"ticket_id": "9999", "status": "closed"})
        rec.observe("c2", {"updated": "9999"})
        v, _ = rec.evaluate(KEYS)
        self.assertEqual(v.outcome, "violated")

    def test_not_executed_without_error_is_ignored(self):
        rec = recorder("not-executed-test")
        rec.declare("c1", "update_ticket", {"ticket_id": "4821", "status": "closed"})
        receipt = rec.observe("c1", {"updated": "4821"}, not_executed=True)
        self.assertEqual(receipt["kind"], "effect")
        self.assertNotIn("call_statements", rec.packet())


if __name__ == "__main__":
    unittest.main()
