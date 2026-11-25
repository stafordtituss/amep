"""Every how-to example runs, and gives the verdict its how-to says it gives."""
import os
import sys
import tempfile
import unittest

EX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "examples")
sys.path.insert(0, EX)


class FrameworkFree(unittest.TestCase):
    def test_save_and_verify(self):
        import save_and_verify
        r = save_and_verify.main(tempfile.mkdtemp())
        self.assertEqual((r["outcome"], r["invariant"]), ("preserved", "-"))
        self.assertTrue(os.path.exists(os.path.join(r["dir"], "packet.json")))

    def test_separate_observer(self):
        import separate_observer
        r = separate_observer.main()
        self.assertEqual(r["separate"], ("preserved", "-"))
        self.assertEqual(r["self"], ("unresolved", "I10"))

    def test_signed_verdict(self):
        import signed_verdict
        self.assertEqual(signed_verdict.main()["predicate"]["verdict"]["outcome"], "preserved")


class Frameworks(unittest.TestCase):
    def test_langgraph(self):
        try:
            import langgraph  # noqa: F401
        except ImportError:
            self.skipTest("langgraph not installed")
        import langgraph_tickets
        self.assertEqual(langgraph_tickets.main("4821"), ("preserved", "-"))
        self.assertEqual(langgraph_tickets.main("9999"), ("violated", "I2"))

    def test_openai_agents(self):
        try:
            import agents  # noqa: F401
        except ImportError:
            self.skipTest("openai-agents not installed")
        import openai_agents_tickets
        self.assertEqual(openai_agents_tickets.main("4821"), ("preserved", "-"))
        self.assertEqual(openai_agents_tickets.main("9999"), ("violated", "I2"))


if __name__ == "__main__":
    unittest.main()
