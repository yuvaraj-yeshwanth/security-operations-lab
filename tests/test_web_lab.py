from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from web_lab import exercise


class WebLabTests(unittest.TestCase):
    def test_local_before_after_checks_and_evidence(self):
        evidence = exercise()
        self.assertTrue(all(v is False for v in evidence["vulnerable"]["checks"].values()))
        self.assertTrue(all(v is True for v in evidence["hardened"]["checks"].values()))
        self.assertIn("DEMO_TOKEN=not-a-secret", evidence["vulnerable"]["observations"][0]["body"])
        self.assertNotIn("DEMO_TOKEN", evidence["hardened"]["observations"][0]["body"])
        self.assertNotIn("Date", evidence["hardened"]["observations"][0]["headers"])


if __name__ == "__main__":
    unittest.main()
