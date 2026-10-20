import contextlib
import csv
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from run_lab import csv_cell, demo


class DemoTests(unittest.TestCase):
    def test_full_demo_outputs_and_raw_evidence_link(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            out = Path(tmp) / "run"
            result = demo(out)
            self.assertEqual(result["run_status"], "complete")
            self.assertEqual(result["findings"], 13)
            self.assertEqual(result["severity_counts"], {"high": 5, "medium": 7, "low": 1})
            self.assertIn("all hardened checks passed", result["web_status"])
            with (out / "remediation_queue.csv").open(newline="") as stream:
                self.assertEqual(len(list(csv.DictReader(stream))), 13)
            rows = [json.loads(row) for row in (out / "auth_for_splunk.jsonl").read_text().splitlines()]
            self.assertEqual(len(rows), 18)
            self.assertIn("dest_host", rows[0])
            self.assertNotIn("host", rows[0])
            parse = json.loads((out / "parse_review.json").read_text())
            self.assertEqual(parse["event_source_lines"]["EVT-006"], 7)
            self.assertEqual(len(parse["source_sha256"]), 64)
            self.assertTrue((out / "local_web_assessment.md").exists())

    def test_skip_web_has_no_claim_of_execution(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            out = Path(tmp) / "run"
            result = demo(out, skip_web=True)
            self.assertEqual(result["web_status"], "skipped by request")
            self.assertFalse((out / "local_web").exists())

    def test_skip_web_rejects_stale_web_evidence_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "local_web").mkdir()
            with self.assertRaises(ValueError):
                demo(out, skip_web=True)
            self.assertFalse((out / "normalized").exists())

    def test_source_folders_are_protected(self):
        with self.assertRaises(ValueError):
            demo(ROOT / "data")
        with self.assertRaises(ValueError):
            demo(ROOT)

    def test_csv_formula_values_neutralized(self):
        for value in ("=1+1", "+SUM(A1)", "-1+1", "@command", " \t=1+1", "\tcommand", "\rcommand", "\ncommand"):
            self.assertEqual(csv_cell(value), "'" + value)
        self.assertEqual(csv_cell("F-001"), "F-001")


if __name__ == "__main__":
    unittest.main()
