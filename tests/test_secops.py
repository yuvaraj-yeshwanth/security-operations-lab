import copy
from datetime import date
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from secops import analyze, auth_findings, cloud_findings, iam_findings, run, validate

AS_OF = date(2026, 10, 20)


def event(index, minute, result="failure", user="u", ip="192.0.2.1", host="vpn"):
    return dict(id=f"E-{index}", timestamp=f"2026-10-19T09:{minute:02}:00Z",
                result=result, user=user, source_ip=ip, host=host)


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.data = {p.name: json.loads(p.read_text()) for p in (ROOT / "data").glob("*.json")}

    def test_fixture_expected_results(self):
        result = analyze(self.data, AS_OF)
        self.assertEqual(len(result), 13)
        self.assertEqual(sum(f["severity"] == "high" for f in result), 5)
        self.assertEqual(sum(f["severity"] == "medium" for f in result), 7)
        self.assertEqual(sum(f["severity"] == "low" for f in result), 1)

    def test_burst_threshold_and_success(self):
        events = [event(i, i) for i in range(5)] + [event(5, 5, "success")]
        self.assertEqual([f["rule"] for f in auth_findings(events)], ["AUTH-001", "AUTH-003"])

    def test_below_threshold(self):
        self.assertEqual(auth_findings([event(i, i) for i in range(4)]), [])

    def test_old_failures_expire(self):
        events = [event(i, i * 10) for i in range(5)] + [event(5, 41, "success")]
        self.assertEqual(auth_findings(events), [])

    def test_exact_window_boundary(self):
        events = [event(i, m) for i, m in enumerate([0, 1, 2, 3, 5])]
        self.assertEqual(len(auth_findings(events)), 1)
        events[-1]["timestamp"] = "2026-10-19T09:05:01Z"
        self.assertEqual(auth_findings(events), [])

    def test_success_requires_matching_source(self):
        events = [event(i, i) for i in range(5)] + [event(5, 5, "success", ip="192.0.2.2")]
        self.assertNotIn("AUTH-003", [f["rule"] for f in auth_findings(events)])

    def test_success_requires_matching_host(self):
        events = [event(i, i) for i in range(5)] + [event(5, 5, "success", host="mail")]
        self.assertNotIn("AUTH-003", [f["rule"] for f in auth_findings(events)])

    def test_spray_and_host_scope(self):
        events = [event(i, i, user=f"user{i}") for i in range(4)]
        self.assertEqual(auth_findings(events)[0]["rule"], "AUTH-002")
        events[-1]["host"] = "mail"
        self.assertEqual(auth_findings(events), [])

    def test_unsorted_input_and_offsets(self):
        events = [event(i, i) for i in range(5)]
        events[0]["timestamp"] = "2026-10-19T14:30:00+05:30"
        self.assertEqual(auth_findings(events), auth_findings(list(reversed(events))))

    def test_duplicate_bursts_suppressed(self):
        events = [event(i, 0) for i in range(20)]
        self.assertEqual(len(auth_findings(events)), 1)

    def test_disabled_and_service_accounts_not_flagged(self):
        users = [u for u in self.data["users.json"] if u["id"] in ("USR-004", "USR-005")]
        self.assertEqual(iam_findings(users, AS_OF), [])

    def test_dormancy_boundary(self):
        user = copy.deepcopy(self.data["users.json"][2])
        user["last_login"] = "2026-07-22"
        self.assertEqual(len(iam_findings([user], AS_OF)), 1)
        user["last_login"] = "2026-07-23"
        self.assertEqual(iam_findings([user], AS_OF), [])

    def test_public_port_ranges_ipv6_and_all_protocol(self):
        resource = copy.deepcopy(self.data["cloud.json"][2])
        resource["inbound"] = [dict(cidr="::/0", protocol="tcp", from_port=20, to_port=25)]
        self.assertEqual(len(cloud_findings([resource])), 1)
        resource["inbound"][0].update(protocol="udp")
        self.assertEqual(cloud_findings([resource]), [])
        resource["inbound"][0].update(protocol="all", from_port=0, to_port=0)
        self.assertEqual(len(cloud_findings([resource])), 1)

    def test_safe_cloud_controls(self):
        resources = [r for r in self.data["cloud.json"] if r["id"].endswith("002")]
        self.assertEqual(cloud_findings(resources), [])

    def test_unknown_fields_do_not_imply_pass(self):
        del self.data["cloud.json"][0]["block_public_policy"]
        with self.assertRaises(ValueError):
            validate(self.data, AS_OF)

    def test_boolean_strings_rejected(self):
        self.data["users.json"][0]["enabled"] = "false"
        with self.assertRaises(ValueError):
            validate(self.data, AS_OF)

    def test_naive_timestamp_rejected(self):
        self.data["auth.json"][0]["timestamp"] = "2026-10-19T09:00:00"
        with self.assertRaises(ValueError):
            validate(self.data, AS_OF)

    def test_duplicate_ids_rejected(self):
        self.data["auth.json"].append(self.data["auth.json"][0])
        with self.assertRaises(ValueError):
            validate(self.data, AS_OF)

    def test_future_login_rejected(self):
        self.data["users.json"][0]["last_login"] = "2027-01-01"
        with self.assertRaises(ValueError):
            validate(self.data, AS_OF)

    def test_invalid_network_and_port_range(self):
        rule = self.data["cloud.json"][2]["inbound"][0]
        rule["cidr"] = "invalid"
        with self.assertRaises(ValueError):
            validate(self.data, AS_OF)
        rule.update(cidr="0.0.0.0/0", from_port=65536)
        with self.assertRaises(ValueError):
            validate(self.data, AS_OF)

    def test_priority_is_not_severity(self):
        result = analyze(self.data, AS_OF)
        vulns = {f["evidence"][0]: f for f in result if f["category"] == "vulnerability"}
        self.assertEqual(vulns["LAB-VULN-001"]["priority"], "P1")
        self.assertEqual(vulns["LAB-VULN-002"]["priority"], "P2")
        self.assertEqual(vulns["LAB-VULN-003"]["priority"], "P3")

    def test_deterministic_reports_and_fixture_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(ROOT / "data", out, AS_OF)
            first = (out / "findings.json").read_bytes()
            run(ROOT / "data", out, AS_OF)
            self.assertEqual(first, (out / "findings.json").read_bytes())
            self.assertEqual(first, (ROOT / "examples/findings.json").read_bytes())
            self.assertEqual((out / "report.md").read_bytes(), (ROOT / "examples/report.md").read_bytes())

    def test_invalid_cli_fails_without_new_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, out = root / "data", root / "out"
            source.mkdir()
            for name, rows in self.data.items():
                (source / name).write_text(json.dumps(rows))
            (source / "auth.json").write_text("not json")
            result = subprocess.run([sys.executable, str(ROOT / "src/secops.py"), "--data", str(source),
                                     "--out", str(out), "--as-of", "2026-10-20"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("Review failed", result.stderr)
            self.assertFalse(out.exists())

    def test_empty_inputs_are_not_claimed_as_coverage(self):
        self.assertEqual(analyze({name: [] for name in self.data}, AS_OF), [])


if __name__ == "__main__":
    unittest.main()
