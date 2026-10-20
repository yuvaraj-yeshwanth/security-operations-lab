import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from ssh_parser import parse_lines


def line(message, timestamp="2026-10-19T09:00:00Z"):
    return f"{timestamp} vpn sshd[100]: {message}"


class ParserTests(unittest.TestCase):
    def test_fixture_matches_normalized_auth(self):
        rows, review = parse_lines((ROOT / "data/raw/ssh.log").read_text().splitlines())
        expected = json.loads((ROOT / "data/auth.json").read_text())
        self.assertEqual(rows, expected)
        self.assertEqual(review["counts"], dict(total_lines=21, comment_or_blank_lines=1, parsed_lines=18, rejected_lines=2))
        self.assertEqual(review["event_source_lines"]["EVT-001"], 2)

    def test_failed_invalid_user(self):
        rows, _ = parse_lines([line("Failed password for invalid user ghost from 192.0.2.1 port 50000 ssh2")])
        self.assertEqual((rows[0]["user"], rows[0]["result"]), ("ghost", "failure"))

    def test_publickey_success_and_ipv6(self):
        rows, _ = parse_lines([line("Accepted publickey for meena from 2001:db8::1 port 50000 ssh2: ED25519 SHA256:demo")])
        self.assertEqual((rows[0]["source_ip"], rows[0]["result"]), ("2001:db8::1", "success"))

    def test_offsets_normalize_to_utc(self):
        rows, _ = parse_lines([line("Failed password for arun from 192.0.2.1 port 50000 ssh2", "2026-10-19T14:30:00+05:30")])
        self.assertEqual(rows[0]["timestamp"], "2026-10-19T09:00:00Z")

    def test_rejects_invalid_ip_and_port(self):
        rows, review = parse_lines([line("Failed password for arun from bad-ip port 50000 ssh2"),
                                    line("Failed password for arun from 192.0.2.1 port 99999 ssh2")])
        self.assertEqual(rows, [])
        self.assertEqual(review["counts"]["rejected_lines"], 2)

    def test_rejects_naive_time_and_yearless_prefix(self):
        rows, review = parse_lines([line("Failed password for arun from 192.0.2.1 port 50000 ssh2", "2026-10-19T09:00:00"),
                                    "Oct 19 09:00:00 vpn sshd[100]: Failed password for arun from 192.0.2.1 port 50000 ssh2"])
        self.assertEqual(rows, [])
        self.assertEqual(review["counts"]["rejected_lines"], 2)

    def test_comments_blanks_and_unsupported_lines_accounted_for(self):
        rows, review = parse_lines(["# comment", "", "not a supported log"])
        self.assertEqual(rows, [])
        self.assertEqual(review["counts"]["comment_or_blank_lines"], 2)
        self.assertEqual(review["rejected"][0]["line_number"], 3)

    def test_strict_cli_writes_nothing_on_rejected_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            result = subprocess.run([sys.executable, str(ROOT / "src/ssh_parser.py"), str(ROOT / "data/raw/ssh.log"),
                                     "--out", str(out), "--strict"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
