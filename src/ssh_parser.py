"""Normalize a limited RFC3339-prefixed OpenSSH log format.

Reports every non-comment line that is not parsed. This is an adapter for
teaching fixtures, not a universal Linux or journald parser.
"""
import argparse
from datetime import timezone
import ipaddress
import json
from pathlib import Path
import re
import sys

from secops import timestamp

PREFIX = re.compile(r"^(?P<time>\S+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<message>.+)$")
MESSAGE = re.compile(
    r"^(?P<action>Failed|Accepted) (?P<method>password|publickey) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2(?:[:\s].*)?$")


def parse_lines(lines):
    events, rejected, sources = [], [], {}
    counts = dict(total_lines=0, comment_or_blank_lines=0, parsed_lines=0, rejected_lines=0)
    for line_number, line in enumerate(lines, 1):
        counts["total_lines"] += 1
        line = line.strip()
        if not line or line.startswith("#"):
            counts["comment_or_blank_lines"] += 1
            continue
        try:
            prefix = PREFIX.fullmatch(line)
            if not prefix:
                raise ValueError("unsupported prefix; expected RFC3339 host sshd[pid]")
            message = MESSAGE.fullmatch(prefix["message"])
            if not message:
                raise ValueError("unsupported SSH message")
            dt = timestamp(prefix["time"]).astimezone(timezone.utc)
            ipaddress.ip_address(message["ip"])
            if not 1 <= int(message["port"]) <= 65535:
                raise ValueError("invalid source port")
            event_id = f"EVT-{len(events) + 1:03d}"
            events.append(dict(id=event_id, timestamp=dt.isoformat().replace("+00:00", "Z"),
                               user=message["user"], source_ip=message["ip"], host=prefix["host"],
                               result="failure" if message["action"] == "Failed" else "success"))
            sources[event_id] = line_number
        except ValueError as error:
            rejected.append(dict(line_number=line_number, reason=str(error)))
    counts.update(parsed_lines=len(events), rejected_lines=len(rejected))
    return events, dict(counts=counts, event_source_lines=sources, rejected=rejected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--strict", action="store_true", help="Do not write results if any non-comment line is rejected")
    args = parser.parse_args()
    try:
        events, review = parse_lines(args.input.read_text(encoding="utf-8").splitlines())
        if args.strict and review["rejected"]:
            print(f"Strict parse rejected {len(review['rejected'])} lines; no output written.", file=sys.stderr)
            return 2
        targets = [args.out / name for name in ("auth.json", "parse_review.json")]
        if args.input.resolve() in {p.resolve() for p in targets}:
            raise ValueError("output would overwrite input")
        args.out.mkdir(parents=True, exist_ok=True)
        for path, data in zip(targets, (events, review)):
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(review["counts"], sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(f"Parse failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
