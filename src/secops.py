"""Offline security review of a deliberately small, normalized lab schema.

No network calls, credentials, scanning, blocking, or cloud changes.
Python 3.10+; standard library only.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
import hashlib
import ipaddress
import json
from pathlib import Path
import sys

VERSION = "1.0.0"
FILES = ("auth.json", "users.json", "cloud.json", "vulnerabilities.json")
SEVERITIES = {"high": 0, "medium": 1, "low": 2}


def timestamp(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return dt


def require(row, fields, label):
    if not isinstance(row, dict):
        raise ValueError(f"{label}: expected an object")
    for field, kind in fields.items():
        if field not in row or type(row[field]) is not kind:
            raise ValueError(f"{label}: {field} must be {kind.__name__}")
        if kind is str and not row[field].strip():
            raise ValueError(f"{label}: {field} must not be empty")


def validate(data, as_of):
    """Reject incomplete snapshots instead of interpreting missing data as safe."""
    for filename in FILES:
        if not isinstance(data[filename], list):
            raise ValueError(f"{filename}: expected a JSON list")
        seen = set()
        for row in data[filename]:
            require(row, {"id": str}, filename)
            if row["id"] in seen:
                raise ValueError(f"{filename}: duplicate id {row['id']}")
            seen.add(row["id"])
    for row in data["auth.json"]:
        require(row, {"timestamp": str, "user": str, "source_ip": str,
                      "host": str, "result": str}, "auth")
        if row["result"] not in ("success", "failure"):
            raise ValueError("auth: result must be success or failure")
        if timestamp(row["timestamp"]).date() > as_of:
            raise ValueError("auth: event date is after as-of date")
        ipaddress.ip_address(row["source_ip"])
    for row in data["users.json"]:
        require(row, {"enabled": bool, "employment_status": str, "privileged": bool,
                      "mfa_enabled": bool, "last_login": str, "owner": str}, "users")
        if row["employment_status"] not in ("active", "terminated", "service"):
            raise ValueError("users: unsupported employment_status")
        if date.fromisoformat(row["last_login"]) > as_of:
            raise ValueError("users: last_login is after as-of date")
    for row in data["cloud.json"]:
        require(row, {"provider": str, "kind": str, "owner": str}, "cloud")
        pair = row["provider"], row["kind"]
        if pair == ("aws", "s3"):
            require(row, {"block_public_acls": bool, "ignore_public_acls": bool,
                          "block_public_policy": bool, "restrict_public_buckets": bool}, "s3")
        elif pair == ("aws", "security_group"):
            require(row, {"inbound": list}, "security_group")
            for rule in row["inbound"]:
                require(rule, {"cidr": str, "protocol": str, "from_port": int,
                               "to_port": int}, "inbound")
                ipaddress.ip_network(rule["cidr"], strict=True)
                if rule["protocol"] not in ("tcp", "udp", "all"):
                    raise ValueError("inbound: protocol must be tcp, udp or all")
                if not 0 <= rule["from_port"] <= rule["to_port"] <= 65535:
                    raise ValueError("inbound: invalid port range")
        elif pair == ("azure", "storage"):
            require(row, {"allow_blob_public_access": bool,
                          "secure_transfer_required": bool}, "azure storage")
        else:
            raise ValueError(f"cloud: unsupported provider/kind {pair}")
    for row in data["vulnerabilities.json"]:
        require(row, {"asset": str, "title": str, "severity": str,
                      "internet_exposed": bool, "owner": str, "evidence": str,
                      "remediation": str}, "vulnerabilities")
        if row["severity"] not in SEVERITIES:
            raise ValueError("vulnerabilities: severity must be high, medium or low")


def finding(rule, category, severity, asset, evidence, reason, action, owner):
    return dict(rule=rule, category=category, severity=severity, asset=asset,
                evidence=evidence, reason=reason, recommendation=action, owner=owner,
                status="open; analyst review required")


def auth_findings(events):
    """Rolling 5-minute windows, scoped to source and destination host.

    Authentication results are signals, not proof of compromise. A spray signal
    cannot verify password reuse because passwords must never appear in logs.
    """
    events = sorted(events, key=lambda r: (timestamp(r["timestamp"]), r["id"]))
    failures = defaultdict(list)
    spray = defaultdict(list)
    burst_alerted, spray_alerted = set(), set()
    output = []
    for event in events:
        now = timestamp(event["timestamp"])
        key = event["user"], event["source_ip"], event["host"]
        source = event["source_ip"], event["host"]
        failures[key] = [r for r in failures[key]
                         if now - timestamp(r["timestamp"]) <= timedelta(minutes=5)]
        spray[source] = [r for r in spray[source]
                         if now - timestamp(r["timestamp"]) <= timedelta(minutes=5)]
        if not failures[key]:
            burst_alerted.discard(key)
        if not spray[source]:
            spray_alerted.discard(source)
        if event["result"] == "failure":
            failures[key].append(event)
            spray[source].append(event)
            if len(failures[key]) >= 5 and key not in burst_alerted:
                output.append(finding("AUTH-001", "monitoring", "medium", event["host"],
                    [r["id"] for r in failures[key]],
                    f"At least 5 failed logins in 5 minutes for {key[0]} from {key[1]}.",
                    "Check account owner, source, MFA and surrounding events; distinguish retries from abuse.", "SOC analyst"))
                burst_alerted.add(key)
            if len({r["user"] for r in spray[source]}) >= 4 and source not in spray_alerted:
                output.append(finding("AUTH-002", "monitoring", "medium", event["host"],
                    [r["id"] for r in spray[source]],
                    f"Failures against at least 4 users in 5 minutes from {source[0]}; possible spraying.",
                    "Review source reputation and user activity; confirm whether the source is approved testing.", "SOC analyst"))
                spray_alerted.add(source)
        elif len(failures[key]) >= 5:
            output.append(finding("AUTH-003", "monitoring", "high", event["host"],
                [r["id"] for r in failures[key]] + [event["id"]],
                f"Success after at least 5 recent failures for {key[0]} from the same source and host.",
                "Contact the owner and preserve logs; escalate suspected takeover and obtain approval for session revocation.", "SOC analyst"))
            failures[key] = []
            burst_alerted.discard(key)
    return output


def iam_findings(users, as_of):
    output = []
    for user in sorted(users, key=lambda r: r["id"]):
        if not user["enabled"]:
            continue
        checks = []
        if user["employment_status"] == "terminated":
            checks.append(("IAM-001", "high", "Terminated worker retains an enabled account.",
                           "Confirm HR status; request account disablement and session revocation through the owner."))
        if user["employment_status"] != "service" and user["privileged"] and not user["mfa_enabled"]:
            checks.append(("IAM-002", "high", "Enabled privileged human account has no MFA in this snapshot.",
                           "Confirm identity-provider enforcement and require MFA; review privileged grants."))
        if user["employment_status"] != "service" and (as_of - date.fromisoformat(user["last_login"])).days >= 90:
            checks.append(("IAM-003", "medium", "Enabled human account has no login for at least 90 days.",
                           "Ask the owner to justify access; remove unused access after approval."))
        for rule, severity, reason, action in checks:
            output.append(finding(rule, "iam", severity, user["id"], [user["id"]], reason, action, user["owner"]))
    return output


def cloud_findings(resources):
    output = []
    for resource in sorted(resources, key=lambda r: r["id"]):
        checks = []
        if resource["kind"] == "s3":
            flags = ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets")
            if not all(resource[k] for k in flags):
                checks.append(("CLOUD-001", "medium", "Bucket-level Block Public Access is not fully enabled; actual public exposure is unverified.",
                               "Review bucket policy, ACLs and account/organization controls; enable all four settings where appropriate."))
        elif resource["kind"] == "security_group":
            exposed = set()
            for rule in resource["inbound"]:
                network = ipaddress.ip_network(rule["cidr"])
                if network.prefixlen == 0 and rule["protocol"] in ("tcp", "all"):
                    for port in (22, 3389):
                        if rule["protocol"] == "all" or rule["from_port"] <= port <= rule["to_port"]:
                            exposed.add(port)
            if exposed:
                checks.append(("CLOUD-002", "high", f"Security group allows internet-wide TCP administration on ports {sorted(exposed)}; reachability is unverified.",
                               "Confirm routes and attachments; restrict SSH/RDP sources or use approved private administration."))
        elif resource["kind"] == "storage":
            if resource["allow_blob_public_access"]:
                checks.append(("CLOUD-003", "medium", "Storage account permits anonymous blob access configuration; container exposure is unverified.",
                               "Review container settings and business need; disable anonymous access when unnecessary."))
            if not resource["secure_transfer_required"]:
                checks.append(("CLOUD-004", "medium", "Storage account does not require secure transfer.",
                               "Enable secure transfer after checking client compatibility and test approved clients."))
        for rule, severity, reason, action in checks:
            output.append(finding(rule, "cloud", severity, resource["id"], [resource["id"]], reason, action, resource["owner"]))
    return output


def vulnerability_findings(rows):
    output = []
    for row in sorted(rows, key=lambda r: r["id"]):
        priority = "P1" if row["severity"] == "high" and row["internet_exposed"] else ("P3" if row["severity"] == "low" else "P2")
        item = finding("VULN-001", "vulnerability", row["severity"], row["asset"], [row["id"]],
                       row["title"] + " Evidence supplied by the lab fixture: " + row["evidence"],
                       row["remediation"], row["owner"])
        item.update(priority=priority, internet_exposed=row["internet_exposed"])
        output.append(item)
    return output


def analyze(data, as_of):
    validate(data, as_of)
    findings = (auth_findings(data["auth.json"]) + iam_findings(data["users.json"], as_of)
                + cloud_findings(data["cloud.json"]) + vulnerability_findings(data["vulnerabilities.json"]))
    findings.sort(key=lambda r: (SEVERITIES[r["severity"]], r["category"], r["asset"], r["rule"], tuple(r["evidence"])))
    for index, item in enumerate(findings, 1):
        item["id"] = f"F-{index:03d}"
    return findings


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ").replace("\r", " ").replace("<", "&lt;").replace(">", "&gt;")


def markdown(report):
    lines = ["# Security review - synthetic lab", "", f"As of: {report['as_of']} | Tool: {VERSION}", "",
             "All findings are review signals. No live environment was assessed and no remediation was executed.", "",
             "## Summary", "", f"Findings: {len(report['findings'])}", ""]
    for severity in SEVERITIES:
        lines.append(f"- {severity.title()}: {report['severity_counts'].get(severity, 0)}")
    lines += ["", "## Findings", "", "| ID | Rule | Severity | Asset | Owner | Evidence |",
              "| --- | --- | --- | --- | --- | --- |"]
    for item in report["findings"]:
        lines.append("| " + " | ".join(cell(item[k]) if k != "evidence" else cell(", ".join(item[k]))
                                       for k in ("id", "rule", "severity", "asset", "owner", "evidence")) + " |")
    for item in report["findings"]:
        lines += ["", f"### {item['id']} - {item['rule']}", "", cell(item["reason"]), "",
                  "Recommended next step: " + cell(item["recommendation"]), "", "Status: " + item["status"]]
        if "priority" in item:
            lines += ["", "Lab queue priority: " + item["priority"]]
    lines += ["", "## Input integrity", "", "SHA-256 records the reviewed bytes, not their truth or provenance.", ""]
    for filename, digest in report["input_sha256"].items():
        lines.append(f"- {filename}: `{digest}`")
    return "\n".join(lines) + "\n"


def run(data_dir, output_dir, as_of):
    data, hashes = {}, {}
    for filename in FILES:
        raw = (data_dir / filename).read_bytes()
        hashes[filename] = hashlib.sha256(raw).hexdigest()
        data[filename] = json.loads(raw)
    findings = analyze(data, as_of)
    report = dict(schema_version=1, tool_version=VERSION, as_of=as_of.isoformat(),
                  scope="Synthetic normalized fixtures only; no live assessment",
                  input_sha256=hashes, input_counts={k: len(v) for k, v in data.items()},
                  severity_counts=dict(sorted(Counter(f["severity"] for f in findings).items())),
                  category_counts=dict(sorted(Counter(f["category"] for f in findings).items())), findings=findings)
    # Validate everything before producing output; refuse to overwrite source evidence.
    outputs = [output_dir / name for name in ("findings.json", "report.md")]
    inputs = {(data_dir / name).resolve() for name in FILES}
    if any(path.resolve() in inputs for path in outputs):
        raise ValueError("output would overwrite an input file")
    output_dir.mkdir(parents=True, exist_ok=True)
    outputs[0].write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    outputs[1].write_text(markdown(report), encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("data"))
    parser.add_argument("--out", type=Path, default=Path("reports"))
    parser.add_argument("--as-of", type=date.fromisoformat, required=True, help="YYYY-MM-DD snapshot review date")
    args = parser.parse_args(argv)
    try:
        report = run(args.data, args.out, args.as_of)
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"Review failed: {error}", file=sys.stderr)
        return 2
    print(f"Reviewed synthetic fixtures: {len(report['findings'])} findings. Reports: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
