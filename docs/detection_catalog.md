# Detection and review catalog

Thresholds are lab choices, not NIST-mandated requirements.

| Rule | Trigger | False positives or missing context | Analyst follow-up |
| --- | --- | --- | --- |
| AUTH-001 | 5 failures, same user/source/host, inclusive 5-minute window | Mistyped passwords, stale saved credentials, shared NAT | Confirm user and source; inspect adjacent events and authentication methods |
| AUTH-002 | Failures for 4 distinct users, same source/host, 5 minutes | Shared egress, approved testing, bad client configuration | Validate source and account distribution; passwords are unavailable, so spraying is only suspected |
| AUTH-003 | Success with 5 prior matching failures still within 5 minutes | Legitimate user succeeds after retries | Verify with user; examine sessions and activity before escalating |
| IAM-001 | Enabled account for a terminated worker | HR feed delay or approved transition exception | Validate termination and exception; request approved removal |
| IAM-002 | Enabled privileged human without MFA flag | External identity-provider enforcement absent from export | Check authoritative policy and actual sign-in enforcement |
| IAM-003 | Enabled human has no login for 90 days | Leave, emergency account, incomplete login source | Get owner justification and expiry for exceptions |
| CLOUD-001 | Any bucket-level public-access guardrail disabled | Higher-level controls may still block access | Evaluate effective access; flag is not proof of public data |
| CLOUD-002 | Public IPv4/IPv6 TCP 22/3389 or all-protocol rule | No attached reachable host or blocked route | Confirm attachment, route and private administration design |
| CLOUD-003 | Storage account allows anonymous blob configuration | Containers may remain private | Inspect container exposure and business approval |
| CLOUD-004 | Secure transfer not required | Legacy clients; setting alone does not prove intercepted traffic | Test client compatibility and enforce secure transport |
| VULN-001 | Supplied normalized vulnerability record | Fixture severity may be inaccurate | Verify evidence and context before assigning final priority |

## Severity versus queue priority

Severity is retained from the lab vulnerability record. P1 is high severity plus internet exposure; P3 is low severity; all other combinations are P2. This deliberately small policy does not incorporate active exploitation, asset criticality, compensating controls, EPSS, CVSS or deadlines. It must not be described as an enterprise risk model.

## Detection tuning exercise

Change one failed authentication to a success and observe which rules still fire. Split failures across hosts; cross-host aggregation must not create a burst. Move one failure outside the five-minute window. Explain why repeated attempts spanning an hour do not meet this specific rule, even though other rules might detect them.
