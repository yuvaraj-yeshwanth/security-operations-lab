# Interview demonstration

## Five-minute walkthrough

1. **Scope, 30 seconds.** Explain that the project reviews fictional snapshots and runs a real loopback HTTP exercise. It has no access to AWS/Azure tenants and does not perform third-party scans.
2. **Execution, 45 seconds.** Run `python run_lab.py`. Show the 18 parsed events, 2 rejected lines, 13 snapshot findings and local HTTP results. Explain why rejected lines are visible instead of silently discarded.
3. **Investigation, 90 seconds.** Follow AUTH-003 from report to normalized events to raw line 7. Explain the five failures and later success. Identify MFA, device and user-confirmation evidence that would be needed next.
4. **Access and cloud, 60 seconds.** Show an enabled-leaver account and an S3 guardrail gap. Explain owner approval and why the S3 flag does not prove public exposure.
5. **Local assessment, 45 seconds.** Show the debug endpoint's 200/404 responses and the cookie headers before and after hardening. Explain that the server is plain loopback HTTP, so cookie flags are not a TLS deployment.
6. **Quality and ownership, 30 seconds.** Run the tests or show your own saved execution record. Point to a change you personally made and explain its test. If asked who wrote the starter code, answer accurately.

## Questions and the reasoning behind them

| Question | What a sound answer should establish |
| --- | --- |
| What happens after a suspicious login alert? | Preserve and validate evidence, investigate context, escalate when justified and use an approved response process |
| Why not block every source immediately? | Shared infrastructure and legitimate retries can cause false positives; blocking has operational consequences |
| Why keep rejected parser lines? | Unsupported formats are a coverage gap; zero alerts does not mean zero risk |
| Why exclude service identities from human MFA checks? | Workload identities need different authentication and lifecycle controls, not an automatic clean bill of health |
| Is an internet-wide SSH rule proof of reachability? | Routes, attachment, host firewall and other controls still matter |
| What does the CSV queue accomplish? | It turns findings into reviewable work with evidence and proposed owners; it does not prove remediation |
| What is different between the Python and SPL examples? | Rolling versus fixed windows, alert suppression and execution validation |
| Why might this fail in production? | Source diversity, scale, identity normalization, clock skew, duplicates, missing telemetry, operational ownership and access controls |

## Claims to avoid

Do not invent production improvements, percentage risk reduction, client experience or detection accuracy. “13 findings” is a property of deliberately designed fixtures. “Tests pass” is an observed software check, not proof that a real enterprise is secure.
