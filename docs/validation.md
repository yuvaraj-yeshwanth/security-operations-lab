# Recorded validation

Validated in the preparation workspace on **20 October 2026**, using **Python 3.12.14 on Linux**.

| Check | Observed result |
| --- | --- |
| Complete demo runner | Finished successfully |
| SSH adapter | 18 accepted authentication records, 2 rejected non-comment lines, 1 comment line |
| Snapshot review | 13 findings: 5 high, 7 medium, 1 low |
| Remediation export | 13 CSV data rows with evidence, owner roles and recommendations |
| Local HTTP exercise | All four vulnerable-mode checks failed; all four hardened-mode checks passed |
| Automated suite | 38 tests passed |
| Raw-to-normalized regression | Parsed fixture events match the committed normalized authentication fixture |
| Evidence traceability | Source-line mapping, raw-source SHA-256 and normalized-input SHA-256 records present |

Commands used:

```bash
python3 run_lab.py
python3 -m unittest discover -s tests -v
```

The tests exercise inclusive window boundaries, source/host scoping, stale events, detection thresholds, input validation, IPv6, parser rejection, timestamp offsets, CSV formula neutralization, complete-demo outputs and actual loopback HTTP behavior.

GitHub Actions is configured for Python 3.10, 3.12 and 3.13, but those hosted jobs have not been run by this package. Local validation here was on 3.12.14 only. The optional Splunk searches have not been execution-tested. No live cloud, production SIEM or real incident was assessed.

This is a preparation-workspace validation record. It is not Yuvaraj's personal execution record. Create `docs/personal_validation.md` only after running the lab yourself and recording your actual observations.
