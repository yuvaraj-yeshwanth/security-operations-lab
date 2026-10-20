# Proposed remediation and verification

All owners below are fictional roles. No change was implemented in a real environment.

| Work item | Proposed owner | Next action | Verification needed before closure |
| --- | --- | --- | --- |
| Suspicious authentication | SOC / identity team | Validate user and session; preserve evidence | User confirmation, session analysis, documented disposition |
| Enabled leaver | HR / IAM | Reconcile HR status and remove access after approval | Disabled identity, revoked sessions, downstream application review |
| Privileged account without MFA | IAM / IT admin | Confirm effective enforcement and require MFA | Policy evidence plus an appropriate sign-in test |
| Dormant human account | Application owner | Review need; remove or time-limit exception | Updated access inventory and owner decision |
| S3 guardrail gap | Storage owner | Review effective policy and approved use | Guardrail state and an effective-access review; no anonymous read assumption |
| Internet-wide SSH/RDP rule | Network owner | Restrict approved admin paths | Updated rule plus connectivity verification from allowed/disallowed paths |
| Anonymous blob permission | Cloud owner | Inspect containers and disable unnecessary permission | Account/container settings and effective-access test |
| Secure-transfer setting | Cloud owner | Test clients and require secure transfer | Secure clients work; insecure requests fail as intended |
| Debug endpoint | App owner | Remove debug route from deployed build | Authorized retest; local demo has a 404 after hardening |
| Cookie attributes | App owner | Add flags and test authentication with TLS | Header review plus real application session testing; demo checks headers only |
| Build-label disclosure | App owner | Remove unnecessary public header | Header absent on authorized retest |

A finding closes only after evidence supports the verification criterion, a reviewer records the decision and any exception has an owner and expiry. A recommendation is not evidence of remediation.

Conceptual framework alignment: authentication review supports detection; incident investigation supports response; identity review supports protection; configuration and vulnerability reviews support identifying and reducing risk. These are explanatory links to CSF functions, not a formal control crosswalk or audit conclusion.
