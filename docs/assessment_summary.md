# Assessment summary - demonstration environment

**Snapshot date:** 20 October 2026. **Status:** simulated review; recommendations open.

## Main observations

- Five failed logins followed by a matching success deserve investigation. They do not establish compromise.
- An enabled leaver account and a privileged human account without an MFA flag need owner review against authoritative identity and HR records.
- An internet-wide administration rule and storage guardrail gaps require an effective-access review. Snapshot settings alone do not establish data exposure.
- The executed local HTTP exercise shows debug-route removal and improved cookie/header settings. It does not establish full application security.

The supplied evidence yields **13 snapshot findings: 5 high, 7 medium and 1 low**. The local HTTP exercise is recorded separately and is not added again to those totals. The vulnerability snapshot mirrors the same teaching themes but is fictional, so the report must not describe it as independently verified internet exposure.

## Suggested analyst priorities

1. Validate the suspicious authentication and the enabled leaver account.
2. Verify MFA enforcement and effective administration exposure.
3. Review storage configuration, dormant access and the supplied application observations with their owners.
4. Track approved changes and retest evidence before closing findings.

These are teaching priorities, not an organization's response SLA. Real priorities require asset criticality, exploitation evidence, business impact, compensating controls and the organization's risk appetite.

## Deliverables

The demo creates a parser coverage report, normalized evidence, JSON/Markdown findings, a CSV work queue, raw local HTTP observations and a run summary. The `run_status` field indicates whether the complete runner finished. A failed run can leave partial files; do not present them as a completed assessment.
