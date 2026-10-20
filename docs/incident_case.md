# Case IR-LAB-001: successful login after repeated failures

**Classification:** simulated suspicious authentication; compromise unconfirmed.

**Scope:** `vpn-gateway`, fictional user `arun`, documentation IP `203.0.113.10`. Case date: 19 October 2026. No real incident occurred.

## Timeline

| UTC time | Evidence | Observation |
| --- | --- | --- |
| 09:00-09:04 | EVT-001 to EVT-005 | Five failures for the same user, source and destination |
| 09:04 | AUTH-001 | Failure threshold met |
| 09:05 | EVT-006; AUTH-003 | A matching successful authentication follows |

The success arrives exactly five minutes after the first failure, so the first failure remains inside the inclusive window. Review the event IDs in `examples/findings.json`; finding sequence IDs can change if input data changes.

## Analyst assessment

The evidence supports suspicious authentication, not confirmed account takeover. A legitimate user could mistype a password. Missing evidence includes effective MFA enforcement, SSH session details, device identity, user confirmation, source ownership and post-login actions. In the complete demo, the gateway-named host emits fictional SSH records; these are not VPN sign-in events. There is no evidence of malware, data theft or business impact in the fixtures.

## Proposed response

1. Preserve original SSH/host logs and relevant identity records and record their source, collection time, timezone, access restrictions and retention. The supplied hash report covers fixture bytes only.
2. Validate the user, source and expected activity through an approved internal channel. Inspect relevant identity-provider and endpoint records.
3. Escalate if unauthorized access is suspected. A response owner decides whether to revoke sessions, reset credentials or isolate a device. Those actions were not executed here.
4. Check subsequent access, privileged operations and affected resources. Record evidence gaps rather than inventing a scope or impact estimate.
5. After any approved recovery, verify expected sign-in behavior, monitor recurrence and document lessons learned and rule tuning.

## Disposition

Open for analyst review. No containment, eradication or recovery result is claimed. The broader process follows the idea of integrating preparation, detection, response and recovery into risk management; it is not an assertion of NIST conformance. See the NIST SP 800-61 Rev. 3 reference.
