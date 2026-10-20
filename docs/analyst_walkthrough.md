# Run the lab and make it your own

## First run

1. Install Python 3.10+ and run all three Quick start commands from the README.
2. Confirm the snapshot produces 13 findings: 5 high, 7 medium, 1 low.
3. Inspect the five-failure authentication sequence and the subsequent success in the JSON inputs.
4. Follow AUTH-003 evidence IDs into the incident case. Explain why compromise remains unconfirmed.
5. Review one IAM and one cloud finding. Distinguish a permissive setting from proven exposure.
6. Read the actual local web responses. Match each remediation to its before/after evidence.
7. Change one fixture in a private working copy, rerun the review, and record the changed finding count. Restore the canonical fixtures before running the regression suite; it intentionally expects the committed example results.
8. Add a new boundary test and explain what failure it would prevent.

## Personal validation record

Create your own `docs/personal_validation.md` after doing the work. Record:

- Your run date, OS and Python version.
- Commands executed and observed results.
- One rule you changed and the before/after behavior.
- One false positive and one blind spot you identified.
- Your own short triage decision using the supplied evidence.

Do not prefill a run date or claim results you have not personally observed. This file is intentionally not included as a completed record.

## Five-minute interview demo

- Minute 1: explain the problem and the distinction between synthetic snapshots and executed localhost requests.
- Minute 2: run the snapshot review and follow AUTH-003 evidence.
- Minute 3: show an enabled leaver and explain ownership and approval.
- Minute 4: run the web exercise and compare raw headers/status codes.
- Minute 5: show a boundary test and explain limitations, including no live cloud, SIEM or confirmed breach.

## Questions you must answer

1. Why group failures by source and host as well as user?
2. Why does successful authentication after failures not prove compromise?
3. Why are service identities excluded from human-MFA checks?
4. Why does disabled S3 Block Public Access not by itself prove a public bucket?
5. How is severity different from remediation priority?
6. What does a SHA-256 digest establish, and what does it not establish?
7. Why is a Secure cookie flag not evidence of HTTPS deployment?
8. What adapters and operational controls would be needed to use real logs?

## GitHub upload

Suggested repository name: `security-operations-lab`. Create an empty repository, extract the project ZIP, and upload the **contents** of the project folder. Keep `src`, `data`, `tests`, `docs`, `examples` and `.github` at the repository root. GitHub's browser uploader may skip the hidden `.github` directory; add `.github/workflows/tests.yml` manually or use Git to retain it.

With Git, from the extracted project folder:

```bash
git init
git add .
git commit -m "Add security operations lab and evidence"
git branch -M main
git remote add origin https://github.com/yuvaraj-yeshwanth/security-operations-lab.git
git push -u origin main
```

The remote URL is the suggested destination, not an existing or published repository. Create it first. Do not publish your resume, phone number, email, private incident data or real credentials with this lab. Review the GitHub Actions result after pushing; local tests here do not prove the hosted workflow has run.

## Resume wording after personal validation

Title: **Security Operations Lab | Python, IAM, AWS/Azure configuration review**

- Built a Python lab to flag suspicious login patterns, review user access, and check normalized AWS/Azure configuration snapshots.
- Generated evidence-linked reports with severity, owners and remediation steps; tested a local web app before and after hardening.

Use "built" only if you have worked through and can explain or extend the implementation. Otherwise use "Completed a guided Python lab covering..." and describe the parts you actually completed. Do not claim the tests as authored by you unless you wrote them.
