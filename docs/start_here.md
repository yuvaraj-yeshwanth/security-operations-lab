# Start here

## 1. Run the complete project

Install Python 3.10 or newer. Extract the archive and open a terminal **inside the `security-operations-lab` folder**, where `run_lab.py` is visible.

On Ubuntu/Linux:

```bash
python3 --version
python3 run_lab.py
python3 -m unittest discover -s tests -v
```

On Windows:

```powershell
py -3 --version
py -3 run_lab.py
py -3 -m unittest discover -s tests -v
```

There are no external Python dependencies to install. The default demo uses synthetic files and a temporary loopback HTTP app. It does not use your cloud account or collect host logs. The review date is fixed to the sample snapshot date, 20 October 2026.

## 2. Inspect the evidence

Open these generated files:

| File under `reports/demo/` | What to inspect |
| --- | --- |
| `summary.json` | `run_status` must say `complete`; inspect counts and web-exercise status |
| `parse_review.json` | 18 supported SSH messages, 2 rejected non-comment lines, raw-source hash and original line references |
| `normalized/auth.json` | Common event schema used by the rules |
| `review/report.md` | 13 findings with evidence, owner roles and recommendations |
| `review/findings.json` | Machine-readable version of the same review |
| `remediation_queue.csv` | Work queue you can open in Excel; recommendations remain open |
| `local_web_assessment.md` | Before/after checks from executed local requests |
| `local_web/before_after.json` | Actual HTTP status, header and body observations |
| `auth_for_splunk.jsonl` | Optional SIEM import sample; importing into Splunk is a separate step |

The two rejected lines are deliberately included: one connection-close message and one unrelated systemd message. Their line numbers remain in the parse report. They are **not** treated as evidence of a successful or failed login. Review rejected lines when judging coverage.

If a device policy blocks loopback sockets, use a separate output directory:

```bash
python3 run_lab.py --skip-web --out reports/snapshot-only
```

This records that the web exercise was skipped. Do not claim the web checks ran on that run. A snapshot-only run refuses a directory containing older web evidence, so old observations cannot look like a new assessment.

## 3. Understand one complete finding

Trace AUTH-003 from `review/findings.json` to events EVT-001 through EVT-006 in `normalized/auth.json`. Use `parse_review.json` to locate those events in `data/raw/ssh.log`. The source mapping identifies line 7 as EVT-006. Explain what happened and what evidence is still missing before calling it a compromise.

## 4. Make a personal contribution

Use a temporary copy of the input data for experiments. The regression tests expect the committed fixtures to stay unchanged.

- Change a failure time so that it leaves the five-minute window. Explain the result.
- Add a parser test for an unsupported log message and document the coverage gap.
- Add a triage decision in your own words, with the evidence that supports it.
- Record your actual OS, Python version, commands and observations in a new `docs/personal_validation.md`.

Do not prefill observations you have not made. The project gives you a working starting point; your own run, explanation and changes make it demonstrable work.

## 5. Publish to GitHub

Suggested repository name: **security-operations-lab**.

Suggested description:

> Python security operations lab with SSH log parsing, login detection, IAM and cloud configuration reviews, incident triage, and a local web hardening exercise.

Suggested topics: `cybersecurity`, `soc`, `python`, `log-analysis`, `incident-response`, `iam`, `cloud-security`, `security-lab`.

Create an empty GitHub repository, then upload the extracted folder's contents. `README.md`, `run_lab.py`, `src`, `tests`, `data`, `docs`, `queries` and `examples` should be at the repository root. Upload the extracted files, not just the ZIP.

Using Git from the project folder preserves the hidden workflow directory:

```bash
git init
git add .
git commit -m "Add security operations lab and evidence"
git branch -M main
git remote add origin https://github.com/yuvaraj-yeshwanth/security-operations-lab.git
git push -u origin main
```

Create that remote repository before running the last commands. The URL is a suggested destination, not a repository already published by this deliverable. If using GitHub's browser uploader, ensure `.github/workflows/tests.yml` is included; add it manually if the browser skips it. Verify the Actions run after pushing.

## 6. Present it accurately

After personally completing the exercises, use wording such as:

> Completed and extended a Python security operations lab covering SSH log parsing, suspicious authentication, user access reviews and offline AWS/Azure configuration checks. Reviewed evidence-linked findings and tested a local HTTP app before and after hardening.

Use “extended” only after making your own changes. Be ready to identify which parts were prepared and which parts you implemented. Do not claim production SOC ownership, live cloud remediation, a confirmed breach, CVE discovery, or deployment of the optional Splunk queries from this lab alone.
