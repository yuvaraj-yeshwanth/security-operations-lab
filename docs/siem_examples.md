# Optional Splunk search examples

These are **SPL examples for manual validation**, not a deployed SIEM integration. They have not been executed against a Splunk instance in this project. The executable Python rules and their tests are the validated detection implementation.

## Data setup

Run `python run_lab.py`, then import `reports/demo/auth_for_splunk.jsonl` into a lab Splunk instance as one JSON object per event. Use an index named `secops_lab` and a sourcetype named `secops:auth`, or edit the searches to match your choices. Confirm JSON fields are accessible through `spath`. Select **All time** while testing the fixed-date sample, then narrow the range after confirming timestamp handling.

The export uses `dest_host`, not `host`, to distinguish the authentication destination from Splunk's ingestion-host metadata. The adapter exports UTC timestamps ending in Z; the searches parse that exact format into `_time`.

## Searches

- `queries/splunk/login_failure_burst.spl`: five failed events in a five-minute fixed bucket for the same user/source/destination.
- `queries/splunk/possible_password_spray.spl`: failures against four distinct users in a five-minute fixed bucket for the same source/destination.

The supplied sample should produce one burst group and one spray group after correct import and field extraction. This is an expectation to verify, not a recorded Splunk execution result.

## Window semantics matter

The SPL examples use `bin _time span=5m`, which groups events into fixed time buckets. The Python implementation uses a rolling inclusive five-minute window. They are not equivalent: a burst spanning 09:04 to 09:06 can fit a rolling window while being divided between fixed buckets. The optional SPL searches also aggregate groups rather than sharing Python's alert-suppression state. Discuss these differences before claiming rule parity.

A password-spray signal cannot prove that the same password was tried, because passwords must not be logged. Shared NAT, approved testing and broken clients can also cause grouped failures.

## Official references

- Splunk SPL `bin` reference: https://help.splunk.com/en/splunk-cloud-platform/search/search-reference/9.2.2406/search-commands/bin
- Splunk aggregate functions, including distinct count: https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.2/statistical-and-charting-functions/aggregate-functions
