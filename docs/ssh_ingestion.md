# SSH ingestion and evidence coverage

The adapter accepts a limited RFC3339-prefixed OpenSSH-style record:

```text
2026-10-19T09:00:00Z vpn-gateway sshd[2000]: Failed password for arun from 203.0.113.10 port 50000 ssh2
```

Supported messages: Failed/Accepted password and publickey, optional `invalid user`, IPv4 or IPv6 source addresses, timezone-aware RFC3339 dates and optional public-key details after `ssh2:`. Timestamps normalize to UTC. Source ports are checked but not retained in the normalized teaching schema.

Not supported: yearless RFC3164 prefixes, journald JSON, Windows Security events, Entra records, keyboard-interactive methods, multiline messages, source identity enrichment or all OpenSSH variants. It is not an assurance that every SSH authentication method is covered.

Run only the adapter:

```bash
python src/ssh_parser.py data/raw/ssh.log --out reports/parsed
```

Output files are `auth.json` and `parse_review.json`. The latter records counts, event-to-source-line mappings, and every rejected non-comment line's number and reason. IDs reflect accepted-record order; they are not stable identifiers across edited source files. Keep the raw-source hash and source mapping with each review.

`--strict` refuses to write new output if any non-comment line is rejected. With the included fixture, strict mode intentionally exits with code 2 because two unsupported messages are present. Existing files are not deleted by a failed parse.

```bash
python src/ssh_parser.py data/raw/ssh.log --out reports/strict --strict
```

The complete runner records the raw source's SHA-256 in `parse_review.json`; the adapter-only command does not add a hash. The downstream review separately hashes the normalized inputs. Neither hash proves that the source logs are authentic.

For a real collection pipeline, preserve access controls and provenance, specify clock policy, support the actual source formats, monitor parser failures, deduplicate records, correlate identities and define retention. The supplied raw file is fictional and was not collected from a live host.
