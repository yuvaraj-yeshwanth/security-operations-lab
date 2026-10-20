# Input contract

Every file contains a JSON array. Each record requires a unique, non-empty string `id` within its file. The fixtures are a custom normalized teaching schema, not AWS/Azure API responses. Additional fields are ignored. Required fields are checked; their factual accuracy is not established by validation.

| File | Required fields beyond `id` | Notes |
| --- | --- | --- |
| `auth.json` | `timestamp`, `user`, `source_ip`, `host`, `result` | Strings; result is success/failure; timestamp includes timezone; source is a valid IP |
| `users.json` | `enabled`, `employment_status`, `privileged`, `mfa_enabled`, `last_login`, `owner` | Boolean flags must be JSON booleans; status is active/terminated/service; date is YYYY-MM-DD |
| `cloud.json`, all resources | `provider`, `kind`, `owner` | Allowed provider/kind pairs: aws/s3, aws/security_group, azure/storage |
| AWS S3 | `block_public_acls`, `ignore_public_acls`, `block_public_policy`, `restrict_public_buckets` | Four booleans; only bucket-level snapshot flags |
| AWS security group | `inbound` | Array of cidr/protocol/from_port/to_port objects; protocols tcp/udp/all |
| Azure storage | `allow_blob_public_access`, `secure_transfer_required` | Two booleans |
| `vulnerabilities.json` | `asset`, `title`, `severity`, `internet_exposed`, `owner`, `evidence`, `remediation` | Severity high/medium/low; internet_exposed is a boolean; all other fields strings |

For protocol `all`, ports are ignored during detection but must still be a valid ordered range; use 0 and 65535. Public administration detection checks only unrestricted CIDRs `0.0.0.0/0` and `::/0`, not every possible collection of broader prefixes. It flags a permissive rule, not a proven attack path.

Authentication and login dates must not be after the review date. Dormancy uses whole calendar days, with 90 days inclusive. The date of an authentication event is taken in its supplied offset; a production adapter should normalize its date policy, user IDs, host IDs and clock conventions consistently. Timestamp arithmetic for windows is timezone aware.

All IPs are documentation ranges or private addresses. People, owners, hosts, resource IDs, vulnerabilities and events are fictional. The `owner` labels are proposed lab roles, not real assignments.

Service identities need separate controls such as credential lifecycle, workload identity, scoped permissions and owner review. Excluding them from the human-account rules does not assess those controls.
