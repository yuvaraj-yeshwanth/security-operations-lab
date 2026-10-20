# Technical references

Consulted 20 October 2026. The implementations use a deliberately limited normalized teaching schema. These sources explain the underlying controls; they do not endorse this project or establish conformance.

- NIST, SP 800-61 Rev. 3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- AWS, S3 security best practices: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html
- AWS, S3 Block Public Access: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- AWS, IAM security best practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- Microsoft, secure transfer for Azure Storage: https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer
- Microsoft, Blob Storage security recommendations: https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations

NIST SP 800-61 Rev. 3 integrates incident response with CSF 2.0 risk-management activities. AWS guidance distinguishes public-access settings from effective resource access, and recommends least privilege and appropriate MFA. Microsoft's storage guidance distinguishes anonymous access permissions from secure transport enforcement. The lab implements selected checks and review questions from those concepts; thresholds and priorities are local teaching choices.

- Python HTTP server documentation: https://docs.python.org/3.12/library/http.server.html
- Splunk SPL fixed time buckets: https://help.splunk.com/en/splunk-cloud-platform/search/search-reference/9.2.2406/search-commands/bin
- Splunk aggregate functions: https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.2/statistical-and-charting-functions/aggregate-functions
