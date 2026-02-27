# Infraguard

> AWS infrastructure security auditing tool for engineering teams

Infraguard is a command-line tool that audits your AWS infrastructure and validates configurations against security best practices. It helps identify misconfigurations, security vulnerabilities, and compliance issues across your AWS environment.

## Features

- **S3 Security Auditing**: Detect publicly accessible buckets, missing encryption, and insecure bucket policies
- **IAM Security**: Check for missing MFA, old access keys, and overly permissive policies
- **EC2 Security**: Identify open security groups, unencrypted EBS volumes, and IMDSv1 usage
- **Logging & Monitoring**: Verify CloudTrail, AWS Config, and GuardDuty are properly enabled
- **Multi-Region Support**: Scan across multiple AWS regions concurrently
- **Flexible Output**: Human-readable text or structured JSON for CI/CD integration
- **Concurrent Execution**: Fast parallel check execution for quick results

## Installation

### From Source

```bash
git clone https://github.com/yourorg/infraguard.git
cd infraguard
go build -o infraguard ./cmd/infraguard
sudo mv infraguard /usr/local/bin/
```

### Prerequisites

- Go 1.24.3 or later
- AWS credentials configured (see Authentication)

## Quick Start

```bash
# Audit infrastructure in default region (eu-west-2)
infraguard infra

# Audit configuration across multiple regions
infraguard config -r us-east-1,us-west-2,eu-west-1

# Output as JSON for automation
infraguard infra --output json

# Use a specific AWS profile
infraguard infra --profile production
```

## Authentication

Infraguard uses the AWS default credential chain to authenticate:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. AWS credentials file (`~/.aws/credentials`)
3. AWS config file (`~/.aws/config`)
4. IAM instance profile (when running on EC2)
5. ECS container credentials (when running on ECS)

### Using AWS Profiles

```bash
# Use a named profile
infraguard infra --profile my-profile

# Or set the environment variable
export AWS_PROFILE=my-profile
infraguard infra
```

## Commands

### `infraguard infra`

Audits live AWS infrastructure resources for security misconfigurations.

**Checks performed:**
- **S3**: Public buckets, missing encryption
- **IAM**: Missing MFA, old access keys, root account security
- **EC2**: Open security groups, unencrypted EBS volumes, IMDSv1 enabled
- **CloudTrail**: Logging enabled and active
- **AWS Config**: Configuration recorder enabled
- **GuardDuty**: Threat detection enabled

```bash
# Basic usage
infraguard infra

# Multiple regions
infraguard infra -r us-east-1,us-west-2,eu-west-1

# JSON output for CI/CD
infraguard infra --output json > audit-results.json
```

### `infraguard config`

Validates AWS configuration settings and account-level service enablement.

**Checks performed:**
- CloudTrail trail configuration and status
- AWS Config recorder status
- GuardDuty detector status

```bash
# Basic usage
infraguard config

# Specific region
infraguard config -r us-east-1
```

## Flags

### Global Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--output` | `-o` | Output format: `text` or `json` | `text` |
| `--region` | `-r` | Comma-separated list of AWS regions | `eu-west-2` |
| `--profile` | | AWS named profile to use | (default profile) |

## IAM Permissions

Infraguard requires read-only permissions to audit your AWS environment. Below is a minimal IAM policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetPublicAccessBlock",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketLocation",
        "s3:GetEncryptionConfiguration",
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:GetLoginProfile",
        "iam:ListAccessKeys",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "ec2:DescribeInstances",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

For AWS Organizations, you can use the AWS-managed `SecurityAudit` policy as a starting point.

## Output Formats

### Text Output (Default)

Human-readable output with findings grouped by severity:

```
infraguard: running infra audit in regions [us-east-1] (output: text)
infraguard: authenticated as account 123456789012

[CRITICAL] 2 finding(s)
────────────────────────────────────────────────────────────
  Check:       s3/public-buckets
  Resource:    arn:aws:s3:::my-public-bucket
  Region:      us-east-1
  Message:     S3 bucket 'my-public-bucket' has no public access block configuration
  Remediation: Enable S3 Block Public Access settings...
  Discovered:  2026-02-27T13:45:00Z

[HIGH] 3 finding(s)
────────────────────────────────────────────────────────────
  ...
```

### JSON Output

Structured JSON for automation and CI/CD integration:

```json
{
  "findings": [
    {
      "check_name": "s3/public-buckets",
      "severity": "CRITICAL",
      "resource_id": "arn:aws:s3:::my-public-bucket",
      "region": "us-east-1",
      "message": "S3 bucket 'my-public-bucket' has no public access block configuration",
      "remediation": "Enable S3 Block Public Access settings...",
      "discovered_at": "2026-02-27T13:45:00Z"
    }
  ],
  "errors": {},
  "summary": {
    "CRITICAL": 2,
    "HIGH": 3,
    "MEDIUM": 1,
    "LOW": 0,
    "INFO": 5
  }
}
```

## Security Checks Reference

### S3 Checks

| Check | Severity | Description |
|-------|----------|-------------|
| `s3/public-buckets` | CRITICAL | Detects S3 buckets with public access enabled |
| `s3/unencrypted-buckets` | HIGH | Identifies buckets without default encryption |

### IAM Checks

| Check | Severity | Description |
|-------|----------|-------------|
| `iam/root-mfa` | CRITICAL | Verifies root account has MFA enabled |
| `iam/users-missing-mfa` | HIGH | Identifies IAM users with console access but no MFA |
| `iam/old-access-keys` | MEDIUM | Finds access keys older than 90 days |

### EC2 Checks

| Check | Severity | Description |
|-------|----------|-------------|
| `ec2/open-security-groups` | CRITICAL | Detects security groups with unrestricted ingress (0.0.0.0/0 or ::/0) |
| `ec2/unencrypted-ebs` | HIGH | Identifies EBS volumes without encryption |
| `ec2/imdsv1-enabled` | MEDIUM | Finds EC2 instances allowing IMDSv1 (insecure metadata service) |

### Logging Checks

| Check | Severity | Description |
|-------|----------|-------------|
| `logging/cloudtrail-enabled` | CRITICAL | Verifies CloudTrail is enabled and logging |
| `logging/config-recorder` | HIGH | Checks AWS Config recorder is enabled |
| `logging/guardduty-enabled` | HIGH | Verifies GuardDuty threat detection is enabled |

## CI/CD Integration

### GitHub Actions

```yaml
name: AWS Security Audit
on:
  schedule:
    - cron: '0 0 * * *'  # Daily
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      - name: Install Infraguard
        run: |
          wget https://github.com/yourorg/infraguard/releases/latest/download/infraguard
          chmod +x infraguard

      - name: Run Audit
        run: |
          ./infraguard infra --output json > audit-results.json

      - name: Check for Critical Findings
        run: |
          if jq -e '.summary.CRITICAL > 0' audit-results.json; then
            echo "❌ Critical security findings detected!"
            exit 1
          fi
```

### GitLab CI

```yaml
aws-security-audit:
  stage: security
  image: golang:1.24
  before_script:
    - go install github.com/yourorg/infraguard/cmd/infraguard@latest
  script:
    - infraguard infra --output json | tee audit-results.json
    - |
      if jq -e '.summary.CRITICAL > 0' audit-results.json; then
        echo "❌ Critical security findings detected!"
        exit 1
      fi
  artifacts:
    reports:
      junit: audit-results.json
  only:
    - schedules
```

## Development

### Project Structure

```
infraguard/
├── cmd/infraguard/        # CLI entry point
│   └── main.go
├── internal/
│   ├── awsutil/           # AWS SDK configuration helpers
│   ├── checks/            # Security check implementations
│   │   ├── s3/            # S3 security checks
│   │   ├── iam/           # IAM security checks
│   │   ├── ec2/           # EC2 security checks
│   │   └── logging/       # Logging & monitoring checks
│   ├── cli/               # Cobra command definitions
│   ├── collector/         # AWS resource collectors
│   ├── engine/            # Check execution engine
│   └── reporter/          # Output formatters
├── go.mod
└── README.md
```

### Adding New Checks

1. Create a new check file in the appropriate package (e.g., `internal/checks/s3/my_check.go`)
2. Implement the `engine.Check` interface:

```go
type MyCheck struct{}

func (c *MyCheck) Name() string {
    return "s3/my-check"
}

func (c *MyCheck) Description() string {
    return "Brief description of what this check does"
}

func (c *MyCheck) Severity() engine.Severity {
    return engine.SeverityHigh
}

func (c *MyCheck) RequiredIAMPermissions() []string {
    return []string{"s3:GetBucketPolicy"}
}

func (c *MyCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
    // Implement check logic
    return findings, nil
}
```

3. Register the check in `internal/cli/audit_infra.go`:

```go
eng.Register(&s3.MyCheck{})
```

4. Build and test:

```bash
go build ./...
go test ./...
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests for a specific package
go test ./internal/checks/s3/...
```

## Troubleshooting

### "NoCredentialProviders" Error

```
Error: failed to load AWS config: no AWS credentials found
```

**Solution**: Configure AWS credentials using one of these methods:
- Set environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
- Create `~/.aws/credentials` file
- Use an IAM instance profile (when running on EC2)

### "AccessDenied" Errors

```
Error: Access Denied when calling s3:ListAllMyBuckets
```

**Solution**: Ensure your IAM user/role has the required permissions. See [IAM Permissions](#iam-permissions).

### Slow Execution

Infraguard runs checks concurrently, but large environments with many resources may take time:
- Reduce the number of regions: `-r us-east-1`
- Use specific checks (feature coming soon)
- Run in parallel for different regions using CI/CD

## Roadmap

- [ ] VPC security checks (NACLs, route tables, VPC Flow Logs)
- [ ] RDS security checks (encryption, public accessibility, backups)
- [ ] Lambda security checks (execution roles, VPC configuration)
- [ ] Check filtering (`--skip-checks`, `--only-checks`)
- [ ] Custom check policies via YAML configuration
- [ ] HTML report generation
- [ ] Remediation automation mode
- [ ] AWS Organizations support for multi-account auditing

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Security

If you discover a security vulnerability, please email security@yourorg.com instead of using the issue tracker.

## Support

- Documentation: [https://infraguard.yourorg.com](https://infraguard.yourorg.com)
- Issues: [GitHub Issues](https://github.com/yourorg/infraguard/issues)
- Discussions: [GitHub Discussions](https://github.com/yourorg/infraguard/discussions)

---

**Built with ❤️ for AWS security**
