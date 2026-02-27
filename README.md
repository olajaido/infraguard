# Infraguard

> Enterprise-grade AWS infrastructure security auditing tool

Infraguard is a lightning-fast command-line tool that audits your AWS infrastructure and validates configurations against security best practices. With **50 comprehensive security checks** across **12 AWS services**, it helps identify misconfigurations, security vulnerabilities, and compliance issues in seconds.

## ✨ Key Features

- **🚀 Lightning Fast**: 50 concurrent checks complete in 15-30 seconds
- **🎨 Beautiful UI**: Colour-coded output with ASCII art banner
- **🔄 Auto-Retry**: Built-in AWS rate limit handling with exponential backoff
- **📊 Real-time Progress**: See each check as it runs
- **🌍 Multi-Region**: Scan across multiple AWS regions simultaneously
- **📄 Flexible Output**: Human-readable text or structured JSON
- **✅ 50 Security Checks**: Comprehensive coverage across 12 AWS services
- **🛡️ Production-Ready**: Battle-tested with automatic error recovery

## 🎯 What's New in v2.0

**Massive Expansion**: From 11 to 50 security checks (+354%!)

- ✅ **VPC Security** (5 checks): Flow logs, default VPC, network ACLs, VPC peering
- ✅ **KMS & Secrets** (3 checks): Key rotation, overly permissive policies, secrets rotation
- ✅ **Load Balancers** (3 checks): HTTP→HTTPS redirects, access logging, SSL certificates
- ✅ **CloudFront** (3 checks): TLS versions, WAF protection, access logging
- ✅ **Cost Optimization** (3 checks): Unattached EIPs, unused EBS volumes, idle load balancers
- ✅ **Enhanced IAM** (4 new checks): Stale users, wildcard policies, dual access, root usage
- ✅ **Enhanced S3** (4 new checks): Versioning, logging, lifecycle policies, bucket policies
- ✅ **Enhanced EC2** (4 new checks): Public AMIs, stopped instances, snapshots, ephemeral IPs
- ✅ **Complete RDS Suite** (5 checks): Public access, encryption, backups, Multi-AZ, snapshots
- ✅ **Lambda Security** (2 checks): Secrets in env vars, deprecated runtimes
- ✅ **Container Security** (3 checks): Privileged containers, host networking, ECR lifecycle

## 📥 Installation

### From Source

```bash
git clone https://github.com/olajaido/infraguard
cd infraguard
go build -o infraguard ./cmd/infraguard
sudo mv infraguard /usr/local/bin/
```

### Build with Version Info

```bash
VERSION=2.0.0
go build -ldflags "-X https://github.com/olajaido/infraguard/internal/cli.version=${VERSION}" \
  -o infraguard ./cmd/infraguard
```

### Prerequisites

- Go 1.24.3 or later
- AWS credentials configured (see [Authentication](#-authentication))

## 🚀 Quick Start

```bash
# Audit infrastructure with beautiful coloured output
./infraguard infra

# Audit multiple regions
./infraguard infra -r us-east-1,eu-west-1,ap-southeast-1

# JSON output for CI/CD (colours auto-disabled)
./infraguard infra -o json > audit.json

# Use specific AWS profile
./infraguard infra --profile production
```

## 🎨 Visual Experience

### Beautiful Banner & Progress

```
  _        __                                     _
 (_)_ __  / _|_ __ __ _  __ _ _   _  __ _ _ __ __| |
 | | '_ \| |_| '__/ _' |/ _' | | | |/ _' | '__/ _' |
 | | | | |  _| | | (_| | (_| | |_| | (_| | | | (_| |
 |_|_| |_|_| |_|  \__,_|\__, |\__,_|\__,_|_|  \__,_|
                        |___/
  AWS Infrastructure Auditing CLI
  Version: 2.0.0

  Account: 345594566447
  Regions: eu-west-1, us-east-1

  Starting scan with 50 checks across 2 region(s)...

  → Running check: s3/public-buckets [eu-west-1]
  ✓ Completed: s3/public-buckets [eu-west-1] - 2 findings
  → Running check: iam/root-mfa [eu-west-1]
  ✓ Completed: iam/root-mfa [eu-west-1] - 0 findings
  ...

✓ Scan complete: 100/100 checks finished, 28 findings, 0 errors
```

### Colour-Coded Results

```
[CRITICAL] 5 finding(s)  ← Bold Red - jumps out!
────────────────────────────────────────────────────────────
  Check:       [CRITICAL] s3/public-buckets
  Resource:    arn:aws:s3:::my-bucket
  Region:      eu-west-1
  Message:     S3 bucket 'my-bucket' has public access enabled
  Remediation: Enable S3 Block Public Access settings...

[HIGH] 8 finding(s)  ← Orange
[MEDIUM] 12 finding(s)  ← Yellow
[LOW] 3 finding(s)  ← Cyan
```

**Colours auto-disable for:**
- Piped output (`| less`)
- Redirected output (`> file.txt`)
- JSON mode (`-o json`)
- `NO_COLOR=1` environment variable

## 🔒 Complete Security Coverage (50 Checks)

### IAM (7 checks)
- `iam/root-mfa` - Root account MFA verification (**CRITICAL**)
- `iam/users-missing-mfa` - Users without MFA (**HIGH**)
- `iam/old-access-keys` - Access keys >90 days (**MEDIUM**)
- `iam/stale-users` - Inactive users (90+ days) (**MEDIUM**)
- `iam/wildcard-policies` - `*:*` wildcard permissions (**CRITICAL**)
- `iam/dual-access-users` - Console + API access (**MEDIUM**)
- `iam/root-account-usage` - Root account usage (**CRITICAL**)

### S3 (6 checks)
- `s3/public-buckets` - Public access enabled (**CRITICAL**)
- `s3/unencrypted-buckets` - No default encryption (**HIGH**)
- `s3/no-versioning` - Versioning disabled (**MEDIUM**)
- `s3/no-access-logging` - Access logging disabled (**MEDIUM**)
- `s3/no-lifecycle-policy` - No lifecycle policy (**LOW**)
- `s3/public-getobject-policy` - Public GetObject access (**CRITICAL**)

### EC2 (7 checks)
- `ec2/open-security-groups` - 0.0.0.0/0 ingress (**CRITICAL**)
- `ec2/unencrypted-ebs` - Unencrypted EBS volumes (**HIGH**)
- `ec2/imdsv1-enabled` - IMDSv1 allowed (**MEDIUM**)
- `ec2/public-amis` - Publicly shared AMIs (**CRITICAL**)
- `ec2/stopped-instances` - Stopped 30+ days (**LOW**)
- `ec2/unencrypted-snapshots` - Unencrypted snapshots (**HIGH**)
- `ec2/ephemeral-public-ips` - Ephemeral IPs (**MEDIUM**)

### RDS (5 checks)
- `rds/public-instances` - Publicly accessible (**CRITICAL**)
- `rds/unencrypted-instances` - No encryption at rest (**HIGH**)
- `rds/no-backups` - No automated backups (**HIGH**)
- `rds/no-multi-az` - No Multi-AZ (**MEDIUM**)
- `rds/public-snapshots` - Public snapshots (**CRITICAL**)

### VPC (5 checks)
- `vpc/no-flow-logs` - No VPC flow logs (**HIGH**)
- `vpc/default-vpc-exists` - Default VPC exists (**MEDIUM**)
- `vpc/map-public-ip-on-launch` - Auto-assign public IPs (**MEDIUM**)
- `vpc/open-network-acls` - Permissive NACLs (**HIGH**)
- `vpc/stale-peering` - Inactive peering (**LOW**)

### Lambda (2 checks)
- `lambda/secrets-in-env` - Secrets in environment variables (**HIGH**)
- `lambda/deprecated-runtime` - Deprecated runtimes (**HIGH**)

### ECS/ECR (3 checks)
- `ecs/privileged-containers` - Privileged containers (**CRITICAL**)
- `ecs/host-network-mode` - Host network mode (**HIGH**)
- `ecr/no-lifecycle-policy` - No lifecycle policy (**LOW**)

### KMS (3 checks)
- `kms/no-key-rotation` - No automatic rotation (**MEDIUM**)
- `kms/overly-permissive-policy` - `*` principal policies (**CRITICAL**)
- `kms/secrets-no-rotation` - Secrets Manager no rotation (**MEDIUM**)

### ELB (3 checks)
- `elb/http-no-redirect` - HTTP without HTTPS redirect (**HIGH**)
- `elb/no-access-logging` - No access logging (**MEDIUM**)
- `elb/ssl-cert-expiring` - Expiring SSL certificates (**HIGH**)

### CloudFront (3 checks)
- `cloudfront/deprecated-tls` - TLS < 1.2 (**HIGH**)
- `cloudfront/no-waf` - No WAF protection (**MEDIUM**)
- `cloudfront/no-logging` - No access logging (**MEDIUM**)

### Cost/Hygiene (3 checks)
- `cost/unattached-eips` - Unattached Elastic IPs (**LOW**)
- `cost/unattached-ebs-volumes` - Unattached EBS volumes (**LOW**)
- `cost/unused-load-balancers` - Load balancers with no targets (**LOW**)

### Logging (3 checks)
- `logging/cloudtrail-enabled` - CloudTrail logging (**CRITICAL**)
- `logging/config-recorder` - AWS Config recorder (**HIGH**)
- `logging/guardduty-enabled` - GuardDuty enabled (**HIGH**)

## 🔑 Authentication

Infraguard uses the AWS SDK default credential chain:

1. **Environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
2. **AWS credentials file**: `~/.aws/credentials`
3. **AWS config file**: `~/.aws/config`
4. **IAM instance profile** (on EC2)
5. **ECS container credentials** (on ECS)

### Using AWS Profiles

```bash
# Named profile
./infraguard infra --profile production

# Environment variable
export AWS_PROFILE=production
./infraguard infra
```

## 📋 IAM Permissions

**Minimal read-only policy for all 50 checks:**

<details>
<summary>Click to expand IAM policy JSON</summary>

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketLocation",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetLifecycleConfiguration",
        "s3:GetBucketPolicy",
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:GetUser",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "ec2:DescribeImages",
        "ec2:DescribeImageAttribute",
        "ec2:DescribeSnapshots",
        "ec2:DescribeAddresses",
        "ec2:DescribeVpcs",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeSubnets",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeVpcPeeringConnections",
        "rds:DescribeDBInstances",
        "rds:DescribeDBSnapshots",
        "rds:DescribeDBSnapshotAttributes",
        "lambda:ListFunctions",
        "lambda:GetFunction",
        "ecs:ListTaskDefinitions",
        "ecs:DescribeTaskDefinition",
        "ecr:DescribeRepositories",
        "ecr:GetLifecyclePolicy",
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:GetKeyPolicy",
        "secretsmanager:ListSecrets",
        "secretsmanager:DescribeSecret",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "cloudfront:ListDistributions",
        "cloudfront:GetDistribution",
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

</details>

**AWS-managed policy**: Consider starting with `SecurityAudit` for AWS Organizations.

## 📊 Output Formats

### Text Output (Default)

Colour-coded, human-readable output:

```bash
./infraguard infra
```

```
[CRITICAL] 2 finding(s)  ← Red
────────────────────────────────────────────────────────────
  Check:       [CRITICAL] s3/public-buckets
  Resource:    arn:aws:s3:::my-bucket
  Region:      us-east-1
  Message:     S3 bucket 'my-bucket' has public access enabled
  Remediation: Enable S3 Block Public Access settings...
  Discovered:  2026-02-27T15:20:00Z
```

### JSON Output

Structured output for automation:

```bash
./infraguard infra -o json
```

```json
{
  "findings": [
    {
      "check_name": "s3/public-buckets",
      "severity": "CRITICAL",
      "resource_id": "arn:aws:s3:::my-bucket",
      "region": "us-east-1",
      "message": "S3 bucket 'my-bucket' has public access enabled",
      "remediation": "Enable S3 Block Public Access settings...",
      "discovered_at": "2026-02-27T15:20:00Z"
    }
  ],
  "summary": {
    "CRITICAL": 2,
    "HIGH": 8,
    "MEDIUM": 12,
    "LOW": 3
  }
}
```

## 🤖 CI/CD Integration

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

      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.24'

      - name: Build Infraguard
        run: go build -o infraguard ./cmd/infraguard

      - name: Run Security Audit
        run: ./infraguard infra -o json > audit.json

      - name: Check for Critical Findings
        run: |
          CRITICAL=$(jq '.summary.CRITICAL' audit.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "❌ Found $CRITICAL CRITICAL security issues!"
            jq '.findings[] | select(.severity == "CRITICAL")' audit.json
            exit 1
          fi
          echo "✅ No critical security issues found"

      - name: Upload Audit Results
        uses: actions/upload-artifact@v3
        with:
          name: security-audit
          path: audit.json
```

### GitLab CI

```yaml
security-audit:
  stage: security
  image: golang:1.24
  before_script:
    - go build -o infraguard ./cmd/infraguard
  script:
    - ./infraguard infra -o json | tee audit.json
    - |
      CRITICAL=$(jq '.summary.CRITICAL' audit.json)
      if [ "$CRITICAL" -gt 0 ]; then
        echo "❌ Found $CRITICAL CRITICAL security issues!"
        exit 1
      fi
  artifacts:
    reports:
      junit: audit.json
    expire_in: 30 days
  only:
    - schedules
```

## ⚡ Performance

- **Speed**: 15-30 seconds for most environments
- **Concurrency**: 50 checks run in parallel via goroutines
- **Multi-region**: 3 regions = 150 concurrent checks
- **Rate Limiting**: Automatic retry with exponential backoff (5 attempts, 20s max)
- **Efficiency**: ~30-50 MB memory usage

**Benchmark (200 resources, 2 regions):**
```
Total Time: 23 seconds
Concurrent Checks: 100
Findings: 47 issues discovered
Rate Limit Retries: 3 (auto-recovered)
```

## 🛠️ Development

### Project Structure

```
infraguard/
├── cmd/infraguard/        # CLI entry point
├── internal/
│   ├── awsutil/           # AWS SDK configuration + retry logic
│   ├── checks/            # Security check implementations
│   │   ├── s3/            # S3 checks (6)
│   │   ├── iam/           # IAM checks (7)
│   │   ├── ec2/           # EC2 checks (7)
│   │   ├── rds/           # RDS checks (5)
│   │   ├── vpc/           # VPC checks (5)
│   │   ├── kms/           # KMS checks (3)
│   │   ├── elb/           # ELB checks (3)
│   │   ├── cloudfront/    # CloudFront checks (3)
│   │   ├── compute/       # Lambda/ECS checks (5)
│   │   ├── cost/          # Cost checks (3)
│   │   └── logging/       # Logging checks (3)
│   ├── cli/               # Cobra commands + banner
│   ├── colour/            # ANSI colour support
│   ├── engine/            # Concurrent check executor
│   └── reporter/          # Text/JSON formatters
├── go.mod
└── README.md
```

### Adding New Checks

1. **Create check file** in appropriate package:

```go
// internal/checks/s3/my_check.go
package s3

import (
    "context"
    "github.com/yourorg/infraguard/internal/engine"
)

type MyCheck struct{}

func (c *MyCheck) Name() string {
    return "s3/my-check"
}

func (c *MyCheck) Description() string {
    return "Brief description"
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

2. **Register in CLI** (`internal/cli/audit_infra.go`):

```go
eng.Register(&s3.MyCheck{})
```

3. **Build and test**:

```bash
go build ./...
./infraguard infra
```

### Running Tests

```bash
# All tests
go test ./...

# With coverage
go test -cover ./...

# Specific package
go test ./internal/checks/s3/...
```

## 🐛 Troubleshooting

### "NoCredentialProviders" Error

```
Error: failed to load AWS config: no AWS credentials found
```

**Fix**: Configure credentials:
```bash
# Option 1: Environment variables
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret

# Option 2: AWS CLI
aws configure

# Option 3: Named profile
./infraguard infra --profile myprofile
```

### "AccessDenied" Errors

```
✗ Failed: kms/no-key-rotation [us-east-1] - AccessDeniedException
```

**Fix**: Add missing IAM permission (see [IAM Permissions](#-iam-permissions)).

### Colours Not Showing

**Automatic**: Colours disable for pipes/redirects/JSON.

**Manual disable**:
```bash
NO_COLOR=1 ./infraguard infra
```

## 📚 Documentation

- [FINAL_EXPANSION_SUMMARY.md](FINAL_EXPANSION_SUMMARY.md) - Complete check inventory
- [GETTING_STARTED.md](GETTING_STARTED.md) - Step-by-step tutorial
- [WHATS_NEW.md](WHATS_NEW.md) - v2.0 changes
- [PERFORMANCE_AND_RATE_LIMITING.md](PERFORMANCE_AND_RATE_LIMITING.md) - Technical deep dive
- [COLOUR_SUPPORT.md](COLOUR_SUPPORT.md) - Colour feature documentation
- [PROGRESS_LOGGING.md](PROGRESS_LOGGING.md) - Real-time progress docs

## 🗺️ Roadmap

- [x] ~~50 comprehensive security checks~~ ✅ **Complete!**
- [x] ~~VPC security checks~~ ✅ **Complete!**
- [x] ~~RDS security checks~~ ✅ **Complete!**
- [x] ~~Lambda security checks~~ ✅ **Complete!**
- [x] ~~Real-time progress logging~~ ✅ **Complete!**
- [x] ~~Colour-coded output~~ ✅ **Complete!**
- [x] ~~AWS rate limit handling~~ ✅ **Complete!**
- [ ] Check filtering (`--skip-checks`, `--only-checks`)
- [ ] HTML report generation
- [ ] Remediation automation mode
- [ ] AWS Organizations multi-account support
- [ ] Custom check policies via YAML
- [ ] Slack/email alerting

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🔐 Security

If you discover a security vulnerability, please email **info@j3consult.co.uk** instead of using the issue tracker.

## 💬 Support

- **Issues**: [GitHub Issues](https://github.com/olajaido/infraguard/issues)
- **Discussions**: [GitHub Discussions](https://github.com/olajaido/infraguard/discussions)

---

**Built with ❤️ by the Infraguard Team**

*Securing AWS infrastructure, one check at a time.* 🛡️
