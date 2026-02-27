# Getting Started with Infraguard

This guide will walk you through setting up and running Infraguard to audit your AWS infrastructure.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [AWS Configuration](#aws-configuration)
- [Running Your First Audit](#running-your-first-audit)
- [Understanding the Output](#understanding-the-output)
- [Common Use Cases](#common-use-cases)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before you begin, ensure you have:

1. **Go installed** (version 1.24.3 or later)
   ```bash
   # Check your Go version
   go version
   ```

   If you don't have Go installed, download it from [go.dev](https://go.dev/dl/)

2. **AWS Account** with appropriate access
   - You'll need read-only access to AWS services
   - See [Required IAM Permissions](#required-iam-permissions) below

3. **AWS CLI configured** (optional but recommended)
   ```bash
   # Check if AWS CLI is installed
   aws --version
   ```

---

## Installation

### Option 1: Build from Source (Recommended)

1. **Clone or navigate to the infraguard directory**
   ```bash
   cd /Users/olajideadeluwoye/Desktop/CLI_Project/infraguard
   ```

2. **Download dependencies**
   ```bash
   go mod download
   ```

3. **Build the binary**
   ```bash
   go build -o infraguard ./cmd/infraguard
   ```

4. **Verify the installation**
   ```bash
   ./infraguard --help
   ```

   You should see the help output with available commands.

5. **Optional: Install globally**
   ```bash
   # On macOS/Linux
   sudo mv infraguard /usr/local/bin/

   # Verify global installation
   infraguard --help
   ```

### Option 2: Quick Build and Run

```bash
# Build and run in one step
go run ./cmd/infraguard --help
```

---

## AWS Configuration

Infraguard needs AWS credentials to scan your infrastructure. There are several ways to provide credentials:

### Method 1: AWS CLI Configuration (Easiest)

If you have AWS CLI installed and configured, Infraguard will automatically use those credentials.

```bash
# Configure AWS CLI (if not already done)
aws configure

# You'll be prompted for:
# - AWS Access Key ID
# - AWS Secret Access Key
# - Default region name (e.g., us-east-1)
# - Default output format (e.g., json)
```

### Method 2: Environment Variables

```bash
# Set AWS credentials as environment variables
export AWS_ACCESS_KEY_ID="your-access-key-id"
export AWS_SECRET_ACCESS_KEY="your-secret-access-key"
export AWS_DEFAULT_REGION="us-east-1"

# Optional: Use a session token for temporary credentials
export AWS_SESSION_TOKEN="your-session-token"
```

### Method 3: AWS Profiles

If you manage multiple AWS accounts, use named profiles:

```bash
# Configure a named profile
aws configure --profile production

# Use the profile with Infraguard
infraguard infra --profile production
```

### Method 4: IAM Instance Profile (for EC2)

If running on an EC2 instance, attach an IAM role with the required permissions. Infraguard will automatically use the instance profile credentials.

---

## Required IAM Permissions

Create an IAM user or role with the following policy:

### Minimal Read-Only Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetPublicAccessBlock",
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

### Using AWS Managed Policy (Alternative)

For simplicity, you can use the AWS-managed `SecurityAudit` policy, which includes all required permissions and more:

```bash
# Attach to a user
aws iam attach-user-policy \
  --user-name infraguard-user \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit

# Or attach to a role
aws iam attach-role-policy \
  --role-name infraguard-role \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

---

## Running Your First Audit

### Step 1: Verify AWS Access

Before running the audit, verify your AWS credentials are working:

```bash
# Test with AWS CLI (if installed)
aws sts get-caller-identity

# Or just run infraguard - it will show your account ID
./infraguard infra
```

### Step 2: Run a Basic Infrastructure Audit

```bash
# Audit with default settings (single region: eu-west-2)
./infraguard infra
```

**Expected output:**
```
infraguard: running infra audit in regions [eu-west-2] (output: text)
infraguard: authenticated as account 123456789012

[CRITICAL] 2 finding(s)
────────────────────────────────────────────────────────────
  Check:       s3/public-buckets
  Resource:    arn:aws:s3:::my-bucket
  Region:      eu-west-2
  Message:     S3 bucket 'my-bucket' has no public access block configuration
  Remediation: Enable S3 Block Public Access settings...
  Discovered:  2026-02-27T14:00:00Z

[HIGH] 3 finding(s)
────────────────────────────────────────────────────────────
...
```

### Step 3: Run a Configuration Audit

```bash
# Check AWS service configurations (CloudTrail, Config, GuardDuty)
./infraguard config
```

### Step 4: Scan Multiple Regions

```bash
# Scan across multiple AWS regions
./infraguard infra --region us-east-1,us-west-2,eu-west-1

# Or use short flag
./infraguard infra -r us-east-1,us-west-2
```

### Step 5: Export Results as JSON

```bash
# Output as JSON for automation/CI/CD
./infraguard infra --output json > audit-results.json

# Or use short flag
./infraguard infra -o json
```

---

## Understanding the Output

### Text Output (Human-Readable)

When you run Infraguard, findings are grouped by severity level:

```
[CRITICAL] 2 finding(s)
────────────────────────────────────────────────────────────
  Check:       s3/public-buckets
  Resource:    arn:aws:s3:::my-public-bucket
  Region:      us-east-1
  Message:     S3 bucket 'my-public-bucket' has no public access block
  Remediation: Enable S3 Block Public Access settings...
  Discovered:  2026-02-27T14:00:00Z
```

**Key Fields:**
- **Check**: The security check that found this issue
- **Resource**: The AWS resource affected (ARN or ID)
- **Region**: The AWS region where the resource is located
- **Message**: Description of the security issue
- **Remediation**: Step-by-step fix instructions
- **Discovered**: Timestamp when the issue was detected

### Severity Levels

| Level | Description | Action Required |
|-------|-------------|-----------------|
| **CRITICAL** | Immediately exploitable or compliance-breaking | Fix immediately |
| **HIGH** | Significant misconfiguration | Fix within 24-48 hours |
| **MEDIUM** | Moderate risk misconfiguration | Fix within 1 week |
| **LOW** | Best-practice deviation with limited risk | Fix when convenient |
| **INFO** | Informational observations | Review and document |

### JSON Output (Machine-Readable)

```json
{
  "findings": [
    {
      "check_name": "s3/public-buckets",
      "severity": "CRITICAL",
      "resource_id": "arn:aws:s3:::my-bucket",
      "region": "us-east-1",
      "message": "S3 bucket 'my-bucket' has no public access block",
      "remediation": "Enable S3 Block Public Access settings...",
      "discovered_at": "2026-02-27T14:00:00Z"
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

---

## Common Use Cases

### Use Case 1: Daily Security Scan

Set up a daily scan to catch new issues:

```bash
#!/bin/bash
# save as: daily-audit.sh

DATE=$(date +%Y-%m-%d)
REGIONS="us-east-1,us-west-2,eu-west-1"

echo "Running daily AWS security audit for $DATE"
infraguard infra -r $REGIONS -o json > "audit-$DATE.json"

# Check for critical findings
CRITICAL=$(jq '.summary.CRITICAL // 0' "audit-$DATE.json")
if [ "$CRITICAL" -gt 0 ]; then
    echo "❌ ALERT: $CRITICAL critical findings detected!"
    # Send alert (email, Slack, PagerDuty, etc.)
fi
```

```bash
# Make it executable
chmod +x daily-audit.sh

# Run it
./daily-audit.sh
```

### Use Case 2: Pre-Deployment Check

Run before deploying new infrastructure:

```bash
# Check current state
infraguard infra -r us-east-1 -o json > before.json

# Deploy your infrastructure
terraform apply

# Check for new issues
infraguard infra -r us-east-1 -o json > after.json

# Compare results
jq -s '.[0].summary.CRITICAL - .[1].summary.CRITICAL' after.json before.json
```

### Use Case 3: Compliance Audit Report

Generate a compliance report:

```bash
#!/bin/bash
# Generate compliance report

REPORT_DATE=$(date +"%Y-%m-%d %H:%M:%S")
OUTPUT_FILE="compliance-report-$(date +%Y%m%d).txt"

{
  echo "=========================================="
  echo "AWS Security Compliance Report"
  echo "Generated: $REPORT_DATE"
  echo "=========================================="
  echo ""

  infraguard infra -r us-east-1,us-west-2,eu-west-1

  echo ""
  echo "=========================================="
  echo "Configuration Audit"
  echo "=========================================="
  echo ""

  infraguard config -r us-east-1

} | tee "$OUTPUT_FILE"

echo "Report saved to: $OUTPUT_FILE"
```

### Use Case 4: Multi-Account Scanning

Scan multiple AWS accounts using profiles:

```bash
#!/bin/bash
# Multi-account scan

ACCOUNTS=("production" "staging" "development")
REGIONS="us-east-1,us-west-2"

for account in "${ACCOUNTS[@]}"; do
    echo "Scanning account: $account"
    infraguard infra --profile "$account" -r "$REGIONS" -o json > "audit-$account.json"

    # Check for critical issues
    CRITICAL=$(jq '.summary.CRITICAL // 0' "audit-$account.json")
    echo "  → Critical findings: $CRITICAL"
done
```

### Use Case 5: Focus on Specific Services

Analyze the output to focus on specific services:

```bash
# Get only S3 findings
infraguard infra -o json | jq '.findings[] | select(.check_name | startswith("s3/"))'

# Get only CRITICAL findings
infraguard infra -o json | jq '.findings[] | select(.severity == "CRITICAL")'

# Get findings for a specific resource
infraguard infra -o json | jq '.findings[] | select(.resource_id | contains("my-bucket"))'
```

---

## Command Reference

### Global Flags

```bash
# Output format (text or json)
--output, -o <format>     # Default: text

# AWS regions to scan (comma-separated)
--region, -r <regions>    # Default: eu-west-2

# AWS profile to use
--profile <profile-name>  # Default: default profile
```

### Commands

#### `infraguard infra`

Audit infrastructure resources (S3, IAM, EC2, logging).

```bash
# Examples
infraguard infra
infraguard infra -r us-east-1
infraguard infra -r us-east-1,us-west-2 -o json
infraguard infra --profile production -r us-east-1
```

#### `infraguard config`

Validate AWS configuration settings (CloudTrail, Config, GuardDuty).

```bash
# Examples
infraguard config
infraguard config -r us-east-1
infraguard config -o json
```

---

## Troubleshooting

### Issue: "No AWS credentials found"

**Error:**
```
Error: failed to load AWS config: no AWS credentials found
```

**Solution:**
```bash
# Option 1: Configure AWS CLI
aws configure

# Option 2: Set environment variables
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"

# Option 3: Verify credentials file exists
cat ~/.aws/credentials
```

### Issue: "Access Denied" errors

**Error:**
```
Error: operation error S3: ListBuckets, https response error StatusCode: 403, AccessDenied
```

**Solution:**
Ensure your IAM user/role has the required permissions. Check the [Required IAM Permissions](#required-iam-permissions) section.

```bash
# Test your permissions
aws s3 ls
aws iam list-users
aws ec2 describe-instances --region us-east-1
```

### Issue: Slow execution

**Problem:** Scanning takes a long time.

**Solutions:**
```bash
# 1. Reduce number of regions
infraguard infra -r us-east-1  # Instead of multiple regions

# 2. Run region scans in parallel (separate terminals)
infraguard infra -r us-east-1 -o json > us-east-1.json &
infraguard infra -r us-west-2 -o json > us-west-2.json &
infraguard infra -r eu-west-1 -o json > eu-west-1.json &
wait
```

### Issue: "Invalid region" error

**Error:**
```
Error: no such host
```

**Solution:**
Make sure you're using valid AWS region codes:

```bash
# Valid regions
us-east-1, us-east-2, us-west-1, us-west-2
eu-west-1, eu-west-2, eu-west-3, eu-central-1
ap-south-1, ap-northeast-1, ap-southeast-1, ap-southeast-2

# List all available regions
aws ec2 describe-regions --query 'Regions[].RegionName' --output table
```

### Issue: Build failures

**Error:**
```
go: module not found
```

**Solution:**
```bash
# Download dependencies
go mod download

# Clean and rebuild
go clean -cache
go build -v ./cmd/infraguard
```

### Issue: Permission denied when running binary

**Error:**
```
bash: ./infraguard: Permission denied
```

**Solution:**
```bash
# Make the binary executable
chmod +x infraguard

# Then run it
./infraguard --help
```

---

## Next Steps

Now that you have Infraguard set up and running:

1. **Schedule Regular Scans**: Set up a cron job or CI/CD pipeline to run daily audits
2. **Fix Critical Issues**: Start with CRITICAL severity findings
3. **Integrate with Alerting**: Send results to Slack, email, or PagerDuty
4. **Automate Remediation**: Use the remediation commands provided in findings
5. **Track Progress**: Keep historical JSON outputs to track security improvements over time

## Additional Resources

- **README.md**: Comprehensive project documentation
- **Contributing**: See how to add custom checks
- **GitHub Issues**: Report bugs or request features

---

**Need Help?**

If you encounter issues not covered here:
- Check the main [README.md](README.md)
- Review AWS CloudTrail logs for permission errors
- Open an issue on GitHub with detailed logs

**Happy Auditing! 🔒**
