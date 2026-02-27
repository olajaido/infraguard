# Progress Logging

## Overview

Infraguard now shows real-time progress as it scans your AWS infrastructure. You'll see each check as it runs, making it clear that the tool is working even on large environments.

## What You'll See

### Startup
```
infraguard: running infra audit in regions [eu-west-1] (output: text)
infraguard: authenticated as account 345594566447
infraguard: starting scan with 50 checks across 1 region(s)...
```

### During Scan
```
  → Running check: s3/public-buckets [eu-west-1]
  ✓ Completed: s3/public-buckets [eu-west-1] - 2 findings
  → Running check: iam/root-mfa [eu-west-1]
  ✓ Completed: iam/root-mfa [eu-west-1] - 0 findings
  → Running check: ec2/open-security-groups [eu-west-1]
  ✓ Completed: ec2/open-security-groups [eu-west-1] - 5 findings
  → Running check: vpc/no-flow-logs [eu-west-1]
  ✓ Completed: vpc/no-flow-logs [eu-west-1] - 1 findings
  ...
```

### Failed Checks
If a check fails (e.g., due to missing permissions), you'll see:
```
  → Running check: kms/no-key-rotation [eu-west-1]
  ✗ Failed: kms/no-key-rotation [eu-west-1] - AccessDeniedException: User: arn:aws:iam::123456789012:user/scanner is not authorized to perform: kms:ListKeys
```

### Completion
```
✓ Scan complete: 50/50 checks finished, 28 findings, 0 errors

infraguard: found 28 total findings
```

## Why This Matters

### Before (No Logging)
```
$ ./infraguard infra -r eu-west-1
infraguard: running infra audit in regions [eu-west-1] (output: text)
infraguard: authenticated as account 345594566447
... (appears stuck for 30-60 seconds with no feedback)
```

**Problems:**
- ❌ Users don't know if the tool is working or frozen
- ❌ No visibility into what's being scanned
- ❌ Can't tell which checks are slow
- ❌ Difficult to debug permission issues

### After (With Logging)
```
$ ./infraguard infra -r eu-west-1
infraguard: running infra audit in regions [eu-west-1] (output: text)
infraguard: authenticated as account 345594566447
infraguard: starting scan with 50 checks across 1 region(s)...

  → Running check: s3/public-buckets [eu-west-1]
  ✓ Completed: s3/public-buckets [eu-west-1] - 2 findings
  → Running check: iam/root-mfa [eu-west-1]
  ✓ Completed: iam/root-mfa [eu-west-1] - 0 findings
  ...
```

**Benefits:**
- ✅ Real-time feedback shows tool is working
- ✅ Can see exactly which checks are running
- ✅ Identify slow checks that might need optimization
- ✅ Immediately see permission errors for specific checks
- ✅ Know how much progress has been made

## Multi-Region Scanning

When scanning multiple regions, you'll see checks run concurrently:

```
$ ./infraguard infra -r us-east-1,eu-west-1,ap-southeast-1

infraguard: starting scan with 50 checks across 3 region(s)...

  → Running check: s3/public-buckets [us-east-1]
  → Running check: s3/public-buckets [eu-west-1]
  → Running check: s3/public-buckets [ap-southeast-1]
  ✓ Completed: s3/public-buckets [eu-west-1] - 1 findings
  ✓ Completed: s3/public-buckets [us-east-1] - 3 findings
  → Running check: iam/root-mfa [us-east-1]
  ✓ Completed: s3/public-buckets [ap-southeast-1] - 0 findings
  ...

✓ Scan complete: 150/150 checks finished, 42 findings, 0 errors
```

**Note:** With 50 checks × 3 regions = 150 total check executions running concurrently!

## Performance Insights

The logging helps you understand scan performance:

### Fast Checks (< 1 second)
```
  → Running check: iam/root-mfa [eu-west-1]
  ✓ Completed: iam/root-mfa [eu-west-1] - 0 findings
```

### Slow Checks (3-10 seconds)
```
  → Running check: ec2/stopped-instances [eu-west-1]
  ... (takes a few seconds if you have many EC2 instances)
  ✓ Completed: ec2/stopped-instances [eu-west-1] - 2 findings
```

### Very Slow Checks (10+ seconds)
```
  → Running check: iam/stale-users [eu-west-1]
  ... (can take 15-30 seconds due to IAM credential report generation)
  ✓ Completed: iam/stale-users [eu-west-1] - 5 findings
```

**Tip:** If a specific check is consistently slow, you can skip it in future runs using `--skip-checks` (feature to be added).

## Troubleshooting with Logs

### Identifying Permission Issues

If you see failures like:
```
  ✗ Failed: vpc/no-flow-logs [eu-west-1] - AccessDeniedException: User is not authorized to perform: ec2:DescribeFlowLogs
```

**Solution:** Add the missing permission to your IAM policy:
```json
{
  "Action": ["ec2:DescribeFlowLogs"],
  "Resource": "*"
}
```

### Tracking Down Slow Scans

If a scan seems slow, watch the logs to see which checks take longest:
```
  ✓ Completed: s3/public-buckets [eu-west-1] - 2 findings      # Fast (1s)
  ✓ Completed: iam/stale-users [eu-west-1] - 5 findings        # Slow (25s)
  ✓ Completed: ec2/stopped-instances [eu-west-1] - 2 findings  # Medium (5s)
```

## Quiet Mode (Future Feature)

If you want to suppress progress logs and only see results:
```bash
./infraguard infra --quiet  # Coming soon
```

## CI/CD Integration

In CI/CD environments, progress logs go to stderr while results go to stdout:

```bash
# Progress logs → stderr (visible in CI logs)
# Results → stdout (can be captured)
./infraguard infra -o json > results.json 2>&1
```

This allows you to:
- See progress in CI logs
- Capture JSON results for further processing
- Debug permission issues in CI environments

## Summary

**Before:** Silent scan that appears frozen for 30-60 seconds
**After:** Real-time progress with check-by-check feedback

This makes infraguard much more user-friendly, especially when:
- Scanning large environments with many resources
- Debugging permission issues
- Running multi-region scans
- Integrating with CI/CD pipelines

**The tool is no longer a "black box" - you can see exactly what it's doing!** 🚀
