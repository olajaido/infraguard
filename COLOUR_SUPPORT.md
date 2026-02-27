# Colour Support & Visual Enhancements

## Overview

Infraguard now features a beautiful, colourful terminal interface with:
- **ASCII art banner** with version and scan context
- **Colour-coded severity levels** for easy identification
- **Automatic detection** of terminal capabilities
- **Clean JSON output** with colours disabled

---

## What You'll See

### 1. Welcome Banner

When you run infraguard, you'll see:

```
  _        __                                     _
 (_)_ __  / _|_ __ __ _  __ _ _   _  __ _ _ __ __| |
 | | '_ \| |_| '__/ _' |/ _' | | | |/ _' | '__/ _' |
 | | | | |  _| | | (_| | (_| | |_| | (_| | | | (_| |
 |_|_| |_|_| |_|  \__,_|\__, |\__,_|\__,_|_|  \__,_|
                        |___/
  AWS Infrastructure Auditing CLI
  Version: dev

  Account: 345594566447
  Regions: eu-west-1

  Starting scan with 50 checks across 1 region(s)...
```

**Note:** Banner appears in cyan, account/region info in bold.

---

### 2. Colour-Coded Results

Findings are colour-coded by severity:

```
[CRITICAL] 5 finding(s)  ← Bold Red
────────────────────────────────────────────────────────────
  Check:       [CRITICAL] s3/public-buckets
  Resource:    arn:aws:s3:::my-bucket
  Region:      eu-west-1
  Message:     S3 bucket 'my-bucket' has public access enabled
  Remediation: Enable S3 Block Public Access settings...
  Discovered:  2026-02-27T15:20:00Z

[HIGH] 8 finding(s)  ← Orange
────────────────────────────────────────────────────────────
  Check:       [HIGH] iam/users-missing-mfa
  Resource:    arn:aws:iam::123456789012:user/admin
  ...

[MEDIUM] 12 finding(s)  ← Yellow
────────────────────────────────────────────────────────────
  ...

[LOW] 3 finding(s)  ← Cyan
────────────────────────────────────────────────────────────
  ...
```

---

## Colour Scheme

| Severity | Colour | ANSI Code |
|----------|--------|-----------|
| **CRITICAL** | Bold Red | `\033[1;91m` |
| **HIGH** | Orange | `\033[38;5;208m` |
| **MEDIUM** | Yellow | `\033[33m` |
| **LOW** | Cyan | `\033[36m` |
| **INFO** | Blue | `\033[34m` |
| **Success** | Green | `\033[32m` |
| **Errors** | Red | `\033[31m` |
| **Separators** | White | `\033[37m` |
| **Labels** | Bold | `\033[1m` |

---

## Automatic Colour Detection

Colours are **automatically disabled** in these scenarios:

### 1. Non-TTY Output (Piped or Redirected)
```bash
./infraguard infra > output.txt  # ← Colours disabled
cat output.txt                    # ← Plain text
```

### 2. NO_COLOR Environment Variable
```bash
NO_COLOR=1 ./infraguard infra    # ← Colours disabled
```

### 3. JSON Output Mode
```bash
./infraguard infra -o json       # ← Colours disabled
# JSON is completely clean, no ANSI codes
```

### 4. CI/CD Environments
Most CI systems set `NO_COLOR` or use non-TTY pipes, so colours are automatically disabled.

---

## Examples

### Terminal Output (Colours Enabled)
```bash
$ ./infraguard infra -r eu-west-1

  _        __                                     _
 (_)_ __  / _|_ __ __ _  __ _ _   _  __ _ _ __ __| |
  ...

[CRITICAL] 5 finding(s)  ← Red background jumps out!
────────────────────────────────────────────────────────────
  Check:       [CRITICAL] ec2/open-security-groups
  ...
```

### JSON Output (Colours Disabled)
```bash
$ ./infraguard infra -r eu-west-1 -o json

{
  "findings": [
    {
      "check_name": "ec2/open-security-groups",
      "severity": "CRITICAL",
      ...
    }
  ],
  "summary": {
    "CRITICAL": 5,
    "HIGH": 8
  }
}
```

**Note:** No banner, no colours, clean JSON only.

### Piped Output (Colours Disabled)
```bash
$ ./infraguard infra -r eu-west-1 | grep CRITICAL

[CRITICAL] 5 finding(s)
  Check:       [CRITICAL] ec2/open-security-groups
```

**Note:** No ANSI escape codes in grep output.

---

## Banner Behaviour

The banner is **only shown** when:
- ✅ Stdout is a TTY (terminal)
- ✅ `NO_COLOR` is not set
- ✅ Output format is `text` (default)

The banner is **hidden** when:
- ❌ Output is piped (`./infraguard infra | less`)
- ❌ Output is redirected (`./infraguard infra > file.txt`)
- ❌ `NO_COLOR=1` is set
- ❌ Output format is JSON (`-o json`)

---

## Version Information

The banner shows the tool version:

```bash
# Default (during development)
Version: dev

# After building with ldflags
go build -ldflags "-X github.com/yourorg/infraguard/internal/cli.version=1.0.0" ./cmd/infraguard
# Shows: Version: 1.0.0
```

---

## Disabling Colours Manually

If you want to disable colours even in a terminal:

```bash
# Method 1: Environment variable
NO_COLOR=1 ./infraguard infra

# Method 2: Use JSON output
./infraguard infra -o json
```

---

## Why This Matters

### Before (No Colours)
```
[CRITICAL] 5 finding(s)
[HIGH] 8 finding(s)
[MEDIUM] 12 finding(s)
[LOW] 3 finding(s)

  Check:       s3/public-buckets
  Resource:    arn:aws:s3:::my-bucket
  ...
```

**Problems:**
- ❌ All text looks the same
- ❌ Hard to spot critical issues quickly
- ❌ Boring, difficult to read
- ❌ No visual hierarchy

### After (With Colours)
```
[CRITICAL] 5 finding(s)  ← JUMPS OUT in bold red!
────────────────────────────────────────────────────────────
  Check:       [CRITICAL] s3/public-buckets  ← Red badge
  Resource:    arn:aws:s3:::my-bucket
  ...

[HIGH] 8 finding(s)  ← Orange, still important
[MEDIUM] 12 finding(s)  ← Yellow, medium priority
[LOW] 3 finding(s)  ← Cyan, low priority
```

**Benefits:**
- ✅ **Critical issues instantly visible** (red = danger!)
- ✅ **Visual hierarchy** shows priority at a glance
- ✅ **Professional appearance** like modern security tools
- ✅ **Easier to scan** through many findings

---

## Technical Implementation

### Colour Package
```go
// internal/colour/colour.go
package colour

// Auto-detects terminal capabilities
func init() {
    if os.Getenv("NO_COLOR") != "" {
        enabled = false
    }
    if !isTTY(os.Stdout) {
        enabled = false
    }
}

// Usage
fmt.Println(colour.BoldRed("CRITICAL"))
fmt.Println(colour.Orange("HIGH"))
fmt.Println(colour.Yellow("MEDIUM"))
```

### Banner Package
```go
// internal/cli/banner.go
func PrintBanner(w io.Writer, accountID string, regions []string) {
    if !colour.IsEnabled() {
        return  // Skip banner in JSON mode
    }
    fmt.Fprint(w, colour.Cyan(banner))
    // ...
}
```

### Reporter Integration
```go
// internal/reporter/reporter.go
func (r *TextReporter) Report(w io.Writer, result *engine.RunResult) error {
    sevColour := map[engine.Severity]func(string) string{
        engine.SeverityCritical: colour.BoldRed,
        engine.SeverityHigh:     colour.Orange,
        // ...
    }

    colourFn := sevColour[sev]
    fmt.Fprintf(w, "%s %d finding(s)\n", colourFn(fmt.Sprintf("[%s]", sev)), len(findings))
}
```

---

## Compatibility

### Terminal Compatibility
- ✅ **Linux/macOS** - Full colour support
- ✅ **Windows 10+** - ANSI colours supported in modern terminals
- ✅ **iTerm2, Terminal.app** - Full support
- ✅ **VS Code terminal** - Full support
- ⚠️ **Windows CMD (old)** - Falls back to plain text

### CI/CD Compatibility
- ✅ **GitHub Actions** - Automatically disables colours
- ✅ **GitLab CI** - Automatically disables colours
- ✅ **Jenkins** - Automatically disables colours
- ✅ **CircleCI** - Automatically disables colours

**All CI systems work perfectly!** The tool detects non-TTY and disables colours automatically.

---

## Summary

### What Was Added
1. ✅ **ASCII art banner** with version and context
2. ✅ **Colour-coded severity levels** (red = critical, orange = high, etc.)
3. ✅ **Automatic TTY detection** (colours off for pipes/redirects)
4. ✅ **NO_COLOR support** (respects standard environment variable)
5. ✅ **Clean JSON output** (no ANSI codes in JSON mode)
6. ✅ **Bold field labels** for better readability
7. ✅ **Coloured separators** and error messages

### Benefits
- 🎨 **Professional appearance** like modern security tools
- 👁️ **Critical issues instantly visible** (red = danger!)
- 📊 **Visual hierarchy** shows priority at a glance
- 🚀 **Easier to scan** through many findings
- ✅ **Backward compatible** - works everywhere without issues

**Infraguard now looks as good as it works!** 🌈✨
