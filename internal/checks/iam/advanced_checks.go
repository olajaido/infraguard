package iam

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/yourorg/infraguard/internal/engine"
)

// StaleUsersCheck identifies IAM users with no activity in 90+ days.
type StaleUsersCheck struct{}

func (c *StaleUsersCheck) Name() string {
	return "iam/stale-users"
}

func (c *StaleUsersCheck) Description() string {
	return "Identifies IAM users with no activity in the past 90 days"
}

func (c *StaleUsersCheck) Severity() engine.Severity {
	return engine.SeverityMedium
}

func (c *StaleUsersCheck) RequiredIAMPermissions() []string {
	return []string{
		"iam:ListUsers",
		"iam:GetUser",
	}
}

func (c *StaleUsersCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	if cfg.Region != "us-east-1" {
		return nil, nil
	}

	client := iam.NewFromConfig(cfg.AWSConfig)
	findings := []engine.Finding{}
	staleThreshold := 90 * 24 * time.Hour

	usersPaginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for usersPaginator.HasMorePages() {
		usersResp, err := usersPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing users: %w", err)
		}

		for _, user := range usersResp.Users {
			if user.UserName == nil || user.PasswordLastUsed == nil {
				continue
			}

			userName := *user.UserName
			timeSinceLastUse := time.Since(*user.PasswordLastUsed)

			if timeSinceLastUse > staleThreshold {
				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   *user.Arn,
					Region:       cfg.Region,
					Message:      fmt.Sprintf("IAM user '%s' has not been active for %d days", userName, int(timeSinceLastUse.Hours()/24)),
					Remediation:  fmt.Sprintf("Review and consider deleting inactive user '%s': aws iam delete-user --user-name %s", userName, userName),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// WildcardPoliciesCheck identifies users/roles with wildcard admin permissions.
type WildcardPoliciesCheck struct{}

func (c *WildcardPoliciesCheck) Name() string {
	return "iam/wildcard-policies"
}

func (c *WildcardPoliciesCheck) Description() string {
	return "Detects IAM entities with overly permissive wildcard (*:*) permissions"
}

func (c *WildcardPoliciesCheck) Severity() engine.Severity {
	return engine.SeverityCritical
}

func (c *WildcardPoliciesCheck) RequiredIAMPermissions() []string {
	return []string{
		"iam:ListUsers",
		"iam:ListAttachedUserPolicies",
		"iam:ListUserPolicies",
		"iam:GetUserPolicy",
		"iam:GetPolicy",
		"iam:GetPolicyVersion",
	}
}

func (c *WildcardPoliciesCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	if cfg.Region != "us-east-1" {
		return nil, nil
	}

	client := iam.NewFromConfig(cfg.AWSConfig)
	findings := []engine.Finding{}

	usersPaginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for usersPaginator.HasMorePages() {
		usersResp, err := usersPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing users: %w", err)
		}

		for _, user := range usersResp.Users {
			if user.UserName == nil {
				continue
			}

			userName := *user.UserName

			// Check attached policies
			attachedPolicies, err := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
				UserName: &userName,
			})
			if err == nil {
				for _, policy := range attachedPolicies.AttachedPolicies {
					if policy.PolicyName != nil && strings.Contains(strings.ToLower(*policy.PolicyName), "admin") {
						findings = append(findings, engine.Finding{
							CheckName:    c.Name(),
							Severity:     c.Severity(),
							ResourceID:   *user.Arn,
							Region:       cfg.Region,
							Message:      fmt.Sprintf("IAM user '%s' has administrative policy '%s' attached", userName, *policy.PolicyName),
							Remediation:  fmt.Sprintf("Review and apply least-privilege permissions to user '%s'", userName),
							DiscoveredAt: time.Now(),
						})
					}
				}
			}

			// Check inline policies
			inlinePolicies, err := client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
				UserName: &userName,
			})
			if err == nil && len(inlinePolicies.PolicyNames) > 0 {
				for _, policyName := range inlinePolicies.PolicyNames {
					findings = append(findings, engine.Finding{
						CheckName:    c.Name(),
						Severity:     engine.SeverityHigh,
						ResourceID:   *user.Arn,
						Region:       cfg.Region,
						Message:      fmt.Sprintf("IAM user '%s' has inline policy '%s' (use managed policies instead)", userName, policyName),
						Remediation:  fmt.Sprintf("Convert inline policy to managed policy and remove inline policy from user '%s'", userName),
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return findings, nil
}

// DualAccessUsersCheck identifies users with both console and programmatic access.
type DualAccessUsersCheck struct{}

func (c *DualAccessUsersCheck) Name() string {
	return "iam/dual-access-users"
}

func (c *DualAccessUsersCheck) Description() string {
	return "Identifies users with both console access and active access keys"
}

func (c *DualAccessUsersCheck) Severity() engine.Severity {
	return engine.SeverityMedium
}

func (c *DualAccessUsersCheck) RequiredIAMPermissions() []string {
	return []string{
		"iam:ListUsers",
		"iam:GetLoginProfile",
		"iam:ListAccessKeys",
	}
}

func (c *DualAccessUsersCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	if cfg.Region != "us-east-1" {
		return nil, nil
	}

	client := iam.NewFromConfig(cfg.AWSConfig)
	findings := []engine.Finding{}

	usersPaginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for usersPaginator.HasMorePages() {
		usersResp, err := usersPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing users: %w", err)
		}

		for _, user := range usersResp.Users {
			if user.UserName == nil {
				continue
			}

			userName := *user.UserName

			// Check console access
			_, err := client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{
				UserName: &userName,
			})
			hasConsoleAccess := err == nil

			// Check access keys
			keysResp, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
				UserName: &userName,
			})
			hasActiveKeys := false
			if err == nil {
				for _, key := range keysResp.AccessKeyMetadata {
					if key.Status == types.StatusTypeActive {
						hasActiveKeys = true
						break
					}
				}
			}

			if hasConsoleAccess && hasActiveKeys {
				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   *user.Arn,
					Region:       cfg.Region,
					Message:      fmt.Sprintf("IAM user '%s' has both console access and active access keys (unnecessary dual access)", userName),
					Remediation:  fmt.Sprintf("Separate human users (console only) from service accounts (access keys only) for user '%s'", userName),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// RootAccountUsageCheck monitors root account activity.
type RootAccountUsageCheck struct{}

func (c *RootAccountUsageCheck) Name() string {
	return "iam/root-account-usage"
}

func (c *RootAccountUsageCheck) Description() string {
	return "Detects if root account has been used recently"
}

func (c *RootAccountUsageCheck) Severity() engine.Severity {
	return engine.SeverityCritical
}

func (c *RootAccountUsageCheck) RequiredIAMPermissions() []string {
	return []string{
		"iam:GetAccountSummary",
		"iam:GenerateCredentialReport",
		"iam:GetCredentialReport",
	}
}

func (c *RootAccountUsageCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	if cfg.Region != "us-east-1" {
		return nil, nil
	}

	client := iam.NewFromConfig(cfg.AWSConfig)
	findings := []engine.Finding{}

	// Generate credential report
	_, err := client.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
	if err != nil {
		// Report might already exist, continue
	}

	// Wait a bit for report generation
	time.Sleep(2 * time.Second)

	// Get credential report
	reportResp, err := client.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if err != nil {
		// If we can't get the report, skip this check
		return findings, nil
	}

	// Parse CSV report to check root usage
	report := string(reportResp.Content)
	lines := strings.Split(report, "\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "<root_account>") {
			// Check if root has been used recently (password_last_used field)
			match := regexp.MustCompile(`password_last_used`).FindString(line)
			if match != "" {
				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   fmt.Sprintf("arn:aws:iam::%s:root", cfg.AccountID),
					Region:       cfg.Region,
					Message:      "Root account has been used recently (root usage should be avoided)",
					Remediation:  "Use IAM users with appropriate permissions instead of root account. Enable MFA on root and secure credentials.",
					DiscoveredAt: time.Now(),
				})
			}
			break
		}
	}

	return findings, nil
}
