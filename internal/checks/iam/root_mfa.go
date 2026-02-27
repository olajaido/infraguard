// Package iam implements IAM security checks.
package iam

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/yourorg/infraguard/internal/engine"
)

// RootMFACheck verifies that the root account has MFA enabled.
type RootMFACheck struct{}

func (c *RootMFACheck) Name() string {
	return "iam/root-mfa"
}

func (c *RootMFACheck) Description() string {
	return "Verifies that the AWS root account has MFA enabled"
}

func (c *RootMFACheck) Severity() engine.Severity {
	return engine.SeverityCritical
}

func (c *RootMFACheck) RequiredIAMPermissions() []string {
	return []string{
		"iam:GetAccountSummary",
	}
}

func (c *RootMFACheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	// IAM is global, only run in one region
	if cfg.Region != "us-east-1" {
		return nil, nil
	}

	client := iam.NewFromConfig(cfg.AWSConfig)
	findings := []engine.Finding{}

	summary, err := client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, fmt.Errorf("getting account summary: %w", err)
	}

	// Check if root account has MFA enabled
	if mfaDevices, ok := summary.SummaryMap["AccountMFAEnabled"]; ok && mfaDevices == 0 {
		findings = append(findings, engine.Finding{
			CheckName:    c.Name(),
			Severity:     c.Severity(),
			ResourceID:   fmt.Sprintf("arn:aws:iam::%s:root", cfg.AccountID),
			Region:       cfg.Region,
			Message:      "AWS root account does not have MFA enabled",
			Remediation:  "Enable MFA for the root account: Sign in as root user, navigate to IAM > My Security Credentials, and activate MFA",
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}

// UsersMissingMFACheck identifies IAM users without MFA enabled.
type UsersMissingMFACheck struct{}

func (c *UsersMissingMFACheck) Name() string {
	return "iam/users-missing-mfa"
}

func (c *UsersMissingMFACheck) Description() string {
	return "Identifies IAM users with console access but no MFA enabled"
}

func (c *UsersMissingMFACheck) Severity() engine.Severity {
	return engine.SeverityHigh
}

func (c *UsersMissingMFACheck) RequiredIAMPermissions() []string {
	return []string{
		"iam:ListUsers",
		"iam:ListMFADevices",
		"iam:GetLoginProfile",
	}
}

func (c *UsersMissingMFACheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	// IAM is global, only run in one region
	if cfg.Region != "us-east-1" {
		return nil, nil
	}

	client := iam.NewFromConfig(cfg.AWSConfig)
	findings := []engine.Finding{}

	// List all users
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

			// Check if user has console access
			_, err := client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{
				UserName: &userName,
			})
			hasConsoleAccess := err == nil

			// Only check MFA for users with console access
			if !hasConsoleAccess {
				continue
			}

			// Check if user has MFA devices
			mfaResp, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{
				UserName: &userName,
			})
			if err != nil {
				continue
			}

			if len(mfaResp.MFADevices) == 0 {
				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   *user.Arn,
					Region:       cfg.Region,
					Message:      fmt.Sprintf("IAM user '%s' has console access but no MFA device enabled", userName),
					Remediation:  fmt.Sprintf("Enable MFA for user '%s': aws iam enable-mfa-device --user-name %s --serial-number <device-serial> --authentication-code1 <code1> --authentication-code2 <code2>", userName, userName),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// OldAccessKeysCheck identifies IAM access keys that haven't been rotated recently.
type OldAccessKeysCheck struct{}

func (c *OldAccessKeysCheck) Name() string {
	return "iam/old-access-keys"
}

func (c *OldAccessKeysCheck) Description() string {
	return "Identifies IAM access keys that are older than 90 days"
}

func (c *OldAccessKeysCheck) Severity() engine.Severity {
	return engine.SeverityMedium
}

func (c *OldAccessKeysCheck) RequiredIAMPermissions() []string {
	return []string{
		"iam:ListUsers",
		"iam:ListAccessKeys",
	}
}

func (c *OldAccessKeysCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	// IAM is global, only run in one region
	if cfg.Region != "us-east-1" {
		return nil, nil
	}

	client := iam.NewFromConfig(cfg.AWSConfig)
	findings := []engine.Finding{}

	rotationThreshold := 90 * 24 * time.Hour

	// List all users
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

			// List access keys for user
			keysResp, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
				UserName: &userName,
			})
			if err != nil {
				continue
			}

			for _, key := range keysResp.AccessKeyMetadata {
				if key.AccessKeyId == nil || key.CreateDate == nil {
					continue
				}

				keyAge := time.Since(*key.CreateDate)
				if keyAge > rotationThreshold {
					findings = append(findings, engine.Finding{
						CheckName:    c.Name(),
						Severity:     c.Severity(),
						ResourceID:   *user.Arn,
						Region:       cfg.Region,
						Message:      fmt.Sprintf("IAM user '%s' has access key '%s' that is %d days old (threshold: 90 days)", userName, *key.AccessKeyId, int(keyAge.Hours()/24)),
						Remediation:  fmt.Sprintf("Rotate the access key for user '%s': Create a new key, update applications, then delete the old key using: aws iam delete-access-key --user-name %s --access-key-id %s", userName, userName, *key.AccessKeyId),
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return findings, nil
}
