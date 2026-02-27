package kms

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/yourorg/infraguard/internal/engine"
)

// KMSKeyRotationCheck identifies KMS keys without automatic rotation enabled.
type KMSKeyRotationCheck struct{}

func (c *KMSKeyRotationCheck) Name() string {
	return "kms/no-key-rotation"
}

func (c *KMSKeyRotationCheck) Description() string {
	return "Detects KMS customer managed keys without automatic rotation enabled"
}

func (c *KMSKeyRotationCheck) Severity() engine.Severity {
	return engine.SeverityMedium
}

func (c *KMSKeyRotationCheck) RequiredIAMPermissions() []string {
	return []string{
		"kms:ListKeys",
		"kms:DescribeKey",
		"kms:GetKeyRotationStatus",
	}
}

func (c *KMSKeyRotationCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := kms.NewFromConfig(cfg.AWSConfig, func(o *kms.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	// List all KMS keys
	keysPaginator := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})
	for keysPaginator.HasMorePages() {
		keysResp, err := keysPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing KMS keys: %w", err)
		}

		for _, key := range keysResp.Keys {
			if key.KeyId == nil {
				continue
			}

			keyID := *key.KeyId

			// Describe key to check if it's customer managed
			descResp, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{
				KeyId: key.KeyId,
			})
			if err != nil {
				continue
			}

			// Skip AWS managed keys
			if descResp.KeyMetadata == nil || descResp.KeyMetadata.KeyManager == "AWS" {
				continue
			}

			// Skip keys that are pending deletion or disabled
			if descResp.KeyMetadata.KeyState != "Enabled" {
				continue
			}

			// Check rotation status
			rotationResp, err := client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{
				KeyId: key.KeyId,
			})
			if err != nil {
				continue
			}

			if !rotationResp.KeyRotationEnabled {
				keyArn := keyID
				if key.KeyArn != nil {
					keyArn = *key.KeyArn
				}

				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   keyArn,
					Region:       cfg.Region,
					Message:      fmt.Sprintf("KMS key '%s' does not have automatic rotation enabled", keyID),
					Remediation:  fmt.Sprintf("Enable key rotation: aws kms enable-key-rotation --key-id %s", keyID),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// KMSKeyPolicyCheck identifies KMS keys with overly permissive policies.
type KMSKeyPolicyCheck struct{}

func (c *KMSKeyPolicyCheck) Name() string {
	return "kms/overly-permissive-policy"
}

func (c *KMSKeyPolicyCheck) Description() string {
	return "Detects KMS keys with policies allowing * principal or overly broad permissions"
}

func (c *KMSKeyPolicyCheck) Severity() engine.Severity {
	return engine.SeverityCritical
}

func (c *KMSKeyPolicyCheck) RequiredIAMPermissions() []string {
	return []string{
		"kms:ListKeys",
		"kms:DescribeKey",
		"kms:GetKeyPolicy",
	}
}

func (c *KMSKeyPolicyCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := kms.NewFromConfig(cfg.AWSConfig, func(o *kms.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	keysPaginator := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})
	for keysPaginator.HasMorePages() {
		keysResp, err := keysPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing KMS keys: %w", err)
		}

		for _, key := range keysResp.Keys {
			if key.KeyId == nil {
				continue
			}

			keyID := *key.KeyId

			// Describe key to check if it's customer managed
			descResp, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{
				KeyId: key.KeyId,
			})
			if err != nil {
				continue
			}

			// Skip AWS managed keys
			if descResp.KeyMetadata == nil || descResp.KeyMetadata.KeyManager == "AWS" {
				continue
			}

			// Get key policy
			policyResp, err := client.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
				KeyId:      key.KeyId,
				PolicyName: strPtr("default"),
			})
			if err != nil {
				continue
			}

			if policyResp.Policy == nil {
				continue
			}

			// Parse policy JSON
			var policy map[string]interface{}
			if err := json.Unmarshal([]byte(*policyResp.Policy), &policy); err != nil {
				continue
			}

			// Check for overly permissive policies
			if statements, ok := policy["Statement"].([]interface{}); ok {
				for _, stmt := range statements {
					if statement, ok := stmt.(map[string]interface{}); ok {
						// Check if Effect is Allow
						if effect, ok := statement["Effect"].(string); ok && effect == "Allow" {
							// Check if Principal is "*" or {"AWS": "*"}
							principal := statement["Principal"]
							isPrincipalPublic := false

							if principalStr, ok := principal.(string); ok && principalStr == "*" {
								isPrincipalPublic = true
							} else if principalMap, ok := principal.(map[string]interface{}); ok {
								if aws, ok := principalMap["AWS"].(string); ok && aws == "*" {
									isPrincipalPublic = true
								}
							}

							if isPrincipalPublic {
								keyArn := keyID
								if key.KeyArn != nil {
									keyArn = *key.KeyArn
								}

								findings = append(findings, engine.Finding{
									CheckName:    c.Name(),
									Severity:     c.Severity(),
									ResourceID:   keyArn,
									Region:       cfg.Region,
									Message:      fmt.Sprintf("KMS key '%s' has policy allowing * principal (potential public access)", keyID),
									Remediation:  fmt.Sprintf("Review and restrict KMS key policy for %s to specific principals", keyID),
									DiscoveredAt: time.Now(),
								})
								break
							}
						}
					}
				}
			}
		}
	}

	return findings, nil
}

// SecretsManagerRotationCheck identifies secrets without automatic rotation.
type SecretsManagerRotationCheck struct{}

func (c *SecretsManagerRotationCheck) Name() string {
	return "kms/secrets-no-rotation"
}

func (c *SecretsManagerRotationCheck) Description() string {
	return "Detects Secrets Manager secrets without automatic rotation enabled"
}

func (c *SecretsManagerRotationCheck) Severity() engine.Severity {
	return engine.SeverityMedium
}

func (c *SecretsManagerRotationCheck) RequiredIAMPermissions() []string {
	return []string{
		"secretsmanager:ListSecrets",
		"secretsmanager:DescribeSecret",
	}
}

func (c *SecretsManagerRotationCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := secretsmanager.NewFromConfig(cfg.AWSConfig, func(o *secretsmanager.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	secretsPaginator := secretsmanager.NewListSecretsPaginator(client, &secretsmanager.ListSecretsInput{})
	for secretsPaginator.HasMorePages() {
		secretsResp, err := secretsPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing secrets: %w", err)
		}

		for _, secret := range secretsResp.SecretList {
			if secret.ARN == nil || secret.Name == nil {
				continue
			}

			secretARN := *secret.ARN
			secretName := *secret.Name

			// Check if rotation is enabled
			if secret.RotationEnabled == nil || !*secret.RotationEnabled {
				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   secretARN,
					Region:       cfg.Region,
					Message:      fmt.Sprintf("Secrets Manager secret '%s' does not have automatic rotation enabled", secretName),
					Remediation:  fmt.Sprintf("Enable automatic rotation: aws secretsmanager rotate-secret --secret-id %s --rotation-lambda-arn <lambda-arn> --rotation-rules AutomaticallyAfterDays=30", secretName),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

func strPtr(s string) *string {
	return &s
}
