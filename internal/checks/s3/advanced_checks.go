package s3

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/yourorg/infraguard/internal/engine"
)

// BucketVersioningCheck identifies buckets without versioning enabled.
type BucketVersioningCheck struct{}

func (c *BucketVersioningCheck) Name() string {
	return "s3/no-versioning"
}

func (c *BucketVersioningCheck) Description() string {
	return "Detects S3 buckets without versioning enabled"
}

func (c *BucketVersioningCheck) Severity() engine.Severity {
	return engine.SeverityMedium
}

func (c *BucketVersioningCheck) RequiredIAMPermissions() []string {
	return []string{
		"s3:ListAllMyBuckets",
		"s3:GetBucketVersioning",
		"s3:GetBucketLocation",
	}
}

func (c *BucketVersioningCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := s3.NewFromConfig(cfg.AWSConfig)
	findings := []engine.Finding{}

	listResp, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing buckets: %w", err)
	}

	for _, bucket := range listResp.Buckets {
		if bucket.Name == nil {
			continue
		}

		bucketName := *bucket.Name

		// Get bucket region
		locationResp, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			continue
		}

		bucketRegion := string(locationResp.LocationConstraint)
		if bucketRegion == "" {
			bucketRegion = "us-east-1"
		}

		if bucketRegion != cfg.Region {
			continue
		}

		// Check versioning status
		versioningResp, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			continue
		}

		// Versioning is not enabled if Status is empty or Suspended
		if versioningResp.Status == "" || versioningResp.Status == "Suspended" {
			findings = append(findings, engine.Finding{
				CheckName:    c.Name(),
				Severity:     c.Severity(),
				ResourceID:   fmt.Sprintf("arn:aws:s3:::%s", bucketName),
				Region:       cfg.Region,
				Message:      fmt.Sprintf("S3 bucket '%s' does not have versioning enabled", bucketName),
				Remediation:  fmt.Sprintf("Enable versioning: aws s3api put-bucket-versioning --bucket %s --versioning-configuration Status=Enabled", bucketName),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// BucketLoggingCheck identifies buckets without access logging enabled.
type BucketLoggingCheck struct{}

func (c *BucketLoggingCheck) Name() string {
	return "s3/no-access-logging"
}

func (c *BucketLoggingCheck) Description() string {
	return "Detects S3 buckets without access logging enabled"
}

func (c *BucketLoggingCheck) Severity() engine.Severity {
	return engine.SeverityMedium
}

func (c *BucketLoggingCheck) RequiredIAMPermissions() []string {
	return []string{
		"s3:ListAllMyBuckets",
		"s3:GetBucketLogging",
		"s3:GetBucketLocation",
	}
}

func (c *BucketLoggingCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := s3.NewFromConfig(cfg.AWSConfig)
	findings := []engine.Finding{}

	listResp, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing buckets: %w", err)
	}

	for _, bucket := range listResp.Buckets {
		if bucket.Name == nil {
			continue
		}

		bucketName := *bucket.Name

		// Get bucket region
		locationResp, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			continue
		}

		bucketRegion := string(locationResp.LocationConstraint)
		if bucketRegion == "" {
			bucketRegion = "us-east-1"
		}

		if bucketRegion != cfg.Region {
			continue
		}

		// Check logging configuration
		loggingResp, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
			Bucket: bucket.Name,
		})
		if err != nil || loggingResp.LoggingEnabled == nil {
			findings = append(findings, engine.Finding{
				CheckName:    c.Name(),
				Severity:     c.Severity(),
				ResourceID:   fmt.Sprintf("arn:aws:s3:::%s", bucketName),
				Region:       cfg.Region,
				Message:      fmt.Sprintf("S3 bucket '%s' does not have access logging enabled", bucketName),
				Remediation:  fmt.Sprintf("Enable access logging: aws s3api put-bucket-logging --bucket %s --bucket-logging-status file://logging-config.json", bucketName),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// BucketLifecycleCheck identifies buckets without lifecycle policies.
type BucketLifecycleCheck struct{}

func (c *BucketLifecycleCheck) Name() string {
	return "s3/no-lifecycle-policy"
}

func (c *BucketLifecycleCheck) Description() string {
	return "Detects S3 buckets without lifecycle policies (cost optimization)"
}

func (c *BucketLifecycleCheck) Severity() engine.Severity {
	return engine.SeverityLow
}

func (c *BucketLifecycleCheck) RequiredIAMPermissions() []string {
	return []string{
		"s3:ListAllMyBuckets",
		"s3:GetLifecycleConfiguration",
		"s3:GetBucketLocation",
	}
}

func (c *BucketLifecycleCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := s3.NewFromConfig(cfg.AWSConfig)
	findings := []engine.Finding{}

	listResp, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing buckets: %w", err)
	}

	for _, bucket := range listResp.Buckets {
		if bucket.Name == nil {
			continue
		}

		bucketName := *bucket.Name

		// Get bucket region
		locationResp, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			continue
		}

		bucketRegion := string(locationResp.LocationConstraint)
		if bucketRegion == "" {
			bucketRegion = "us-east-1"
		}

		if bucketRegion != cfg.Region {
			continue
		}

		// Check lifecycle configuration
		_, err = client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			findings = append(findings, engine.Finding{
				CheckName:    c.Name(),
				Severity:     c.Severity(),
				ResourceID:   fmt.Sprintf("arn:aws:s3:::%s", bucketName),
				Region:       cfg.Region,
				Message:      fmt.Sprintf("S3 bucket '%s' does not have a lifecycle policy (consider for cost optimization)", bucketName),
				Remediation:  fmt.Sprintf("Create lifecycle policy: aws s3api put-bucket-lifecycle-configuration --bucket %s --lifecycle-configuration file://lifecycle-config.json", bucketName),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// PublicBucketPolicyCheck identifies buckets with public GetObject permissions in policy.
type PublicBucketPolicyCheck struct{}

func (c *PublicBucketPolicyCheck) Name() string {
	return "s3/public-getobject-policy"
}

func (c *PublicBucketPolicyCheck) Description() string {
	return "Detects S3 buckets allowing s3:GetObject to * in bucket policy"
}

func (c *PublicBucketPolicyCheck) Severity() engine.Severity {
	return engine.SeverityCritical
}

func (c *PublicBucketPolicyCheck) RequiredIAMPermissions() []string {
	return []string{
		"s3:ListAllMyBuckets",
		"s3:GetBucketPolicy",
		"s3:GetBucketLocation",
	}
}

func (c *PublicBucketPolicyCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := s3.NewFromConfig(cfg.AWSConfig)
	findings := []engine.Finding{}

	listResp, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing buckets: %w", err)
	}

	for _, bucket := range listResp.Buckets {
		if bucket.Name == nil {
			continue
		}

		bucketName := *bucket.Name

		// Get bucket region
		locationResp, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			continue
		}

		bucketRegion := string(locationResp.LocationConstraint)
		if bucketRegion == "" {
			bucketRegion = "us-east-1"
		}

		if bucketRegion != cfg.Region {
			continue
		}

		// Get bucket policy
		policyResp, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			// No policy or access denied
			continue
		}

		if policyResp.Policy == nil {
			continue
		}

		policyDoc := *policyResp.Policy

		// Parse policy JSON
		var policy map[string]interface{}
		if err := json.Unmarshal([]byte(policyDoc), &policy); err != nil {
			continue
		}

		// Check for public GetObject permissions
		if statements, ok := policy["Statement"].([]interface{}); ok {
			for _, stmt := range statements {
				if statement, ok := stmt.(map[string]interface{}); ok {
					// Check if Effect is Allow
					if effect, ok := statement["Effect"].(string); ok && effect == "Allow" {
						// Check if Principal is "*"
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
							// Check if Action includes GetObject
							action := statement["Action"]
							hasGetObject := false
							if actionStr, ok := action.(string); ok {
								hasGetObject = actionStr == "s3:GetObject" || actionStr == "s3:*" || actionStr == "*"
							} else if actionList, ok := action.([]interface{}); ok {
								for _, act := range actionList {
									if actStr, ok := act.(string); ok {
										if actStr == "s3:GetObject" || actStr == "s3:*" || actStr == "*" {
											hasGetObject = true
											break
										}
									}
								}
							}

							if hasGetObject {
								findings = append(findings, engine.Finding{
									CheckName:    c.Name(),
									Severity:     c.Severity(),
									ResourceID:   fmt.Sprintf("arn:aws:s3:::%s", bucketName),
									Region:       cfg.Region,
									Message:      fmt.Sprintf("S3 bucket '%s' has a policy allowing public s3:GetObject access", bucketName),
									Remediation:  fmt.Sprintf("Review and restrict bucket policy to remove public GetObject access for bucket '%s'", bucketName),
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
