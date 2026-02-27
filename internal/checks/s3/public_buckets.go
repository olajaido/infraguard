// Package s3 implements S3 security checks.
package s3

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/yourorg/infraguard/internal/engine"
)

// PublicBucketsCheck identifies S3 buckets with public access enabled.
type PublicBucketsCheck struct{}

func (c *PublicBucketsCheck) Name() string {
	return "s3/public-buckets"
}

func (c *PublicBucketsCheck) Description() string {
	return "Detects S3 buckets with public access settings enabled"
}

func (c *PublicBucketsCheck) Severity() engine.Severity {
	return engine.SeverityCritical
}

func (c *PublicBucketsCheck) RequiredIAMPermissions() []string {
	return []string{
		"s3:ListAllMyBuckets",
		"s3:GetBucketPublicAccessBlock",
		"s3:GetBucketPolicyStatus",
		"s3:GetBucketLocation",
	}
}

func (c *PublicBucketsCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := s3.NewFromConfig(cfg.AWSConfig)
	findings := []engine.Finding{}

	// List all buckets (S3 is global, but we run this check per region)
	// We filter by region after listing
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
			// Bucket might not be accessible, skip
			continue
		}

		// Normalize location (empty string means us-east-1)
		bucketRegion := string(locationResp.LocationConstraint)
		if bucketRegion == "" {
			bucketRegion = "us-east-1"
		}

		// Skip if bucket is not in target region
		if bucketRegion != cfg.Region {
			continue
		}

		// Check public access block configuration
		pabResp, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: bucket.Name,
		})

		// If there's no public access block config, bucket could be public
		if err != nil || pabResp.PublicAccessBlockConfiguration == nil {
			findings = append(findings, engine.Finding{
				CheckName:    c.Name(),
				Severity:     c.Severity(),
				ResourceID:   fmt.Sprintf("arn:aws:s3:::%s", bucketName),
				Region:       cfg.Region,
				Message:      fmt.Sprintf("S3 bucket '%s' has no public access block configuration", bucketName),
				Remediation:  "Enable S3 Block Public Access settings for this bucket via the AWS Console or CLI: aws s3api put-public-access-block --bucket " + bucketName + " --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
				DiscoveredAt: time.Now(),
			})
			continue
		}

		// Check if any public access is allowed
		pabConfig := pabResp.PublicAccessBlockConfiguration
		blockPublicAcls := pabConfig.BlockPublicAcls != nil && *pabConfig.BlockPublicAcls
		blockPublicPolicy := pabConfig.BlockPublicPolicy != nil && *pabConfig.BlockPublicPolicy
		ignorePublicAcls := pabConfig.IgnorePublicAcls != nil && *pabConfig.IgnorePublicAcls
		restrictPublicBuckets := pabConfig.RestrictPublicBuckets != nil && *pabConfig.RestrictPublicBuckets

		if !blockPublicAcls || !blockPublicPolicy || !ignorePublicAcls || !restrictPublicBuckets {
			message := fmt.Sprintf("S3 bucket '%s' has incomplete public access block settings (BlockPublicAcls=%t, BlockPublicPolicy=%t, IgnorePublicAcls=%t, RestrictPublicBuckets=%t)",
				bucketName,
				blockPublicAcls,
				blockPublicPolicy,
				ignorePublicAcls,
				restrictPublicBuckets)

			findings = append(findings, engine.Finding{
				CheckName:    c.Name(),
				Severity:     c.Severity(),
				ResourceID:   fmt.Sprintf("arn:aws:s3:::%s", bucketName),
				Region:       cfg.Region,
				Message:      message,
				Remediation:  "Enable all S3 Block Public Access settings: aws s3api put-public-access-block --bucket " + bucketName + " --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
				DiscoveredAt: time.Now(),
			})
			continue
		}

		// Additionally check if bucket policy is public
		policyStatusResp, err := client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{
			Bucket: bucket.Name,
		})
		if err == nil && policyStatusResp.PolicyStatus != nil && policyStatusResp.PolicyStatus.IsPublic != nil && *policyStatusResp.PolicyStatus.IsPublic {
			findings = append(findings, engine.Finding{
				CheckName:    c.Name(),
				Severity:     engine.SeverityHigh,
				ResourceID:   fmt.Sprintf("arn:aws:s3:::%s", bucketName),
				Region:       cfg.Region,
				Message:      fmt.Sprintf("S3 bucket '%s' has a public bucket policy", bucketName),
				Remediation:  "Review and restrict the bucket policy to prevent public access",
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// UnencryptedBucketsCheck identifies S3 buckets without default encryption.
type UnencryptedBucketsCheck struct{}

func (c *UnencryptedBucketsCheck) Name() string {
	return "s3/unencrypted-buckets"
}

func (c *UnencryptedBucketsCheck) Description() string {
	return "Detects S3 buckets without default encryption enabled"
}

func (c *UnencryptedBucketsCheck) Severity() engine.Severity {
	return engine.SeverityHigh
}

func (c *UnencryptedBucketsCheck) RequiredIAMPermissions() []string {
	return []string{
		"s3:ListAllMyBuckets",
		"s3:GetEncryptionConfiguration",
		"s3:GetBucketLocation",
	}
}

func (c *UnencryptedBucketsCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
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

		// Check encryption configuration
		_, err = client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: bucket.Name,
		})

		// If error is returned, encryption is not configured
		if err != nil {
			findings = append(findings, engine.Finding{
				CheckName:    c.Name(),
				Severity:     c.Severity(),
				ResourceID:   fmt.Sprintf("arn:aws:s3:::%s", bucketName),
				Region:       cfg.Region,
				Message:      fmt.Sprintf("S3 bucket '%s' does not have default encryption enabled", bucketName),
				Remediation:  "Enable default encryption: aws s3api put-bucket-encryption --bucket " + bucketName + " --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'",
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}
