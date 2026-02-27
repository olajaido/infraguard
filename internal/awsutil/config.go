// Package awsutil provides AWS SDK configuration and credential helpers.
package awsutil

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// LoadConfig loads AWS configuration from the default credential chain.
// If profile is non-empty, it loads the named profile. Otherwise it uses
// environment variables, instance metadata, or the default profile.
//
// This configuration includes automatic retry with exponential backoff to handle
// AWS rate limiting and transient errors.
func LoadConfig(ctx context.Context, region, profile string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(region),
		// Add retry configuration with exponential backoff
		config.WithRetryer(func() aws.Retryer {
			return retry.NewStandard(func(so *retry.StandardOptions) {
				so.MaxAttempts = 5               // Retry up to 5 times
				so.MaxBackoff = 20 * time.Second // Max wait between retries
			})
		}),
	}

	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("loading AWS config: %w", err)
	}

	return cfg, nil
}

// GetAccountID resolves the AWS account ID for the authenticated principal
// using the STS GetCallerIdentity API.
func GetAccountID(ctx context.Context, cfg aws.Config) (string, error) {
	stsClient := sts.NewFromConfig(cfg)
	resp, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("getting caller identity: %w", err)
	}

	if resp.Account == nil {
		return "", fmt.Errorf("STS GetCallerIdentity returned nil account")
	}

	return *resp.Account, nil
}
