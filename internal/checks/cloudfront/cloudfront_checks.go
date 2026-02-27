package cloudfront

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/yourorg/infraguard/internal/engine"
)

// DeprecatedTLSCheck identifies CloudFront distributions using deprecated TLS versions.
type DeprecatedTLSCheck struct{}

func (c *DeprecatedTLSCheck) Name() string {
	return "cloudfront/deprecated-tls"
}

func (c *DeprecatedTLSCheck) Description() string {
	return "Detects CloudFront distributions using deprecated TLS versions (< TLSv1.2)"
}

func (c *DeprecatedTLSCheck) Severity() engine.Severity {
	return engine.SeverityHigh
}

func (c *DeprecatedTLSCheck) RequiredIAMPermissions() []string {
	return []string{
		"cloudfront:ListDistributions",
		"cloudfront:GetDistributionConfig",
	}
}

func (c *DeprecatedTLSCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := cloudfront.NewFromConfig(cfg.AWSConfig)
	findings := []engine.Finding{}

	// CloudFront is a global service, only run in us-east-1
	if cfg.Region != "us-east-1" {
		return findings, nil
	}

	// List distributions
	distPaginator := cloudfront.NewListDistributionsPaginator(client, &cloudfront.ListDistributionsInput{})
	for distPaginator.HasMorePages() {
		distResp, err := distPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing CloudFront distributions: %w", err)
		}

		if distResp.DistributionList == nil || distResp.DistributionList.Items == nil {
			continue
		}

		for _, dist := range distResp.DistributionList.Items {
			if dist.Id == nil || dist.DomainName == nil {
				continue
			}

			distID := *dist.Id
			domainName := *dist.DomainName

			// Check viewer certificate configuration
			if dist.ViewerCertificate != nil {
				minProtocol := string(dist.ViewerCertificate.MinimumProtocolVersion)

				// Check for deprecated protocols
				if minProtocol == "SSLv3" || minProtocol == "TLSv1" || minProtocol == "TLSv1_2016" ||
					minProtocol == "TLSv1.1_2016" {
					findings = append(findings, engine.Finding{
						CheckName:    c.Name(),
						Severity:     c.Severity(),
						ResourceID:   fmt.Sprintf("arn:aws:cloudfront::%s:distribution/%s", cfg.AccountID, distID),
						Region:       "global",
						Message:      fmt.Sprintf("CloudFront distribution '%s' (%s) uses deprecated TLS version '%s'", distID, domainName, minProtocol),
						Remediation:  fmt.Sprintf("Update minimum TLS version to TLSv1.2_2021 or higher for distribution '%s'", distID),
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return findings, nil
}

// NoWAFCheck identifies CloudFront distributions without AWS WAF protection.
type NoWAFCheck struct{}

func (c *NoWAFCheck) Name() string {
	return "cloudfront/no-waf"
}

func (c *NoWAFCheck) Description() string {
	return "Detects CloudFront distributions without AWS WAF WebACL attached"
}

func (c *NoWAFCheck) Severity() engine.Severity {
	return engine.SeverityMedium
}

func (c *NoWAFCheck) RequiredIAMPermissions() []string {
	return []string{
		"cloudfront:ListDistributions",
		"cloudfront:GetDistributionConfig",
	}
}

func (c *NoWAFCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := cloudfront.NewFromConfig(cfg.AWSConfig)
	findings := []engine.Finding{}

	// CloudFront is a global service, only run in us-east-1
	if cfg.Region != "us-east-1" {
		return findings, nil
	}

	distPaginator := cloudfront.NewListDistributionsPaginator(client, &cloudfront.ListDistributionsInput{})
	for distPaginator.HasMorePages() {
		distResp, err := distPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing CloudFront distributions: %w", err)
		}

		if distResp.DistributionList == nil || distResp.DistributionList.Items == nil {
			continue
		}

		for _, dist := range distResp.DistributionList.Items {
			if dist.Id == nil || dist.DomainName == nil {
				continue
			}

			distID := *dist.Id
			domainName := *dist.DomainName

			// Check if WAF WebACL is attached
			if dist.WebACLId == nil || *dist.WebACLId == "" {
				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   fmt.Sprintf("arn:aws:cloudfront::%s:distribution/%s", cfg.AccountID, distID),
					Region:       "global",
					Message:      fmt.Sprintf("CloudFront distribution '%s' (%s) does not have AWS WAF protection", distID, domainName),
					Remediation:  fmt.Sprintf("Attach a WAF WebACL to distribution '%s' for enhanced security", distID),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// NoLoggingCheck identifies CloudFront distributions without logging enabled.
type NoLoggingCheck struct{}

func (c *NoLoggingCheck) Name() string {
	return "cloudfront/no-logging"
}

func (c *NoLoggingCheck) Description() string {
	return "Detects CloudFront distributions without access logging enabled"
}

func (c *NoLoggingCheck) Severity() engine.Severity {
	return engine.SeverityMedium
}

func (c *NoLoggingCheck) RequiredIAMPermissions() []string {
	return []string{
		"cloudfront:ListDistributions",
		"cloudfront:GetDistribution",
	}
}

func (c *NoLoggingCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := cloudfront.NewFromConfig(cfg.AWSConfig)
	findings := []engine.Finding{}

	// CloudFront is a global service, only run in us-east-1
	if cfg.Region != "us-east-1" {
		return findings, nil
	}

	distPaginator := cloudfront.NewListDistributionsPaginator(client, &cloudfront.ListDistributionsInput{})
	for distPaginator.HasMorePages() {
		distResp, err := distPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing CloudFront distributions: %w", err)
		}

		if distResp.DistributionList == nil || distResp.DistributionList.Items == nil {
			continue
		}

		for _, dist := range distResp.DistributionList.Items {
			if dist.Id == nil || dist.DomainName == nil {
				continue
			}

			distID := *dist.Id
			domainName := *dist.DomainName

			// Get full distribution configuration to check logging
			distConfigResp, err := client.GetDistribution(ctx, &cloudfront.GetDistributionInput{
				Id: dist.Id,
			})
			if err != nil {
				continue
			}

			// Check if logging is enabled
			loggingEnabled := false
			if distConfigResp.Distribution != nil &&
				distConfigResp.Distribution.DistributionConfig != nil &&
				distConfigResp.Distribution.DistributionConfig.Logging != nil &&
				distConfigResp.Distribution.DistributionConfig.Logging.Enabled != nil &&
				*distConfigResp.Distribution.DistributionConfig.Logging.Enabled {
				loggingEnabled = true
			}

			if !loggingEnabled {
				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   fmt.Sprintf("arn:aws:cloudfront::%s:distribution/%s", cfg.AccountID, distID),
					Region:       "global",
					Message:      fmt.Sprintf("CloudFront distribution '%s' (%s) does not have access logging enabled", distID, domainName),
					Remediation:  fmt.Sprintf("Enable access logging for distribution '%s' to track access patterns", distID),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}
