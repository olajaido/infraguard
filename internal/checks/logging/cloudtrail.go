// Package logging implements AWS logging and monitoring checks.
package logging

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/yourorg/infraguard/internal/engine"
)

// CloudTrailEnabledCheck verifies that CloudTrail is enabled in the region.
type CloudTrailEnabledCheck struct{}

func (c *CloudTrailEnabledCheck) Name() string {
	return "logging/cloudtrail-enabled"
}

func (c *CloudTrailEnabledCheck) Description() string {
	return "Verifies that CloudTrail is enabled and logging to S3"
}

func (c *CloudTrailEnabledCheck) Severity() engine.Severity {
	return engine.SeverityCritical
}

func (c *CloudTrailEnabledCheck) RequiredIAMPermissions() []string {
	return []string{
		"cloudtrail:DescribeTrails",
		"cloudtrail:GetTrailStatus",
	}
}

func (c *CloudTrailEnabledCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := cloudtrail.NewFromConfig(cfg.AWSConfig, func(o *cloudtrail.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	// Describe trails
	trailsResp, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("describing trails: %w", err)
	}

	if len(trailsResp.TrailList) == 0 {
		findings = append(findings, engine.Finding{
			CheckName:    c.Name(),
			Severity:     c.Severity(),
			ResourceID:   fmt.Sprintf("arn:aws:cloudtrail:%s:%s:trail/none", cfg.Region, cfg.AccountID),
			Region:       cfg.Region,
			Message:      fmt.Sprintf("No CloudTrail trails found in region %s", cfg.Region),
			Remediation:  "Create a CloudTrail trail: aws cloudtrail create-trail --name my-trail --s3-bucket-name my-bucket && aws cloudtrail start-logging --name my-trail",
			DiscoveredAt: time.Now(),
		})
		return findings, nil
	}

	// Check each trail's status
	for _, trail := range trailsResp.TrailList {
		if trail.TrailARN == nil || trail.Name == nil {
			continue
		}

		trailName := *trail.Name
		trailARN := *trail.TrailARN

		// Get trail status
		statusResp, err := client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: trail.Name,
		})
		if err != nil {
			continue
		}

		// Check if trail is logging
		if statusResp.IsLogging != nil && !*statusResp.IsLogging {
			findings = append(findings, engine.Finding{
				CheckName:    c.Name(),
				Severity:     c.Severity(),
				ResourceID:   trailARN,
				Region:       cfg.Region,
				Message:      fmt.Sprintf("CloudTrail trail '%s' exists but is not actively logging", trailName),
				Remediation:  fmt.Sprintf("Start logging: aws cloudtrail start-logging --name %s", trailName),
				DiscoveredAt: time.Now(),
			})
		}

		// Check if trail has multi-region enabled
		if trail.IsMultiRegionTrail != nil && !*trail.IsMultiRegionTrail {
			findings = append(findings, engine.Finding{
				CheckName:    c.Name(),
				Severity:     engine.SeverityHigh,
				ResourceID:   trailARN,
				Region:       cfg.Region,
				Message:      fmt.Sprintf("CloudTrail trail '%s' is not configured for multi-region logging", trailName),
				Remediation:  fmt.Sprintf("Enable multi-region: aws cloudtrail update-trail --name %s --is-multi-region-trail", trailName),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// ConfigRecorderCheck verifies that AWS Config is enabled and recording.
type ConfigRecorderCheck struct{}

func (c *ConfigRecorderCheck) Name() string {
	return "logging/config-recorder"
}

func (c *ConfigRecorderCheck) Description() string {
	return "Verifies that AWS Config recorder is enabled"
}

func (c *ConfigRecorderCheck) Severity() engine.Severity {
	return engine.SeverityHigh
}

func (c *ConfigRecorderCheck) RequiredIAMPermissions() []string {
	return []string{
		"config:DescribeConfigurationRecorders",
		"config:DescribeConfigurationRecorderStatus",
	}
}

func (c *ConfigRecorderCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := configservice.NewFromConfig(cfg.AWSConfig, func(o *configservice.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	// Describe configuration recorders
	recordersResp, err := client.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return nil, fmt.Errorf("describing config recorders: %w", err)
	}

	if len(recordersResp.ConfigurationRecorders) == 0 {
		findings = append(findings, engine.Finding{
			CheckName:    c.Name(),
			Severity:     c.Severity(),
			ResourceID:   fmt.Sprintf("arn:aws:config:%s:%s:config-recorder/none", cfg.Region, cfg.AccountID),
			Region:       cfg.Region,
			Message:      fmt.Sprintf("No AWS Config recorder found in region %s", cfg.Region),
			Remediation:  "Create a Config recorder: aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=<role-arn> && aws configservice start-configuration-recorder --configuration-recorder-name default",
			DiscoveredAt: time.Now(),
		})
		return findings, nil
	}

	// Check recorder status
	statusResp, err := client.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		return nil, fmt.Errorf("describing config recorder status: %w", err)
	}

	for _, status := range statusResp.ConfigurationRecordersStatus {
		if status.Name == nil {
			continue
		}

		recorderName := *status.Name

		if !status.Recording {
			findings = append(findings, engine.Finding{
				CheckName:    c.Name(),
				Severity:     c.Severity(),
				ResourceID:   fmt.Sprintf("arn:aws:config:%s:%s:config-recorder/%s", cfg.Region, cfg.AccountID, recorderName),
				Region:       cfg.Region,
				Message:      fmt.Sprintf("AWS Config recorder '%s' exists but is not recording", recorderName),
				Remediation:  fmt.Sprintf("Start recording: aws configservice start-configuration-recorder --configuration-recorder-name %s", recorderName),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// GuardDutyEnabledCheck verifies that GuardDuty is enabled.
type GuardDutyEnabledCheck struct{}

func (c *GuardDutyEnabledCheck) Name() string {
	return "logging/guardduty-enabled"
}

func (c *GuardDutyEnabledCheck) Description() string {
	return "Verifies that Amazon GuardDuty is enabled for threat detection"
}

func (c *GuardDutyEnabledCheck) Severity() engine.Severity {
	return engine.SeverityHigh
}

func (c *GuardDutyEnabledCheck) RequiredIAMPermissions() []string {
	return []string{
		"guardduty:ListDetectors",
		"guardduty:GetDetector",
	}
}

func (c *GuardDutyEnabledCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := guardduty.NewFromConfig(cfg.AWSConfig, func(o *guardduty.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	// List detectors
	detectorsResp, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing GuardDuty detectors: %w", err)
	}

	if len(detectorsResp.DetectorIds) == 0 {
		findings = append(findings, engine.Finding{
			CheckName:    c.Name(),
			Severity:     c.Severity(),
			ResourceID:   fmt.Sprintf("arn:aws:guardduty:%s:%s:detector/none", cfg.Region, cfg.AccountID),
			Region:       cfg.Region,
			Message:      fmt.Sprintf("GuardDuty is not enabled in region %s", cfg.Region),
			Remediation:  "Enable GuardDuty: aws guardduty create-detector --enable",
			DiscoveredAt: time.Now(),
		})
		return findings, nil
	}

	// Check each detector's status
	for _, detectorID := range detectorsResp.DetectorIds {
		detectorResp, err := client.GetDetector(ctx, &guardduty.GetDetectorInput{
			DetectorId: &detectorID,
		})
		if err != nil {
			continue
		}

		if detectorResp.Status != "ENABLED" {
			findings = append(findings, engine.Finding{
				CheckName:    c.Name(),
				Severity:     c.Severity(),
				ResourceID:   fmt.Sprintf("arn:aws:guardduty:%s:%s:detector/%s", cfg.Region, cfg.AccountID, detectorID),
				Region:       cfg.Region,
				Message:      fmt.Sprintf("GuardDuty detector '%s' exists but is not enabled (status: %s)", detectorID, detectorResp.Status),
				Remediation:  fmt.Sprintf("Enable detector: aws guardduty update-detector --detector-id %s --enable", detectorID),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}
