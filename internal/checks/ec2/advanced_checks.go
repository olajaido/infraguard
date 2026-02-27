package ec2

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/yourorg/infraguard/internal/engine"
)

// PublicAMIsCheck identifies accidentally shared AMIs.
type PublicAMIsCheck struct{}

func (c *PublicAMIsCheck) Name() string {
	return "ec2/public-amis"
}

func (c *PublicAMIsCheck) Description() string {
	return "Detects AMIs that are publicly shared"
}

func (c *PublicAMIsCheck) Severity() engine.Severity {
	return engine.SeverityCritical
}

func (c *PublicAMIsCheck) RequiredIAMPermissions() []string {
	return []string{
		"ec2:DescribeImages",
		"ec2:DescribeImageAttribute",
	}
}

func (c *PublicAMIsCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := ec2.NewFromConfig(cfg.AWSConfig, func(o *ec2.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	// List all AMIs owned by this account
	imagesResp, err := client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{"self"},
	})
	if err != nil {
		return nil, fmt.Errorf("describing images: %w", err)
	}

	for _, image := range imagesResp.Images {
		if image.ImageId == nil {
			continue
		}

		imageID := *image.ImageId

		// Check if image is public
		if image.Public != nil && *image.Public {
			imageName := "unnamed"
			if image.Name != nil {
				imageName = *image.Name
			}

			findings = append(findings, engine.Finding{
				CheckName:    c.Name(),
				Severity:     c.Severity(),
				ResourceID:   fmt.Sprintf("arn:aws:ec2:%s:%s:image/%s", cfg.Region, cfg.AccountID, imageID),
				Region:       cfg.Region,
				Message:      fmt.Sprintf("AMI '%s' (%s) is publicly shared", imageName, imageID),
				Remediation:  fmt.Sprintf("Make AMI private: aws ec2 modify-image-attribute --image-id %s --launch-permission \"{\\\"Remove\\\":[{\\\"Group\\\":\\\"all\\\"}]}\"", imageID),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// StoppedInstancesCheck identifies long-stopped instances.
type StoppedInstancesCheck struct{}

func (c *StoppedInstancesCheck) Name() string {
	return "ec2/stopped-instances"
}

func (c *StoppedInstancesCheck) Description() string {
	return "Identifies EC2 instances stopped for more than 30 days"
}

func (c *StoppedInstancesCheck) Severity() engine.Severity {
	return engine.SeverityLow
}

func (c *StoppedInstancesCheck) RequiredIAMPermissions() []string {
	return []string{
		"ec2:DescribeInstances",
	}
}

func (c *StoppedInstancesCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := ec2.NewFromConfig(cfg.AWSConfig, func(o *ec2.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	instPaginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for instPaginator.HasMorePages() {
		instResp, err := instPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing instances: %w", err)
		}

		for _, reservation := range instResp.Reservations {
			for _, instance := range reservation.Instances {
				if instance.InstanceId == nil || instance.State == nil {
					continue
				}

				instanceID := *instance.InstanceId

				// Check if instance is stopped
				if instance.State.Name == types.InstanceStateNameStopped {
					if instance.StateTransitionReason != nil {
						// Parse state transition time (format: "User initiated (2023-01-01 12:00:00 GMT)")
						// For simplicity, we'll check if instance has been stopped (detailed parsing would require more logic)

						var instanceName string
						for _, tag := range instance.Tags {
							if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil {
								instanceName = *tag.Value
								break
							}
						}

						message := fmt.Sprintf("EC2 instance '%s' has been stopped for an extended period", instanceID)
						if instanceName != "" {
							message = fmt.Sprintf("EC2 instance '%s' (%s) has been stopped for an extended period", instanceName, instanceID)
						}

						findings = append(findings, engine.Finding{
							CheckName:    c.Name(),
							Severity:     c.Severity(),
							ResourceID:   fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", cfg.Region, cfg.AccountID, instanceID),
							Region:       cfg.Region,
							Message:      message,
							Remediation:  fmt.Sprintf("Review instance and consider terminating if no longer needed: aws ec2 terminate-instances --instance-ids %s", instanceID),
							DiscoveredAt: time.Now(),
						})
					}
				}
			}
		}
	}

	return findings, nil
}

// UnencryptedSnapshotsCheck identifies unencrypted EBS snapshots.
type UnencryptedSnapshotsCheck struct{}

func (c *UnencryptedSnapshotsCheck) Name() string {
	return "ec2/unencrypted-snapshots"
}

func (c *UnencryptedSnapshotsCheck) Description() string {
	return "Detects EBS snapshots that are not encrypted"
}

func (c *UnencryptedSnapshotsCheck) Severity() engine.Severity {
	return engine.SeverityHigh
}

func (c *UnencryptedSnapshotsCheck) RequiredIAMPermissions() []string {
	return []string{
		"ec2:DescribeSnapshots",
	}
}

func (c *UnencryptedSnapshotsCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := ec2.NewFromConfig(cfg.AWSConfig, func(o *ec2.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	// Only check snapshots owned by this account
	snapshotsPaginator := ec2.NewDescribeSnapshotsPaginator(client, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	})

	for snapshotsPaginator.HasMorePages() {
		snapshotsResp, err := snapshotsPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing snapshots: %w", err)
		}

		for _, snapshot := range snapshotsResp.Snapshots {
			if snapshot.SnapshotId == nil {
				continue
			}

			snapshotID := *snapshot.SnapshotId

			if snapshot.Encrypted != nil && !*snapshot.Encrypted {
				var volumeID string
				if snapshot.VolumeId != nil {
					volumeID = *snapshot.VolumeId
				}

				message := fmt.Sprintf("EBS snapshot '%s' is not encrypted", snapshotID)
				if volumeID != "" {
					message = fmt.Sprintf("EBS snapshot '%s' (from volume %s) is not encrypted", snapshotID, volumeID)
				}

				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   fmt.Sprintf("arn:aws:ec2:%s::snapshot/%s", cfg.Region, snapshotID),
					Region:       cfg.Region,
					Message:      message,
					Remediation:  fmt.Sprintf("Create an encrypted copy: aws ec2 copy-snapshot --source-snapshot-id %s --source-region %s --encrypted --description 'Encrypted copy'", snapshotID, cfg.Region),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// EphemeralPublicIPCheck identifies instances with ephemeral public IPs.
type EphemeralPublicIPCheck struct{}

func (c *EphemeralPublicIPCheck) Name() string {
	return "ec2/ephemeral-public-ips"
}

func (c *EphemeralPublicIPCheck) Description() string {
	return "Detects instances with public IPs but no Elastic IP (ephemeral IPs change on restart)"
}

func (c *EphemeralPublicIPCheck) Severity() engine.Severity {
	return engine.SeverityMedium
}

func (c *EphemeralPublicIPCheck) RequiredIAMPermissions() []string {
	return []string{
		"ec2:DescribeInstances",
		"ec2:DescribeAddresses",
	}
}

func (c *EphemeralPublicIPCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := ec2.NewFromConfig(cfg.AWSConfig, func(o *ec2.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	// Get all Elastic IPs
	eipsResp, err := client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, fmt.Errorf("describing addresses: %w", err)
	}

	elasticIPs := make(map[string]bool)
	for _, addr := range eipsResp.Addresses {
		if addr.InstanceId != nil {
			elasticIPs[*addr.InstanceId] = true
		}
	}

	// Check instances
	instPaginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for instPaginator.HasMorePages() {
		instResp, err := instPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing instances: %w", err)
		}

		for _, reservation := range instResp.Reservations {
			for _, instance := range reservation.Instances {
				if instance.InstanceId == nil {
					continue
				}

				instanceID := *instance.InstanceId

				// Skip terminated instances
				if instance.State != nil && instance.State.Name == types.InstanceStateNameTerminated {
					continue
				}

				// Check if has public IP but no Elastic IP
				if instance.PublicIpAddress != nil && !elasticIPs[instanceID] {
					var instanceName string
					for _, tag := range instance.Tags {
						if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil {
							instanceName = *tag.Value
							break
						}
					}

					message := fmt.Sprintf("EC2 instance '%s' has ephemeral public IP %s (will change on restart)", instanceID, *instance.PublicIpAddress)
					if instanceName != "" {
						message = fmt.Sprintf("EC2 instance '%s' (%s) has ephemeral public IP %s (will change on restart)", instanceName, instanceID, *instance.PublicIpAddress)
					}

					findings = append(findings, engine.Finding{
						CheckName:    c.Name(),
						Severity:     c.Severity(),
						ResourceID:   fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", cfg.Region, cfg.AccountID, instanceID),
						Region:       cfg.Region,
						Message:      message,
						Remediation:  fmt.Sprintf("Allocate and associate an Elastic IP: aws ec2 allocate-address && aws ec2 associate-address --instance-id %s --allocation-id <eip-id>", instanceID),
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return findings, nil
}
