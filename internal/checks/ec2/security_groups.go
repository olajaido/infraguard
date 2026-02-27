// Package ec2 implements EC2 security checks.
package ec2

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/yourorg/infraguard/internal/engine"
)

// OpenSecurityGroupsCheck identifies security groups with overly permissive ingress rules.
type OpenSecurityGroupsCheck struct{}

func (c *OpenSecurityGroupsCheck) Name() string {
	return "ec2/open-security-groups"
}

func (c *OpenSecurityGroupsCheck) Description() string {
	return "Detects security groups with unrestricted ingress from 0.0.0.0/0 or ::/0"
}

func (c *OpenSecurityGroupsCheck) Severity() engine.Severity {
	return engine.SeverityCritical
}

func (c *OpenSecurityGroupsCheck) RequiredIAMPermissions() []string {
	return []string{
		"ec2:DescribeSecurityGroups",
	}
}

func (c *OpenSecurityGroupsCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := ec2.NewFromConfig(cfg.AWSConfig, func(o *ec2.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	// Describe all security groups
	sgPaginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
	for sgPaginator.HasMorePages() {
		sgResp, err := sgPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing security groups: %w", err)
		}

		for _, sg := range sgResp.SecurityGroups {
			if sg.GroupId == nil || sg.GroupName == nil {
				continue
			}

			sgID := *sg.GroupId
			sgName := *sg.GroupName

			// Check ingress rules for unrestricted access
			for _, perm := range sg.IpPermissions {
				var protocol string
				if perm.IpProtocol != nil {
					protocol = *perm.IpProtocol
				}

				// Check IPv4 ranges
				for _, ipRange := range perm.IpRanges {
					if ipRange.CidrIp != nil && (*ipRange.CidrIp == "0.0.0.0/0") {
						portInfo := getPortInfo(perm)
						findings = append(findings, engine.Finding{
							CheckName:    c.Name(),
							Severity:     c.Severity(),
							ResourceID:   fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", cfg.Region, cfg.AccountID, sgID),
							Region:       cfg.Region,
							Message:      fmt.Sprintf("Security group '%s' (%s) allows unrestricted ingress from 0.0.0.0/0 on %s %s", sgName, sgID, protocol, portInfo),
							Remediation:  fmt.Sprintf("Restrict security group ingress rules to specific IP ranges. Remove unrestricted rule: aws ec2 revoke-security-group-ingress --group-id %s --protocol %s --cidr 0.0.0.0/0 %s", sgID, protocol, portInfo),
							DiscoveredAt: time.Now(),
						})
					}
				}

				// Check IPv6 ranges
				for _, ipv6Range := range perm.Ipv6Ranges {
					if ipv6Range.CidrIpv6 != nil && (*ipv6Range.CidrIpv6 == "::/0") {
						portInfo := getPortInfo(perm)
						findings = append(findings, engine.Finding{
							CheckName:    c.Name(),
							Severity:     c.Severity(),
							ResourceID:   fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", cfg.Region, cfg.AccountID, sgID),
							Region:       cfg.Region,
							Message:      fmt.Sprintf("Security group '%s' (%s) allows unrestricted ingress from ::/0 on %s %s", sgName, sgID, protocol, portInfo),
							Remediation:  fmt.Sprintf("Restrict security group ingress rules to specific IPv6 ranges. Remove unrestricted rule from security group %s", sgID),
							DiscoveredAt: time.Now(),
						})
					}
				}
			}
		}
	}

	return findings, nil
}

// getPortInfo extracts port range information from an IP permission.
func getPortInfo(perm types.IpPermission) string {
	if perm.FromPort != nil && perm.ToPort != nil {
		if *perm.FromPort == *perm.ToPort {
			return fmt.Sprintf("port %d", *perm.FromPort)
		}
		return fmt.Sprintf("ports %d-%d", *perm.FromPort, *perm.ToPort)
	}
	return "all ports"
}

// UnencryptedEBSCheck identifies EBS volumes without encryption enabled.
type UnencryptedEBSCheck struct{}

func (c *UnencryptedEBSCheck) Name() string {
	return "ec2/unencrypted-ebs"
}

func (c *UnencryptedEBSCheck) Description() string {
	return "Detects EBS volumes that are not encrypted"
}

func (c *UnencryptedEBSCheck) Severity() engine.Severity {
	return engine.SeverityHigh
}

func (c *UnencryptedEBSCheck) RequiredIAMPermissions() []string {
	return []string{
		"ec2:DescribeVolumes",
	}
}

func (c *UnencryptedEBSCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := ec2.NewFromConfig(cfg.AWSConfig, func(o *ec2.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	// Describe all volumes
	volPaginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{})
	for volPaginator.HasMorePages() {
		volResp, err := volPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing volumes: %w", err)
		}

		for _, vol := range volResp.Volumes {
			if vol.VolumeId == nil {
				continue
			}

			volID := *vol.VolumeId

			// Check if volume is encrypted
			if vol.Encrypted != nil && !*vol.Encrypted {
				// Get attached instances if any
				var attachedInstances []string
				for _, attachment := range vol.Attachments {
					if attachment.InstanceId != nil {
						attachedInstances = append(attachedInstances, *attachment.InstanceId)
					}
				}

				message := fmt.Sprintf("EBS volume '%s' is not encrypted", volID)
				if len(attachedInstances) > 0 {
					message += fmt.Sprintf(" (attached to: %v)", attachedInstances)
				}

				findings = append(findings, engine.Finding{
					CheckName:        c.Name(),
					Severity:         c.Severity(),
					ResourceID:       fmt.Sprintf("arn:aws:ec2:%s:%s:volume/%s", cfg.Region, cfg.AccountID, volID),
					Region:           cfg.Region,
					RelatedResources: attachedInstances,
					Message:          message,
					Remediation:      fmt.Sprintf("Create an encrypted snapshot and new volume: aws ec2 create-snapshot --volume-id %s --description 'Snapshot for encryption' && aws ec2 copy-snapshot --source-snapshot-id <snapshot-id> --encrypted", volID),
					DiscoveredAt:     time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// IMDSv1Check identifies EC2 instances not requiring IMDSv2.
type IMDSv1Check struct{}

func (c *IMDSv1Check) Name() string {
	return "ec2/imdsv1-enabled"
}

func (c *IMDSv1Check) Description() string {
	return "Detects EC2 instances that allow IMDSv1 (insecure metadata service)"
}

func (c *IMDSv1Check) Severity() engine.Severity {
	return engine.SeverityMedium
}

func (c *IMDSv1Check) RequiredIAMPermissions() []string {
	return []string{
		"ec2:DescribeInstances",
	}
}

func (c *IMDSv1Check) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := ec2.NewFromConfig(cfg.AWSConfig, func(o *ec2.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	// Describe all instances
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

				// Check metadata options
				if instance.MetadataOptions == nil ||
					instance.MetadataOptions.HttpTokens != types.HttpTokensStateRequired {

					var instanceName string
					for _, tag := range instance.Tags {
						if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil {
							instanceName = *tag.Value
							break
						}
					}

					message := fmt.Sprintf("EC2 instance '%s' allows IMDSv1 (insecure metadata access)", instanceID)
					if instanceName != "" {
						message = fmt.Sprintf("EC2 instance '%s' (%s) allows IMDSv1 (insecure metadata access)", instanceName, instanceID)
					}

					findings = append(findings, engine.Finding{
						CheckName:    c.Name(),
						Severity:     c.Severity(),
						ResourceID:   fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", cfg.Region, cfg.AccountID, instanceID),
						Region:       cfg.Region,
						Message:      message,
						Remediation:  fmt.Sprintf("Require IMDSv2: aws ec2 modify-instance-metadata-options --instance-id %s --http-tokens required --http-put-response-hop-limit 1", instanceID),
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return findings, nil
}
