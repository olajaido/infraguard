package cost

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/yourorg/infraguard/internal/engine"
)

// UnattachedEIPCheck identifies Elastic IPs not associated with any instance.
type UnattachedEIPCheck struct{}

func (c *UnattachedEIPCheck) Name() string {
	return "cost/unattached-eips"
}

func (c *UnattachedEIPCheck) Description() string {
	return "Detects Elastic IPs not attached to any instance (incurring charges)"
}

func (c *UnattachedEIPCheck) Severity() engine.Severity {
	return engine.SeverityLow
}

func (c *UnattachedEIPCheck) RequiredIAMPermissions() []string {
	return []string{
		"ec2:DescribeAddresses",
	}
}

func (c *UnattachedEIPCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := ec2.NewFromConfig(cfg.AWSConfig, func(o *ec2.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	eipsResp, err := client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, fmt.Errorf("describing Elastic IPs: %w", err)
	}

	for _, address := range eipsResp.Addresses {
		if address.AllocationId == nil {
			continue
		}

		allocationID := *address.AllocationId

		// Check if EIP is not associated with any instance or network interface
		if address.InstanceId == nil && address.NetworkInterfaceId == nil {
			publicIP := "unknown"
			if address.PublicIp != nil {
				publicIP = *address.PublicIp
			}

			findings = append(findings, engine.Finding{
				CheckName:    c.Name(),
				Severity:     c.Severity(),
				ResourceID:   fmt.Sprintf("arn:aws:ec2:%s:%s:elastic-ip/%s", cfg.Region, cfg.AccountID, allocationID),
				Region:       cfg.Region,
				Message:      fmt.Sprintf("Elastic IP '%s' (%s) is not attached to any instance (incurring hourly charges)", allocationID, publicIP),
				Remediation:  fmt.Sprintf("Release unused Elastic IP: aws ec2 release-address --allocation-id %s", allocationID),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// UnattachedEBSCheck identifies EBS volumes not attached to any instance.
type UnattachedEBSCheck struct{}

func (c *UnattachedEBSCheck) Name() string {
	return "cost/unattached-ebs-volumes"
}

func (c *UnattachedEBSCheck) Description() string {
	return "Detects EBS volumes not attached to any instance (incurring storage charges)"
}

func (c *UnattachedEBSCheck) Severity() engine.Severity {
	return engine.SeverityLow
}

func (c *UnattachedEBSCheck) RequiredIAMPermissions() []string {
	return []string{
		"ec2:DescribeVolumes",
	}
}

func (c *UnattachedEBSCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := ec2.NewFromConfig(cfg.AWSConfig, func(o *ec2.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	volumesPaginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{})
	for volumesPaginator.HasMorePages() {
		volumesResp, err := volumesPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing volumes: %w", err)
		}

		for _, volume := range volumesResp.Volumes {
			if volume.VolumeId == nil {
				continue
			}

			volumeID := *volume.VolumeId

			// Check if volume is in 'available' state (not attached)
			if volume.State == "available" {
				sizeGB := int32(0)
				if volume.Size != nil {
					sizeGB = *volume.Size
				}

				var volumeName string
				for _, tag := range volume.Tags {
					if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil {
						volumeName = *tag.Value
						break
					}
				}

				message := fmt.Sprintf("EBS volume '%s' (%d GB) is not attached to any instance", volumeID, sizeGB)
				if volumeName != "" {
					message = fmt.Sprintf("EBS volume '%s' (%s, %d GB) is not attached to any instance", volumeName, volumeID, sizeGB)
				}

				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   fmt.Sprintf("arn:aws:ec2:%s:%s:volume/%s", cfg.Region, cfg.AccountID, volumeID),
					Region:       cfg.Region,
					Message:      message,
					Remediation:  fmt.Sprintf("Delete unused volume if no longer needed: aws ec2 delete-volume --volume-id %s (create snapshot first if needed)", volumeID),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// UnusedELBCheck identifies load balancers with no registered targets.
type UnusedELBCheck struct{}

func (c *UnusedELBCheck) Name() string {
	return "cost/unused-load-balancers"
}

func (c *UnusedELBCheck) Description() string {
	return "Detects load balancers with no healthy targets (potentially unused)"
}

func (c *UnusedELBCheck) Severity() engine.Severity {
	return engine.SeverityLow
}

func (c *UnusedELBCheck) RequiredIAMPermissions() []string {
	return []string{
		"elasticloadbalancing:DescribeLoadBalancers",
		"elasticloadbalancing:DescribeTargetGroups",
		"elasticloadbalancing:DescribeTargetHealth",
	}
}

func (c *UnusedELBCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := elasticloadbalancingv2.NewFromConfig(cfg.AWSConfig, func(o *elasticloadbalancingv2.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	lbPaginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	for lbPaginator.HasMorePages() {
		lbResp, err := lbPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing load balancers: %w", err)
		}

		for _, lb := range lbResp.LoadBalancers {
			if lb.LoadBalancerArn == nil || lb.LoadBalancerName == nil {
				continue
			}

			lbArn := *lb.LoadBalancerArn
			lbName := *lb.LoadBalancerName

			// Get target groups for this load balancer
			tgPaginator := elasticloadbalancingv2.NewDescribeTargetGroupsPaginator(client, &elasticloadbalancingv2.DescribeTargetGroupsInput{
				LoadBalancerArn: &lbArn,
			})

			hasHealthyTargets := false
			for tgPaginator.HasMorePages() {
				tgResp, err := tgPaginator.NextPage(ctx)
				if err != nil {
					continue
				}

				for _, tg := range tgResp.TargetGroups {
					if tg.TargetGroupArn == nil {
						continue
					}

					// Check target health
					healthResp, err := client.DescribeTargetHealth(ctx, &elasticloadbalancingv2.DescribeTargetHealthInput{
						TargetGroupArn: tg.TargetGroupArn,
					})
					if err != nil {
						continue
					}

					// Check if any targets are healthy
					for _, targetHealth := range healthResp.TargetHealthDescriptions {
						if targetHealth.TargetHealth != nil && targetHealth.TargetHealth.State == "healthy" {
							hasHealthyTargets = true
							break
						}
					}

					if hasHealthyTargets {
						break
					}
				}

				if hasHealthyTargets {
					break
				}
			}

			if !hasHealthyTargets {
				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   lbArn,
					Region:       cfg.Region,
					Message:      fmt.Sprintf("Load Balancer '%s' has no healthy targets (potentially unused)", lbName),
					Remediation:  fmt.Sprintf("Review load balancer '%s' and delete if no longer needed", lbName),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}
