package vpc

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/yourorg/infraguard/internal/engine"
)

// VPCFlowLogsCheck identifies VPCs without flow logs enabled.
type VPCFlowLogsCheck struct{}

func (c *VPCFlowLogsCheck) Name() string {
	return "vpc/no-flow-logs"
}

func (c *VPCFlowLogsCheck) Description() string {
	return "Detects VPCs without flow logs enabled for network monitoring"
}

func (c *VPCFlowLogsCheck) Severity() engine.Severity {
	return engine.SeverityHigh
}

func (c *VPCFlowLogsCheck) RequiredIAMPermissions() []string {
	return []string{
		"ec2:DescribeVpcs",
		"ec2:DescribeFlowLogs",
	}
}

func (c *VPCFlowLogsCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := ec2.NewFromConfig(cfg.AWSConfig, func(o *ec2.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	// Get all VPCs
	vpcsResp, err := client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("describing VPCs: %w", err)
	}

	// Get all flow logs
	flowLogsResp, err := client.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{})
	if err != nil {
		return nil, fmt.Errorf("describing flow logs: %w", err)
	}

	// Create map of VPCs with flow logs
	vpcFlowLogs := make(map[string]bool)
	for _, flowLog := range flowLogsResp.FlowLogs {
		if flowLog.ResourceId != nil {
			vpcFlowLogs[*flowLog.ResourceId] = true
		}
	}

	// Check each VPC
	for _, vpc := range vpcsResp.Vpcs {
		if vpc.VpcId == nil {
			continue
		}

		vpcID := *vpc.VpcId

		if !vpcFlowLogs[vpcID] {
			var vpcName string
			for _, tag := range vpc.Tags {
				if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil {
					vpcName = *tag.Value
					break
				}
			}

			message := fmt.Sprintf("VPC '%s' does not have flow logs enabled", vpcID)
			if vpcName != "" {
				message = fmt.Sprintf("VPC '%s' (%s) does not have flow logs enabled", vpcName, vpcID)
			}

			findings = append(findings, engine.Finding{
				CheckName:    c.Name(),
				Severity:     c.Severity(),
				ResourceID:   fmt.Sprintf("arn:aws:ec2:%s:%s:vpc/%s", cfg.Region, cfg.AccountID, vpcID),
				Region:       cfg.Region,
				Message:      message,
				Remediation:  fmt.Sprintf("Enable VPC flow logs: aws ec2 create-flow-logs --resource-type VPC --resource-ids %s --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /aws/vpc/flowlogs", vpcID),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// DefaultVPCCheck identifies default VPCs that should be removed.
type DefaultVPCCheck struct{}

func (c *DefaultVPCCheck) Name() string {
	return "vpc/default-vpc-exists"
}

func (c *DefaultVPCCheck) Description() string {
	return "Detects default VPCs that pose security risks"
}

func (c *DefaultVPCCheck) Severity() engine.Severity {
	return engine.SeverityMedium
}

func (c *DefaultVPCCheck) RequiredIAMPermissions() []string {
	return []string{
		"ec2:DescribeVpcs",
	}
}

func (c *DefaultVPCCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := ec2.NewFromConfig(cfg.AWSConfig, func(o *ec2.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	vpcsResp, err := client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("describing VPCs: %w", err)
	}

	for _, vpc := range vpcsResp.Vpcs {
		if vpc.VpcId == nil {
			continue
		}

		vpcID := *vpc.VpcId

		// Check if it's a default VPC
		if vpc.IsDefault != nil && *vpc.IsDefault {
			findings = append(findings, engine.Finding{
				CheckName:    c.Name(),
				Severity:     c.Severity(),
				ResourceID:   fmt.Sprintf("arn:aws:ec2:%s:%s:vpc/%s", cfg.Region, cfg.AccountID, vpcID),
				Region:       cfg.Region,
				Message:      fmt.Sprintf("Default VPC '%s' exists (security best practice is to delete)", vpcID),
				Remediation:  fmt.Sprintf("Consider deleting default VPC: aws ec2 delete-vpc --vpc-id %s (after ensuring no resources are using it)", vpcID),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// MapPublicIPCheck identifies subnets with MapPublicIpOnLaunch enabled.
type MapPublicIPCheck struct{}

func (c *MapPublicIPCheck) Name() string {
	return "vpc/map-public-ip-on-launch"
}

func (c *MapPublicIPCheck) Description() string {
	return "Detects subnets that automatically assign public IPs to instances"
}

func (c *MapPublicIPCheck) Severity() engine.Severity {
	return engine.SeverityMedium
}

func (c *MapPublicIPCheck) RequiredIAMPermissions() []string {
	return []string{
		"ec2:DescribeSubnets",
	}
}

func (c *MapPublicIPCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := ec2.NewFromConfig(cfg.AWSConfig, func(o *ec2.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	subnetsResp, err := client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{})
	if err != nil {
		return nil, fmt.Errorf("describing subnets: %w", err)
	}

	for _, subnet := range subnetsResp.Subnets {
		if subnet.SubnetId == nil {
			continue
		}

		subnetID := *subnet.SubnetId

		if subnet.MapPublicIpOnLaunch != nil && *subnet.MapPublicIpOnLaunch {
			var subnetName string
			for _, tag := range subnet.Tags {
				if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil {
					subnetName = *tag.Value
					break
				}
			}

			message := fmt.Sprintf("Subnet '%s' has MapPublicIpOnLaunch enabled", subnetID)
			if subnetName != "" {
				message = fmt.Sprintf("Subnet '%s' (%s) has MapPublicIpOnLaunch enabled", subnetName, subnetID)
			}

			findings = append(findings, engine.Finding{
				CheckName:    c.Name(),
				Severity:     c.Severity(),
				ResourceID:   fmt.Sprintf("arn:aws:ec2:%s:%s:subnet/%s", cfg.Region, cfg.AccountID, subnetID),
				Region:       cfg.Region,
				Message:      message,
				Remediation:  fmt.Sprintf("Disable auto-assign public IP: aws ec2 modify-subnet-attribute --subnet-id %s --no-map-public-ip-on-launch", subnetID),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// OpenNACLsCheck identifies Network ACLs with overly permissive rules.
type OpenNACLsCheck struct{}

func (c *OpenNACLsCheck) Name() string {
	return "vpc/open-network-acls"
}

func (c *OpenNACLsCheck) Description() string {
	return "Detects Network ACLs allowing 0.0.0.0/0 ingress on all ports"
}

func (c *OpenNACLsCheck) Severity() engine.Severity {
	return engine.SeverityHigh
}

func (c *OpenNACLsCheck) RequiredIAMPermissions() []string {
	return []string{
		"ec2:DescribeNetworkAcls",
	}
}

func (c *OpenNACLsCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := ec2.NewFromConfig(cfg.AWSConfig, func(o *ec2.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	naclsResp, err := client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{})
	if err != nil {
		return nil, fmt.Errorf("describing network ACLs: %w", err)
	}

	for _, nacl := range naclsResp.NetworkAcls {
		if nacl.NetworkAclId == nil {
			continue
		}

		naclID := *nacl.NetworkAclId

		// Check for overly permissive ingress rules
		for _, entry := range nacl.Entries {
			if entry.Egress != nil && *entry.Egress {
				continue // Skip egress rules
			}

			// Check for allow rule with 0.0.0.0/0
			if entry.RuleAction == types.RuleActionAllow &&
				entry.CidrBlock != nil && *entry.CidrBlock == "0.0.0.0/0" &&
				(entry.Protocol == nil || *entry.Protocol == "-1") {

				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   fmt.Sprintf("arn:aws:ec2:%s:%s:network-acl/%s", cfg.Region, cfg.AccountID, naclID),
					Region:       cfg.Region,
					Message:      fmt.Sprintf("Network ACL '%s' allows all traffic from 0.0.0.0/0", naclID),
					Remediation:  fmt.Sprintf("Review and restrict NACL rules for %s to follow least privilege", naclID),
					DiscoveredAt: time.Now(),
				})
				break
			}
		}
	}

	return findings, nil
}

// StalePeeringCheck identifies inactive VPC peering connections.
type StalePeeringCheck struct{}

func (c *StalePeeringCheck) Name() string {
	return "vpc/stale-peering"
}

func (c *StalePeeringCheck) Description() string {
	return "Detects VPC peering connections that are not active"
}

func (c *StalePeeringCheck) Severity() engine.Severity {
	return engine.SeverityLow
}

func (c *StalePeeringCheck) RequiredIAMPermissions() []string {
	return []string{
		"ec2:DescribeVpcPeeringConnections",
	}
}

func (c *StalePeeringCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := ec2.NewFromConfig(cfg.AWSConfig, func(o *ec2.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	peeringResp, err := client.DescribeVpcPeeringConnections(ctx, &ec2.DescribeVpcPeeringConnectionsInput{})
	if err != nil {
		return nil, fmt.Errorf("describing VPC peering connections: %w", err)
	}

	for _, peering := range peeringResp.VpcPeeringConnections {
		if peering.VpcPeeringConnectionId == nil {
			continue
		}

		peeringID := *peering.VpcPeeringConnectionId

		// Check for non-active peering connections
		if peering.Status != nil && peering.Status.Code != types.VpcPeeringConnectionStateReasonCodeActive {
			status := string(peering.Status.Code)

			findings = append(findings, engine.Finding{
				CheckName:    c.Name(),
				Severity:     c.Severity(),
				ResourceID:   fmt.Sprintf("arn:aws:ec2:%s:%s:vpc-peering-connection/%s", cfg.Region, cfg.AccountID, peeringID),
				Region:       cfg.Region,
				Message:      fmt.Sprintf("VPC peering connection '%s' is in '%s' state (not active)", peeringID, status),
				Remediation:  fmt.Sprintf("Delete unused peering connection: aws ec2 delete-vpc-peering-connection --vpc-peering-connection-id %s", peeringID),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}
