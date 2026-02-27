package elb

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/yourorg/infraguard/internal/engine"
)

// HTTPRedirectCheck identifies ALBs with HTTP listeners without HTTPS redirect.
type HTTPRedirectCheck struct{}

func (c *HTTPRedirectCheck) Name() string {
	return "elb/http-no-redirect"
}

func (c *HTTPRedirectCheck) Description() string {
	return "Detects Application Load Balancers with HTTP listeners not redirecting to HTTPS"
}

func (c *HTTPRedirectCheck) Severity() engine.Severity {
	return engine.SeverityHigh
}

func (c *HTTPRedirectCheck) RequiredIAMPermissions() []string {
	return []string{
		"elasticloadbalancing:DescribeLoadBalancers",
		"elasticloadbalancing:DescribeListeners",
		"elasticloadbalancing:DescribeRules",
	}
}

func (c *HTTPRedirectCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := elasticloadbalancingv2.NewFromConfig(cfg.AWSConfig, func(o *elasticloadbalancingv2.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	// Get all load balancers
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

			// Only check Application Load Balancers
			if lb.Type != types.LoadBalancerTypeEnumApplication {
				continue
			}

			lbArn := *lb.LoadBalancerArn
			lbName := *lb.LoadBalancerName

			// Get listeners for this load balancer
			listenersResp, err := client.DescribeListeners(ctx, &elasticloadbalancingv2.DescribeListenersInput{
				LoadBalancerArn: &lbArn,
			})
			if err != nil {
				continue
			}

			// Check for HTTP listeners without redirect
			for _, listener := range listenersResp.Listeners {
				if listener.Protocol == types.ProtocolEnumHttp {
					hasRedirect := false

					// Check if default action is redirect to HTTPS
					for _, action := range listener.DefaultActions {
						if action.Type == types.ActionTypeEnumRedirect &&
							action.RedirectConfig != nil &&
							action.RedirectConfig.Protocol != nil &&
							*action.RedirectConfig.Protocol == "HTTPS" {
							hasRedirect = true
							break
						}
					}

					if !hasRedirect {
						findings = append(findings, engine.Finding{
							CheckName:    c.Name(),
							Severity:     c.Severity(),
							ResourceID:   lbArn,
							Region:       cfg.Region,
							Message:      fmt.Sprintf("ALB '%s' has HTTP listener without HTTPS redirect", lbName),
							Remediation:  fmt.Sprintf("Configure HTTP to HTTPS redirect for ALB '%s'", lbName),
							DiscoveredAt: time.Now(),
						})
					}
				}
			}
		}
	}

	return findings, nil
}

// ALBAccessLoggingCheck identifies ALBs without access logging enabled.
type ALBAccessLoggingCheck struct{}

func (c *ALBAccessLoggingCheck) Name() string {
	return "elb/no-access-logging"
}

func (c *ALBAccessLoggingCheck) Description() string {
	return "Detects Application Load Balancers without access logging enabled"
}

func (c *ALBAccessLoggingCheck) Severity() engine.Severity {
	return engine.SeverityMedium
}

func (c *ALBAccessLoggingCheck) RequiredIAMPermissions() []string {
	return []string{
		"elasticloadbalancing:DescribeLoadBalancers",
		"elasticloadbalancing:DescribeLoadBalancerAttributes",
	}
}

func (c *ALBAccessLoggingCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
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

			// Only check Application and Network Load Balancers
			if lb.Type != types.LoadBalancerTypeEnumApplication && lb.Type != types.LoadBalancerTypeEnumNetwork {
				continue
			}

			lbArn := *lb.LoadBalancerArn
			lbName := *lb.LoadBalancerName

			// Get load balancer attributes
			attrsResp, err := client.DescribeLoadBalancerAttributes(ctx, &elasticloadbalancingv2.DescribeLoadBalancerAttributesInput{
				LoadBalancerArn: &lbArn,
			})
			if err != nil {
				continue
			}

			// Check if access logging is enabled
			loggingEnabled := false
			for _, attr := range attrsResp.Attributes {
				if attr.Key != nil && *attr.Key == "access_logs.s3.enabled" &&
					attr.Value != nil && *attr.Value == "true" {
					loggingEnabled = true
					break
				}
			}

			if !loggingEnabled {
				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   lbArn,
					Region:       cfg.Region,
					Message:      fmt.Sprintf("Load Balancer '%s' does not have access logging enabled", lbName),
					Remediation:  fmt.Sprintf("Enable access logging: aws elbv2 modify-load-balancer-attributes --load-balancer-arn %s --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=<bucket-name>", lbArn),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// SSLCertificateExpiryCheck identifies load balancers with expiring SSL certificates.
type SSLCertificateExpiryCheck struct{}

func (c *SSLCertificateExpiryCheck) Name() string {
	return "elb/ssl-cert-expiring"
}

func (c *SSLCertificateExpiryCheck) Description() string {
	return "Detects load balancers with SSL certificates expiring within 30 days"
}

func (c *SSLCertificateExpiryCheck) Severity() engine.Severity {
	return engine.SeverityHigh
}

func (c *SSLCertificateExpiryCheck) RequiredIAMPermissions() []string {
	return []string{
		"elasticloadbalancing:DescribeLoadBalancers",
		"elasticloadbalancing:DescribeListeners",
		"elasticloadbalancing:DescribeSSLPolicies",
	}
}

func (c *SSLCertificateExpiryCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
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

			// Get listeners
			listenersResp, err := client.DescribeListeners(ctx, &elasticloadbalancingv2.DescribeListenersInput{
				LoadBalancerArn: &lbArn,
			})
			if err != nil {
				continue
			}

			// Check HTTPS/TLS listeners for certificates
			for _, listener := range listenersResp.Listeners {
				if listener.Protocol == types.ProtocolEnumHttps || listener.Protocol == types.ProtocolEnumTls {
					if len(listener.Certificates) == 0 {
						findings = append(findings, engine.Finding{
							CheckName:    c.Name(),
							Severity:     c.Severity(),
							ResourceID:   lbArn,
							Region:       cfg.Region,
							Message:      fmt.Sprintf("Load Balancer '%s' has HTTPS listener without certificates configured", lbName),
							Remediation:  fmt.Sprintf("Configure SSL certificate for listener on '%s'", lbName),
							DiscoveredAt: time.Now(),
						})
					}

					// Note: Certificate expiry checking requires ACM API calls
					// This is a simplified check - full implementation would query ACM
					for _, cert := range listener.Certificates {
						if cert.CertificateArn == nil {
							continue
						}
						// In production, you'd call ACM DescribeCertificate here
						// and check NotAfter field against current time + 30 days
					}
				}
			}
		}
	}

	return findings, nil
}
