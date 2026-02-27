// Package engine provides the rules engine for infraguard, including the
// Check interface, Finding types, and the concurrent check runner.
package engine

import "time"

// Severity represents the impact level of a finding.
type Severity string

const (
	// SeverityCritical indicates an immediately exploitable or compliance-breaking issue.
	SeverityCritical Severity = "CRITICAL"
	// SeverityHigh indicates a significant misconfiguration that should be resolved promptly.
	SeverityHigh Severity = "HIGH"
	// SeverityMedium indicates a misconfiguration that poses moderate risk.
	SeverityMedium Severity = "MEDIUM"
	// SeverityLow indicates a best-practice deviation with limited immediate risk.
	SeverityLow Severity = "LOW"
	// SeverityInfo indicates an informational observation that requires no action.
	SeverityInfo Severity = "INFO"
)

// Finding represents a single result produced by a Check.
// All fields are populated by the check that produces the finding.
type Finding struct {
	// CheckName is the unique identifier of the check that produced this finding.
	CheckName string `json:"check_name"`

	// Severity is the assessed impact level of the finding.
	Severity Severity `json:"severity"`

	// ResourceID is the primary AWS resource identifier (ARN, ID, or name).
	ResourceID string `json:"resource_id"`

	// Region is the AWS region in which the resource resides.
	Region string `json:"region"`

	// RelatedResources holds ARNs or IDs of resources that provide additional
	// context, e.g. a security group attached to a flagged EC2 instance.
	RelatedResources []string `json:"related_resources,omitempty"`

	// Message is a human-readable description of the issue found.
	Message string `json:"message"`

	// Remediation describes the recommended corrective action.
	Remediation string `json:"remediation"`

	// DiscoveredAt records when the finding was produced.
	DiscoveredAt time.Time `json:"discovered_at"`
}
