// Package collector provides utilities for collecting AWS resource data.
package collector

// Collector defines the interface for AWS resource collectors.
type Collector interface {
	// Collect gathers resource data from AWS for analysis.
	Collect() error
}
