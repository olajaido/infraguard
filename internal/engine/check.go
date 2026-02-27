package engine

import (
	"context"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// Check is the interface that every infraguard rule must implement.
//
// Each Check is responsible for its own AWS API calls via the context-provided
// clients. Checks must be safe to call concurrently; they should not mutate
// shared state.
type Check interface {
	// Name returns the unique, stable identifier for this check.
	// Convention: "<service>/<short-description>", e.g. "ec2/public-ami".
	// This value is used in Finding.CheckName and in --skip-checks filtering.
	Name() string

	// Description returns a one-sentence summary of what the check evaluates.
	Description() string

	// Severity returns the default severity level assigned to findings from
	// this check. Individual findings may not override this; use a separate
	// check registration for different severity variants.
	Severity() Severity

	// RequiredIAMPermissions returns the IAM action strings needed for this
	// check to run successfully, e.g. ["ec2:DescribeInstances"].
	// This is used to generate pre-flight IAM validation output.
	RequiredIAMPermissions() []string

	// Run executes the check against the given region and returns zero or more
	// findings. A check that finds no issues returns a nil or empty slice —
	// not an error. Only genuine execution failures (API errors, auth errors)
	// should be returned as an error.
	Run(ctx context.Context, cfg CheckConfig) ([]Finding, error)
}

// CheckConfig carries the runtime inputs provided to every check.
// It is intentionally a plain struct rather than an interface so that tests
// can construct it directly without a builder or mock.
type CheckConfig struct {
	// AWSConfig is the resolved AWS SDK configuration, including credentials
	// and the default region. Checks construct their own service clients from
	// this value.
	AWSConfig aws.Config

	// Region is the specific AWS region this check execution targets.
	// A check may be invoked multiple times, once per target region.
	Region string

	// AccountID is the AWS account ID of the authenticated principal,
	// resolved at startup and injected here for use in ARN construction.
	AccountID string

	// LogWriter is where progress logs should be written (typically os.Stderr).
	// If nil, logging is disabled.
	LogWriter io.Writer
}
