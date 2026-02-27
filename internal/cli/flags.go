// Package cli contains the Cobra command tree and shared CLI utilities.
package cli

import "fmt"

const (
	// FlagOutput is the persistent flag name controlling output format.
	FlagOutput = "output"
	// FlagRegion is the persistent flag name for target AWS regions.
	FlagRegion = "region"
	// FlagProfile is the persistent flag name for the AWS named profile.
	FlagProfile = "profile"

	// OutputText is the human-readable terminal output format.
	OutputText = "text"
	// OutputJSON is the structured JSON output format.
	OutputJSON = "json"

	// DefaultRegion is the region targeted when no --region flag is provided.
	DefaultRegion = "eu-west-2"
)

// ValidateOutputFlag returns an error if the provided output format string is
// not one of the supported values.
func ValidateOutputFlag(v string) error {
	switch v {
	case OutputText, OutputJSON:
		return nil
	default:
		return fmt.Errorf("unsupported output format %q: must be %q or %q", v, OutputText, OutputJSON)
	}
}
