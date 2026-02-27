package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "infraguard",
	Short: "infraguard audits AWS infrastructure and validates configuration",
	Long: `infraguard is a CLI tool for engineering teams to audit AWS
infrastructure posture and validate configuration against defined rules.

Credentials are resolved via the AWS default credential chain:
environment variables, named profiles, instance metadata, and so on.`,
	// SilenceUsage prevents Cobra printing the full usage block on every error,
	// which is noisy in CI. We print usage only on genuine flag parse failures.
	SilenceUsage: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		output, err := cmd.Flags().GetString(FlagOutput)
		if err != nil {
			return fmt.Errorf("reading --%s flag: %w", FlagOutput, err)
		}
		return ValidateOutputFlag(output)
	},
}

// Execute is the entry point called by main. It adds all sub-commands and
// runs the Cobra command tree.
func Execute() error {
	rootCmd.AddCommand(newAuditInfraCmd())
	rootCmd.AddCommand(newAuditConfigCmd())
	return rootCmd.ExecuteContext(context.Background())
}

func init() {
	rootCmd.PersistentFlags().StringP(
		FlagOutput, "o", OutputText,
		`output format: "text" (default) or "json"`,
	)
	rootCmd.PersistentFlags().StringSliceP(
		FlagRegion, "r", []string{DefaultRegion},
		"comma-separated list of AWS regions to target",
	)
	rootCmd.PersistentFlags().String(
		FlagProfile, "",
		"AWS named profile to use (defaults to AWS_PROFILE env var or the default profile)",
	)
}
