package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/yourorg/infraguard/internal/awsutil"
	"github.com/yourorg/infraguard/internal/checks/logging"
	"github.com/yourorg/infraguard/internal/colour"
	"github.com/yourorg/infraguard/internal/engine"
)

// newAuditConfigCmd returns the "audit config" sub-command.
func newAuditConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Validate AWS configuration settings and service limits",
		Long: `Runs configuration-level checks including CloudTrail, Config,
GuardDuty enablement, account-level settings, and resource tagging policies.`,
		RunE: runAuditConfig,
	}
}

func runAuditConfig(cmd *cobra.Command, _ []string) error {
	output, _ := cmd.Flags().GetString(FlagOutput)
	regions, _ := cmd.Flags().GetStringSlice(FlagRegion)
	profile, _ := cmd.Flags().GetString(FlagProfile)

	// Load AWS configuration
	cfg, err := awsutil.LoadConfig(cmd.Context(), regions[0], profile)
	if err != nil {
		return fmt.Errorf("loading AWS config: %w", err)
	}

	// Get account ID
	accountID, err := awsutil.GetAccountID(cmd.Context(), cfg)
	if err != nil {
		return fmt.Errorf("getting account ID: %w", err)
	}

	// Print banner with account and region context
	PrintBanner(os.Stderr, accountID, regions)

	// Create engine and register config-specific checks
	eng := engine.NewEngine()

	// Logging and monitoring checks
	eng.Register(&logging.CloudTrailEnabledCheck{})
	eng.Register(&logging.ConfigRecorderCheck{})
	eng.Register(&logging.GuardDutyEnabledCheck{})

	// Run checks
	fmt.Fprintf(os.Stderr, "%s\n\n", colour.Sprintf(colour.Bold, "  Starting config audit with %d checks across %d region(s)...", eng.CheckCount(), len(regions)))

	checkCfg := engine.CheckConfig{
		AWSConfig: cfg,
		AccountID: accountID,
		LogWriter: os.Stderr,
	}

	result, err := eng.Run(cmd.Context(), checkCfg, regions)
	if err != nil {
		return fmt.Errorf("audit config: %w", err)
	}

	rep := buildReporter(output)
	return rep.Report(os.Stdout, result)
}
