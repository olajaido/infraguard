package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/yourorg/infraguard/internal/awsutil"
	"github.com/yourorg/infraguard/internal/checks/cloudfront"
	"github.com/yourorg/infraguard/internal/checks/compute"
	"github.com/yourorg/infraguard/internal/checks/cost"
	"github.com/yourorg/infraguard/internal/checks/ec2"
	"github.com/yourorg/infraguard/internal/checks/elb"
	"github.com/yourorg/infraguard/internal/checks/iam"
	"github.com/yourorg/infraguard/internal/checks/kms"
	"github.com/yourorg/infraguard/internal/checks/logging"
	"github.com/yourorg/infraguard/internal/checks/rds"
	"github.com/yourorg/infraguard/internal/checks/s3"
	"github.com/yourorg/infraguard/internal/checks/vpc"
	"github.com/yourorg/infraguard/internal/colour"
	"github.com/yourorg/infraguard/internal/engine"
	"github.com/yourorg/infraguard/internal/reporter"
)

// newAuditInfraCmd returns the "audit infra" sub-command.
func newAuditInfraCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "infra",
		Short: "Audit AWS infrastructure resources for misconfigurations",
		Long: `Runs infrastructure checks against live AWS resources including
EC2, S3, IAM, VPC, and RDS. Requires read-only AWS credentials.`,
		RunE: runAuditInfra,
	}
}

func runAuditInfra(cmd *cobra.Command, _ []string) error {
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

	// Create engine and register checks
	eng := engine.NewEngine()

	// S3 checks
	eng.Register(&s3.PublicBucketsCheck{})
	eng.Register(&s3.UnencryptedBucketsCheck{})
	eng.Register(&s3.BucketVersioningCheck{})
	eng.Register(&s3.BucketLoggingCheck{})
	eng.Register(&s3.BucketLifecycleCheck{})
	eng.Register(&s3.PublicBucketPolicyCheck{})

	// IAM checks
	eng.Register(&iam.RootMFACheck{})
	eng.Register(&iam.UsersMissingMFACheck{})
	eng.Register(&iam.OldAccessKeysCheck{})
	eng.Register(&iam.StaleUsersCheck{})
	eng.Register(&iam.WildcardPoliciesCheck{})
	eng.Register(&iam.DualAccessUsersCheck{})
	eng.Register(&iam.RootAccountUsageCheck{})

	// EC2 checks
	eng.Register(&ec2.OpenSecurityGroupsCheck{})
	eng.Register(&ec2.UnencryptedEBSCheck{})
	eng.Register(&ec2.IMDSv1Check{})
	eng.Register(&ec2.PublicAMIsCheck{})
	eng.Register(&ec2.StoppedInstancesCheck{})
	eng.Register(&ec2.UnencryptedSnapshotsCheck{})
	eng.Register(&ec2.EphemeralPublicIPCheck{})

	// RDS checks
	eng.Register(&rds.PublicRDSCheck{})
	eng.Register(&rds.UnencryptedRDSCheck{})
	eng.Register(&rds.RDSBackupCheck{})
	eng.Register(&rds.RDSMultiAZCheck{})
	eng.Register(&rds.PublicRDSSnapshotsCheck{})

	// Lambda & ECS checks
	eng.Register(&compute.LambdaSecretsInEnvCheck{})
	eng.Register(&compute.LambdaDeprecatedRuntimeCheck{})
	eng.Register(&compute.ECSPrivilegedContainersCheck{})
	eng.Register(&compute.ECSHostNetworkModeCheck{})
	eng.Register(&compute.ECRLifecyclePolicyCheck{})

	// Logging checks
	eng.Register(&logging.CloudTrailEnabledCheck{})
	eng.Register(&logging.ConfigRecorderCheck{})
	eng.Register(&logging.GuardDutyEnabledCheck{})

	// VPC checks
	eng.Register(&vpc.VPCFlowLogsCheck{})
	eng.Register(&vpc.DefaultVPCCheck{})
	eng.Register(&vpc.MapPublicIPCheck{})
	eng.Register(&vpc.OpenNACLsCheck{})
	eng.Register(&vpc.StalePeeringCheck{})

	// KMS checks
	eng.Register(&kms.KMSKeyRotationCheck{})
	eng.Register(&kms.KMSKeyPolicyCheck{})
	eng.Register(&kms.SecretsManagerRotationCheck{})

	// ELB checks
	eng.Register(&elb.HTTPRedirectCheck{})
	eng.Register(&elb.ALBAccessLoggingCheck{})
	eng.Register(&elb.SSLCertificateExpiryCheck{})

	// CloudFront checks
	eng.Register(&cloudfront.DeprecatedTLSCheck{})
	eng.Register(&cloudfront.NoWAFCheck{})
	eng.Register(&cloudfront.NoLoggingCheck{})

	// Cost/Hygiene checks
	eng.Register(&cost.UnattachedEIPCheck{})
	eng.Register(&cost.UnattachedEBSCheck{})
	eng.Register(&cost.UnusedELBCheck{})

	// Run checks
	fmt.Fprintf(os.Stderr, "%s\n\n", colour.Sprintf(colour.Bold, "  Starting scan with %d checks across %d region(s)...", eng.CheckCount(), len(regions)))

	checkCfg := engine.CheckConfig{
		AWSConfig: cfg,
		AccountID: accountID,
		LogWriter: os.Stderr,
	}

	result, err := eng.Run(cmd.Context(), checkCfg, regions)
	if err != nil {
		return fmt.Errorf("audit infra: %w", err)
	}

	rep := buildReporter(output)
	return rep.Report(os.Stdout, result)
}

// buildReporter returns the appropriate Reporter implementation based on the
// --output flag value. ValidateOutputFlag has already verified the value.
func buildReporter(output string) reporter.Reporter {
	if output == OutputJSON {
		colour.Disable() // Disable colour for JSON output
		return reporter.NewJSONReporter()
	}
	return reporter.NewTextReporter()
}
