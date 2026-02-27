// Package rds implements RDS security checks.
package rds

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/yourorg/infraguard/internal/engine"
)

// PublicRDSCheck identifies publicly accessible RDS instances.
type PublicRDSCheck struct{}

func (c *PublicRDSCheck) Name() string {
	return "rds/public-instances"
}

func (c *PublicRDSCheck) Description() string {
	return "Detects RDS instances that are publicly accessible"
}

func (c *PublicRDSCheck) Severity() engine.Severity {
	return engine.SeverityCritical
}

func (c *PublicRDSCheck) RequiredIAMPermissions() []string {
	return []string{
		"rds:DescribeDBInstances",
	}
}

func (c *PublicRDSCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := rds.NewFromConfig(cfg.AWSConfig, func(o *rds.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	instPaginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
	for instPaginator.HasMorePages() {
		instResp, err := instPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing RDS instances: %w", err)
		}

		for _, instance := range instResp.DBInstances {
			if instance.DBInstanceIdentifier == nil {
				continue
			}

			dbID := *instance.DBInstanceIdentifier

			if instance.PubliclyAccessible != nil && *instance.PubliclyAccessible {
				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   *instance.DBInstanceArn,
					Region:       cfg.Region,
					Message:      fmt.Sprintf("RDS instance '%s' is publicly accessible", dbID),
					Remediation:  fmt.Sprintf("Make RDS instance private: aws rds modify-db-instance --db-instance-identifier %s --no-publicly-accessible --apply-immediately", dbID),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// UnencryptedRDSCheck identifies RDS instances without encryption at rest.
type UnencryptedRDSCheck struct{}

func (c *UnencryptedRDSCheck) Name() string {
	return "rds/unencrypted-instances"
}

func (c *UnencryptedRDSCheck) Description() string {
	return "Detects RDS instances without encryption at rest enabled"
}

func (c *UnencryptedRDSCheck) Severity() engine.Severity {
	return engine.SeverityHigh
}

func (c *UnencryptedRDSCheck) RequiredIAMPermissions() []string {
	return []string{
		"rds:DescribeDBInstances",
	}
}

func (c *UnencryptedRDSCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := rds.NewFromConfig(cfg.AWSConfig, func(o *rds.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	instPaginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
	for instPaginator.HasMorePages() {
		instResp, err := instPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing RDS instances: %w", err)
		}

		for _, instance := range instResp.DBInstances {
			if instance.DBInstanceIdentifier == nil {
				continue
			}

			dbID := *instance.DBInstanceIdentifier

			if instance.StorageEncrypted != nil && !*instance.StorageEncrypted {
				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   *instance.DBInstanceArn,
					Region:       cfg.Region,
					Message:      fmt.Sprintf("RDS instance '%s' does not have encryption at rest enabled", dbID),
					Remediation:  fmt.Sprintf("Create encrypted snapshot and restore: aws rds create-db-snapshot --db-instance-identifier %s --db-snapshot-identifier %s-snapshot && aws rds copy-db-snapshot --source-db-snapshot-identifier %s-snapshot --target-db-snapshot-identifier %s-encrypted --kms-key-id <key-id>", dbID, dbID, dbID, dbID),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// RDSBackupCheck identifies RDS instances without automated backups.
type RDSBackupCheck struct{}

func (c *RDSBackupCheck) Name() string {
	return "rds/no-backups"
}

func (c *RDSBackupCheck) Description() string {
	return "Detects RDS instances without automated backups enabled"
}

func (c *RDSBackupCheck) Severity() engine.Severity {
	return engine.SeverityHigh
}

func (c *RDSBackupCheck) RequiredIAMPermissions() []string {
	return []string{
		"rds:DescribeDBInstances",
	}
}

func (c *RDSBackupCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := rds.NewFromConfig(cfg.AWSConfig, func(o *rds.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	instPaginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
	for instPaginator.HasMorePages() {
		instResp, err := instPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing RDS instances: %w", err)
		}

		for _, instance := range instResp.DBInstances {
			if instance.DBInstanceIdentifier == nil {
				continue
			}

			dbID := *instance.DBInstanceIdentifier

			// Check if backup retention period is 0 (disabled) or less than 7 days
			if instance.BackupRetentionPeriod != nil {
				retention := *instance.BackupRetentionPeriod
				if retention == 0 {
					findings = append(findings, engine.Finding{
						CheckName:    c.Name(),
						Severity:     c.Severity(),
						ResourceID:   *instance.DBInstanceArn,
						Region:       cfg.Region,
						Message:      fmt.Sprintf("RDS instance '%s' has automated backups disabled", dbID),
						Remediation:  fmt.Sprintf("Enable automated backups: aws rds modify-db-instance --db-instance-identifier %s --backup-retention-period 7 --apply-immediately", dbID),
						DiscoveredAt: time.Now(),
					})
				} else if retention < 7 {
					findings = append(findings, engine.Finding{
						CheckName:    c.Name(),
						Severity:     engine.SeverityMedium,
						ResourceID:   *instance.DBInstanceArn,
						Region:       cfg.Region,
						Message:      fmt.Sprintf("RDS instance '%s' has backup retention period of only %d days (recommended: 7+)", dbID, retention),
						Remediation:  fmt.Sprintf("Increase backup retention: aws rds modify-db-instance --db-instance-identifier %s --backup-retention-period 7 --apply-immediately", dbID),
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return findings, nil
}

// RDSMultiAZCheck identifies RDS instances without Multi-AZ enabled.
type RDSMultiAZCheck struct{}

func (c *RDSMultiAZCheck) Name() string {
	return "rds/no-multi-az"
}

func (c *RDSMultiAZCheck) Description() string {
	return "Detects RDS instances without Multi-AZ deployment enabled"
}

func (c *RDSMultiAZCheck) Severity() engine.Severity {
	return engine.SeverityMedium
}

func (c *RDSMultiAZCheck) RequiredIAMPermissions() []string {
	return []string{
		"rds:DescribeDBInstances",
	}
}

func (c *RDSMultiAZCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := rds.NewFromConfig(cfg.AWSConfig, func(o *rds.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	instPaginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
	for instPaginator.HasMorePages() {
		instResp, err := instPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing RDS instances: %w", err)
		}

		for _, instance := range instResp.DBInstances {
			if instance.DBInstanceIdentifier == nil {
				continue
			}

			dbID := *instance.DBInstanceIdentifier

			if instance.MultiAZ != nil && !*instance.MultiAZ {
				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   *instance.DBInstanceArn,
					Region:       cfg.Region,
					Message:      fmt.Sprintf("RDS instance '%s' does not have Multi-AZ deployment enabled (single point of failure)", dbID),
					Remediation:  fmt.Sprintf("Enable Multi-AZ: aws rds modify-db-instance --db-instance-identifier %s --multi-az --apply-immediately", dbID),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// PublicRDSSnapshotsCheck identifies publicly shared RDS snapshots.
type PublicRDSSnapshotsCheck struct{}

func (c *PublicRDSSnapshotsCheck) Name() string {
	return "rds/public-snapshots"
}

func (c *PublicRDSSnapshotsCheck) Description() string {
	return "Detects RDS snapshots that are publicly shared"
}

func (c *PublicRDSSnapshotsCheck) Severity() engine.Severity {
	return engine.SeverityCritical
}

func (c *PublicRDSSnapshotsCheck) RequiredIAMPermissions() []string {
	return []string{
		"rds:DescribeDBSnapshots",
		"rds:DescribeDBSnapshotAttributes",
	}
}

func (c *PublicRDSSnapshotsCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := rds.NewFromConfig(cfg.AWSConfig, func(o *rds.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	snapshotsPaginator := rds.NewDescribeDBSnapshotsPaginator(client, &rds.DescribeDBSnapshotsInput{
		SnapshotType: nil, // All snapshots
	})

	for snapshotsPaginator.HasMorePages() {
		snapshotsResp, err := snapshotsPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing RDS snapshots: %w", err)
		}

		for _, snapshot := range snapshotsResp.DBSnapshots {
			if snapshot.DBSnapshotIdentifier == nil {
				continue
			}

			snapshotID := *snapshot.DBSnapshotIdentifier

			// Get snapshot attributes to check if it's public
			attrResp, err := client.DescribeDBSnapshotAttributes(ctx, &rds.DescribeDBSnapshotAttributesInput{
				DBSnapshotIdentifier: &snapshotID,
			})
			if err != nil {
				continue
			}

			if attrResp.DBSnapshotAttributesResult != nil {
				for _, attr := range attrResp.DBSnapshotAttributesResult.DBSnapshotAttributes {
					if attr.AttributeName != nil && *attr.AttributeName == "restore" {
						for _, value := range attr.AttributeValues {
							if value == "all" {
								findings = append(findings, engine.Finding{
									CheckName:    c.Name(),
									Severity:     c.Severity(),
									ResourceID:   *snapshot.DBSnapshotArn,
									Region:       cfg.Region,
									Message:      fmt.Sprintf("RDS snapshot '%s' is publicly shared", snapshotID),
									Remediation:  fmt.Sprintf("Make snapshot private: aws rds modify-db-snapshot-attribute --db-snapshot-identifier %s --attribute-name restore --values-to-remove all", snapshotID),
									DiscoveredAt: time.Now(),
								})
								break
							}
						}
					}
				}
			}
		}
	}

	return findings, nil
}
