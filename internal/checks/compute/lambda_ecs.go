// Package compute implements Lambda and ECS security checks.
package compute

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/yourorg/infraguard/internal/engine"
)

// LambdaSecretsInEnvCheck identifies Lambda functions with secrets in environment variables.
type LambdaSecretsInEnvCheck struct{}

func (c *LambdaSecretsInEnvCheck) Name() string {
	return "lambda/secrets-in-env"
}

func (c *LambdaSecretsInEnvCheck) Description() string {
	return "Detects Lambda functions with potential secrets in environment variables"
}

func (c *LambdaSecretsInEnvCheck) Severity() engine.Severity {
	return engine.SeverityHigh
}

func (c *LambdaSecretsInEnvCheck) RequiredIAMPermissions() []string {
	return []string{
		"lambda:ListFunctions",
		"lambda:GetFunction",
	}
}

func (c *LambdaSecretsInEnvCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := lambda.NewFromConfig(cfg.AWSConfig, func(o *lambda.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	secretPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(key|secret|password|token|api|auth)`),
	}

	funcPaginator := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
	for funcPaginator.HasMorePages() {
		funcResp, err := funcPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing Lambda functions: %w", err)
		}

		for _, function := range funcResp.Functions {
			if function.FunctionName == nil {
				continue
			}

			funcName := *function.FunctionName

			// Check environment variables
			if function.Environment != nil && function.Environment.Variables != nil {
				for key := range function.Environment.Variables {
					for _, pattern := range secretPatterns {
						if pattern.MatchString(key) {
							findings = append(findings, engine.Finding{
								CheckName:    c.Name(),
								Severity:     c.Severity(),
								ResourceID:   *function.FunctionArn,
								Region:       cfg.Region,
								Message:      fmt.Sprintf("Lambda function '%s' has environment variable '%s' that may contain secrets", funcName, key),
								Remediation:  fmt.Sprintf("Move secrets to AWS Secrets Manager or Parameter Store and reference them in the function code instead of environment variables"),
								DiscoveredAt: time.Now(),
							})
							break
						}
					}
				}
			}
		}
	}

	return findings, nil
}

// LambdaDeprecatedRuntimeCheck identifies Lambda functions using deprecated runtimes.
type LambdaDeprecatedRuntimeCheck struct{}

func (c *LambdaDeprecatedRuntimeCheck) Name() string {
	return "lambda/deprecated-runtime"
}

func (c *LambdaDeprecatedRuntimeCheck) Description() string {
	return "Detects Lambda functions using deprecated runtimes"
}

func (c *LambdaDeprecatedRuntimeCheck) Severity() engine.Severity {
	return engine.SeverityHigh
}

func (c *LambdaDeprecatedRuntimeCheck) RequiredIAMPermissions() []string {
	return []string{
		"lambda:ListFunctions",
	}
}

func (c *LambdaDeprecatedRuntimeCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := lambda.NewFromConfig(cfg.AWSConfig, func(o *lambda.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	deprecatedRuntimes := map[string]bool{
		"nodejs14.x":  true,
		"nodejs12.x":  true,
		"python3.7":   true,
		"python3.6":   true,
		"ruby2.7":     true,
		"dotnetcore3.1": true,
		"go1.x":       true,
	}

	funcPaginator := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
	for funcPaginator.HasMorePages() {
		funcResp, err := funcPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing Lambda functions: %w", err)
		}

		for _, function := range funcResp.Functions {
			if function.FunctionName == nil {
				continue
			}

			funcName := *function.FunctionName
			runtime := string(function.Runtime)

			if deprecatedRuntimes[runtime] {
				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   *function.FunctionArn,
					Region:       cfg.Region,
					Message:      fmt.Sprintf("Lambda function '%s' uses deprecated runtime '%s'", funcName, runtime),
					Remediation:  fmt.Sprintf("Upgrade to a supported runtime version for function '%s'", funcName),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// ECSPrivilegedContainersCheck identifies ECS tasks with privileged containers.
type ECSPrivilegedContainersCheck struct{}

func (c *ECSPrivilegedContainersCheck) Name() string {
	return "ecs/privileged-containers"
}

func (c *ECSPrivilegedContainersCheck) Description() string {
	return "Detects ECS task definitions with privileged containers"
}

func (c *ECSPrivilegedContainersCheck) Severity() engine.Severity {
	return engine.SeverityCritical
}

func (c *ECSPrivilegedContainersCheck) RequiredIAMPermissions() []string {
	return []string{
		"ecs:ListTaskDefinitions",
		"ecs:DescribeTaskDefinition",
	}
}

func (c *ECSPrivilegedContainersCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := ecs.NewFromConfig(cfg.AWSConfig, func(o *ecs.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	// List task definitions
	taskDefsPaginator := ecs.NewListTaskDefinitionsPaginator(client, &ecs.ListTaskDefinitionsInput{
		Status: "ACTIVE",
	})

	for taskDefsPaginator.HasMorePages() {
		taskDefsResp, err := taskDefsPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing ECS task definitions: %w", err)
		}

		for _, taskDefArn := range taskDefsResp.TaskDefinitionArns {
			// Describe task definition to check containers
			taskDefResp, err := client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
				TaskDefinition: &taskDefArn,
			})
			if err != nil {
				continue
			}

			if taskDefResp.TaskDefinition == nil {
				continue
			}

			taskDef := taskDefResp.TaskDefinition

			// Check each container definition
			for _, container := range taskDef.ContainerDefinitions {
				if container.Privileged != nil && *container.Privileged {
					containerName := "unnamed"
					if container.Name != nil {
						containerName = *container.Name
					}

					findings = append(findings, engine.Finding{
						CheckName:    c.Name(),
						Severity:     c.Severity(),
						ResourceID:   *taskDef.TaskDefinitionArn,
						Region:       cfg.Region,
						Message:      fmt.Sprintf("ECS task definition '%s' has privileged container '%s'", taskDefArn, containerName),
						Remediation:  fmt.Sprintf("Remove privileged mode from container '%s' in task definition", containerName),
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return findings, nil
}

// ECRLifecyclePolicyCheck identifies ECR repositories without lifecycle policies.
type ECRLifecyclePolicyCheck struct{}

func (c *ECRLifecyclePolicyCheck) Name() string {
	return "ecr/no-lifecycle-policy"
}

func (c *ECRLifecyclePolicyCheck) Description() string {
	return "Detects ECR repositories without lifecycle policies (unbounded image accumulation)"
}

func (c *ECRLifecyclePolicyCheck) Severity() engine.Severity {
	return engine.SeverityLow
}

func (c *ECRLifecyclePolicyCheck) RequiredIAMPermissions() []string {
	return []string{
		"ecr:DescribeRepositories",
		"ecr:GetLifecyclePolicy",
	}
}

func (c *ECRLifecyclePolicyCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := ecr.NewFromConfig(cfg.AWSConfig, func(o *ecr.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	reposPaginator := ecr.NewDescribeRepositoriesPaginator(client, &ecr.DescribeRepositoriesInput{})
	for reposPaginator.HasMorePages() {
		reposResp, err := reposPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing ECR repositories: %w", err)
		}

		for _, repo := range reposResp.Repositories {
			if repo.RepositoryName == nil {
				continue
			}

			repoName := *repo.RepositoryName

			// Check if repository has a lifecycle policy
			_, err := client.GetLifecyclePolicy(ctx, &ecr.GetLifecyclePolicyInput{
				RepositoryName: &repoName,
			})

			if err != nil {
				// No lifecycle policy
				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   *repo.RepositoryArn,
					Region:       cfg.Region,
					Message:      fmt.Sprintf("ECR repository '%s' has no lifecycle policy (unbounded image accumulation)", repoName),
					Remediation:  fmt.Sprintf("Create lifecycle policy: aws ecr put-lifecycle-policy --repository-name %s --lifecycle-policy-text file://policy.json", repoName),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// ECSHostNetworkModeCheck identifies ECS tasks using host network mode.
type ECSHostNetworkModeCheck struct{}

func (c *ECSHostNetworkModeCheck) Name() string {
	return "ecs/host-network-mode"
}

func (c *ECSHostNetworkModeCheck) Description() string {
	return "Detects ECS task definitions using host network mode"
}

func (c *ECSHostNetworkModeCheck) Severity() engine.Severity {
	return engine.SeverityHigh
}

func (c *ECSHostNetworkModeCheck) RequiredIAMPermissions() []string {
	return []string{
		"ecs:ListTaskDefinitions",
		"ecs:DescribeTaskDefinition",
	}
}

func (c *ECSHostNetworkModeCheck) Run(ctx context.Context, cfg engine.CheckConfig) ([]engine.Finding, error) {
	client := ecs.NewFromConfig(cfg.AWSConfig, func(o *ecs.Options) {
		o.Region = cfg.Region
	})
	findings := []engine.Finding{}

	taskDefsPaginator := ecs.NewListTaskDefinitionsPaginator(client, &ecs.ListTaskDefinitionsInput{
		Status: "ACTIVE",
	})

	for taskDefsPaginator.HasMorePages() {
		taskDefsResp, err := taskDefsPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing ECS task definitions: %w", err)
		}

		for _, taskDefArn := range taskDefsResp.TaskDefinitionArns {
			taskDefResp, err := client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
				TaskDefinition: &taskDefArn,
			})
			if err != nil {
				continue
			}

			if taskDefResp.TaskDefinition == nil {
				continue
			}

			taskDef := taskDefResp.TaskDefinition

			if strings.ToLower(string(taskDef.NetworkMode)) == "host" {
				findings = append(findings, engine.Finding{
					CheckName:    c.Name(),
					Severity:     c.Severity(),
					ResourceID:   *taskDef.TaskDefinitionArn,
					Region:       cfg.Region,
					Message:      fmt.Sprintf("ECS task definition '%s' uses host network mode (security risk)", taskDefArn),
					Remediation:  "Change network mode to 'bridge' or 'awsvpc' for better isolation",
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}
