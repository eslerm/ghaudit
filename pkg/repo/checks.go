// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"
	"fmt"

	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
)

// RepoCheck represents any repository check that can be run
type RepoCheck struct {
	CommandUse   string
	CommandShort string
	CheckFunc    func(context.Context, *github.Client, string, string) error
}

// repoChecks defines all available repository checks
var repoChecks = []RepoCheck{
	{
		CommandUse:   "secret-scanning",
		CommandShort: "Audit secret scanning settings.",
		CheckFunc: func(ctx context.Context, client *github.Client, org, repo string) error {
			return SecretScanning(ctx, client, org, repo, nil)
		},
	},
	{
		CommandUse:   "push-protection",
		CommandShort: "Audit secret scanning push protection settings.",
		CheckFunc: func(ctx context.Context, client *github.Client, org, repo string) error {
			return PushProtection(ctx, client, org, repo, nil)
		},
	},
	{
		CommandUse:   "secret-validity-checks",
		CommandShort: "Audit secret scanning validity checks settings.",
		CheckFunc: func(ctx context.Context, client *github.Client, org, repo string) error {
			return SecretValidityChecks(ctx, client, org, repo, nil)
		},
	},
	{
		CommandUse:   "vulnerability-alerts",
		CommandShort: "Audit vulnerability alerts (Dependabot) settings.",
		CheckFunc: func(ctx context.Context, client *github.Client, org, repo string) error {
			return VulnerabilityAlerts(ctx, client, org, repo, nil)
		},
	},
	{
		CommandUse:   "vulnerability-reporting",
		CommandShort: "Audit private vulnerability reporting settings.",
		CheckFunc: func(ctx context.Context, client *github.Client, org, repo string) error {
			return VulnerabilityReporting(ctx, client, org, repo, nil)
		},
	},
	{
		CommandUse:   "commit-signoff",
		CommandShort: "Audit web commit signoff requirements.",
		CheckFunc: func(ctx context.Context, client *github.Client, org, repo string) error {
			return CommitSignoff(ctx, client, org, repo, nil)
		},
	},
	{
		CommandUse:   "actions-enabled",
		CommandShort: "Check if GitHub Actions are enabled for the repository.",
		CheckFunc:    ActionsEnabled,
	},
	{
		CommandUse:   "deploy-keys",
		CommandShort: "Audit for usage of deploy keys.",
		CheckFunc:    DeployKeys,
	},
	{
		CommandUse:   "default-permissions",
		CommandShort: "Audit the default permissions.",
		CheckFunc:    DefaultWorkflowPermissions,
	},
	{
		CommandUse:   "non-provider-patterns",
		CommandShort: "Audit secret scanning for custom non-provider patterns.",
		CheckFunc:    NonProviderPatterns,
	},
}

// createRepoCommand creates a cobra command for a repository check
func createRepoCommand(githubClient *github.Client, org, repo string, check RepoCheck) *cobra.Command {
	return &cobra.Command{
		Use:           check.CommandUse,
		Short:         check.CommandShort,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return check.CheckFunc(cmd.Context(), githubClient, org, repo)
		},
	}
}

// SecretScanning checks if secret scanning is enabled
func SecretScanning(ctx context.Context, githubClient *github.Client, orgName, repoName string, cachedRepoData *github.Repository) error {
	repository, err := getRepository(ctx, githubClient, orgName, repoName, cachedRepoData)
	if err != nil {
		return err
	}

	checkSecurityFeature(
		repository,
		func(sa *github.SecurityAndAnalysis) string {
			if sa.SecretScanning == nil {
				return ""
			}
			return sa.SecretScanning.GetStatus()
		},
		orgName,
		repoName,
		"Secret scanning",
	)

	return nil
}

// PushProtection checks if secret scanning push protection is enabled
func PushProtection(ctx context.Context, githubClient *github.Client, orgName, repoName string, cachedRepoData *github.Repository) error {
	repository, err := getRepository(ctx, githubClient, orgName, repoName, cachedRepoData)
	if err != nil {
		return err
	}

	checkSecurityFeature(
		repository,
		func(sa *github.SecurityAndAnalysis) string {
			if sa.SecretScanningPushProtection == nil {
				return ""
			}
			return sa.SecretScanningPushProtection.GetStatus()
		},
		orgName,
		repoName,
		"Secret scanning push protection",
	)

	return nil
}

// SecretValidityChecks checks if secret validity verification is enabled
func SecretValidityChecks(ctx context.Context, githubClient *github.Client, orgName, repoName string, cachedRepoData *github.Repository) error {
	repository, err := getRepository(ctx, githubClient, orgName, repoName, cachedRepoData)
	if err != nil {
		return err
	}

	checkSecurityFeature(
		repository,
		func(sa *github.SecurityAndAnalysis) string {
			if sa.SecretScanningValidityChecks == nil {
				return ""
			}
			return sa.SecretScanningValidityChecks.GetStatus()
		},
		orgName,
		repoName,
		"Secret validity checks",
	)

	return nil
}

// VulnerabilityAlerts checks if Dependabot security updates are enabled
func VulnerabilityAlerts(ctx context.Context, githubClient *github.Client, orgName, repoName string, cachedRepoData *github.Repository) error {
	repository, err := getRepository(ctx, githubClient, orgName, repoName, cachedRepoData)
	if err != nil {
		return err
	}

	checkSecurityFeature(
		repository,
		func(sa *github.SecurityAndAnalysis) string {
			if sa.DependabotSecurityUpdates == nil {
				return ""
			}
			return sa.DependabotSecurityUpdates.GetStatus()
		},
		orgName,
		repoName,
		"Vulnerability alerts (Dependabot security updates)",
	)

	return nil
}

// VulnerabilityReporting checks if private vulnerability reporting is enabled
func VulnerabilityReporting(ctx context.Context, githubClient *github.Client, orgName, repoName string, cachedRepoData *github.Repository) error {
	// First check if the repository is public
	repository, err := getRepository(ctx, githubClient, orgName, repoName, cachedRepoData)
	if err != nil {
		gherror.AddGlobalResult(gherror.ErrorResult("Private vulnerability reporting", orgName, repoName, err))
		return err
	}

	// Skip private repositories as PVR doesn't apply to them
	if repository.GetPrivate() {
		gherror.AddGlobalResult(gherror.Skip("Private vulnerability reporting", orgName, repoName, "Not applicable to private repos"))
		return nil
	}

	// Check if private vulnerability reporting is enabled using the dedicated endpoint
	url := fmt.Sprintf("repos/%s/%s/private-vulnerability-reporting", orgName, repoName)

	request, err := githubClient.NewRequest("GET", url, nil)
	if err != nil {
		gherror.AddGlobalResult(gherror.ErrorResult("Private vulnerability reporting", orgName, repoName, err))
		return err
	}

	var result struct {
		Enabled bool `json:"enabled"`
	}

	_, err = githubClient.Do(ctx, request, &result)
	if err != nil {
		wrappedErr := gherror.WrapAPIError(err, "checking vulnerability reporting", orgName, repoName)
		gherror.AddGlobalResult(gherror.ErrorResult("Private vulnerability reporting", orgName, repoName, wrappedErr))
		return wrappedErr
	}

	// Check if private vulnerability reporting is enabled
	if !result.Enabled {
		message := fmt.Sprintf("Private vulnerability reporting disabled in %s/%s", orgName, repoName)
		res := gherror.Fail("Private vulnerability reporting", orgName, repoName, "error", message)
		res.Value = result.Enabled
		gherror.AddGlobalResult(res)
	} else {
		res := gherror.Pass("Private vulnerability reporting", orgName, repoName)
		res.Value = result.Enabled
		gherror.AddGlobalResult(res)
	}

	return nil
}

// CommitSignoff checks if web commit signoff is required
func CommitSignoff(ctx context.Context, githubClient *github.Client, orgName, repoName string, cachedRepoData *github.Repository) error {
	repository, err := getRepository(ctx, githubClient, orgName, repoName, cachedRepoData)
	if err != nil {
		return err
	}

	// Check if web commit signoff is required
	// This ensures commits made via the web interface are signed off
	if repository.WebCommitSignoffRequired != nil && repository.GetWebCommitSignoffRequired() {
		res := gherror.Pass("Web commit signoff", orgName, repoName)
		res.Value = true
		gherror.AddGlobalResult(res)
	} else {
		message := fmt.Sprintf("Web commit signoff disabled in %s/%s", orgName, repoName)
		res := gherror.Fail("Web commit signoff", orgName, repoName, "error", message)
		res.Value = false
		gherror.AddGlobalResult(res)
	}

	return nil
}

// ActionsEnabled checks if GitHub Actions are enabled for the repository
func ActionsEnabled(ctx context.Context, githubClient *github.Client, org, repo string) error {
	enabled, err := IsActionsEnabled(ctx, githubClient, org, repo)
	if err != nil {
		gherror.AddGlobalResult(gherror.ErrorResult("Actions enabled", org, repo, err))
		return err
	}

	if enabled {
		res := gherror.Pass("Actions enabled", org, repo)
		res.Value = true
		gherror.AddGlobalResult(res)
	} else {
		message := fmt.Sprintf("Actions disabled in %s/%s", org, repo)
		res := gherror.Fail("Actions enabled", org, repo, "error", message)
		res.Value = false
		gherror.AddGlobalResult(res)
	}

	return nil
}

// IsActionsEnabled checks if GitHub Actions are enabled for a repository
func IsActionsEnabled(ctx context.Context, githubClient *github.Client, org, repo string) (bool, error) {
	var actionsPermissions *github.ActionsPermissionsRepository
	var resp *github.Response

	err := gherror.WithRetry(ctx, "get actions permissions", func() error {
		var err error
		actionsPermissions, resp, err = githubClient.Repositories.GetActionsPermissions(ctx, org, repo)
		return err
	})

	if err != nil {
		// 404 means Actions is not enabled for the repository
		if resp != nil && resp.StatusCode == 404 {
			return false, nil
		}
		return false, gherror.WrapAPIError(err, "fetching actions permissions", org, repo)
	}

	return actionsPermissions.GetEnabled(), nil
}

// DeployKeys checks if deploy keys are configured for the repository
func DeployKeys(ctx context.Context, githubClient *github.Client, org, repo string) error {
	page := 0

	var allKeys []*github.Key
	for {
		var keys []*github.Key
		var resp *github.Response

		err := gherror.WithRetry(ctx, fmt.Sprintf("list deploy keys page %d", page), func() error {
			var err error
			keys, resp, err = githubClient.Repositories.ListKeys(ctx, org, repo, &github.ListOptions{
				Page:    page,
				PerPage: 100,
			})
			return err
		})

		if err != nil {
			wrappedErr := gherror.WrapAPIError(err, "listing deploy keys", org, repo)
			gherror.AddGlobalResult(gherror.ErrorResult("Deploy keys", org, repo, wrappedErr))
			return wrappedErr
		}

		allKeys = append(allKeys, keys...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	if len(allKeys) > 0 {
		message := fmt.Sprintf("Deploy keys found in %s/%s: %d keys configured", org, repo, len(allKeys))
		res := gherror.Fail("Deploy keys", org, repo, "error", message)
		res.Value = len(allKeys)
		gherror.AddGlobalResult(res)
	} else {
		res := gherror.Pass("Deploy keys", org, repo)
		res.Value = 0
		gherror.AddGlobalResult(res)
	}

	return nil
}

// DefaultWorkflowPermissions checks the default GitHub Actions workflow permissions
func DefaultWorkflowPermissions(ctx context.Context, githubClient *github.Client, org, repo string) error {
	var defaultWorkflowPermissions *github.DefaultWorkflowPermissionRepository
	var resp *github.Response

	err := gherror.WithRetry(ctx, "get default workflow permissions", func() error {
		var err error
		defaultWorkflowPermissions, resp, err = githubClient.Repositories.GetDefaultWorkflowPermissions(ctx, org, repo)
		return err
	})

	if err != nil {
		// Check for 404 specifically - actions might not be enabled
		if resp != nil && resp.StatusCode == 404 {
			gherror.AddGlobalResult(gherror.Skip("Default workflow permissions", org, repo, "Actions not enabled"))
			return nil
		}
		wrappedErr := gherror.WrapAPIError(err, "fetching default workflow permissions", org, repo)
		gherror.AddGlobalResult(gherror.ErrorResult("Default workflow permissions", org, repo, wrappedErr))
		return wrappedErr
	}

	permissions := defaultWorkflowPermissions.GetDefaultWorkflowPermissions()
	canApprove := defaultWorkflowPermissions.GetCanApprovePullRequestReviews()

	// Check if permissions are restricted (read-only is safer than write)
	if permissions == "read" {
		res := gherror.Pass("Default workflow permissions", org, repo)
		res.Value = map[string]interface{}{
			"permissions":                     permissions,
			"can_approve_pull_request_reviews": canApprove,
		}
		gherror.AddGlobalResult(res)
	} else {
		message := fmt.Sprintf("Default workflow permissions too broad in %s/%s: %s", org, repo, permissions)
		res := gherror.Fail("Default workflow permissions", org, repo, "error", message)
		res.Value = map[string]interface{}{
			"permissions":                     permissions,
			"can_approve_pull_request_reviews": canApprove,
		}
		gherror.AddGlobalResult(res)
	}

	return nil
}

// NonProviderPatterns checks if custom non-provider patterns are configured for secret scanning
func NonProviderPatterns(ctx context.Context, githubClient *github.Client, org, repo string) error {
	// API: GET /repos/{owner}/{repo}/secret-scanning/non-provider-patterns
	url := fmt.Sprintf("repos/%s/%s/secret-scanning/non-provider-patterns", org, repo)

	request, err := githubClient.NewRequest("GET", url, nil)
	if err != nil {
		gherror.AddGlobalResult(gherror.ErrorResult("Non-provider patterns", org, repo, err))
		return err
	}

	var patterns []interface{}
	resp, err := githubClient.Do(ctx, request, &patterns)
	if err != nil {
		// 404 means secret scanning is not enabled
		if resp != nil && resp.StatusCode == 404 {
			gherror.AddGlobalResult(gherror.Skip("Non-provider patterns", org, repo, "Secret scanning not enabled"))
			return nil
		}
		wrappedErr := gherror.WrapAPIError(err, "checking non-provider patterns", org, repo)
		gherror.AddGlobalResult(gherror.ErrorResult("Non-provider patterns", org, repo, wrappedErr))
		return wrappedErr
	}

	// Check if any custom patterns are configured
	if len(patterns) > 0 {
		res := gherror.Pass("Non-provider patterns", org, repo)
		res.Value = len(patterns)
		gherror.AddGlobalResult(res)
	} else {
		message := fmt.Sprintf("No custom patterns configured in %s/%s", org, repo)
		res := gherror.Fail("Non-provider patterns", org, repo, "warning", message)
		res.Value = 0
		gherror.AddGlobalResult(res)
	}

	return nil
}