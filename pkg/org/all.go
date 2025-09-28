// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"

	"github.com/chainguard-dev/ghaudit/pkg/config"
	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/chainguard-dev/ghaudit/pkg/repo"
)

func all(githubClient *github.Client, org *string) *cobra.Command {
	var includeArchived bool
	var limitedAccess bool
	var errorsOnly bool

	cmd := &cobra.Command{
		Use:           "all",
		Short:         "Run all organization security audits",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runChecks(cmd.Context(), githubClient, *org, true, includeArchived, limitedAccess, errorsOnly)
		},
	}

	cmd.Flags().BoolVar(&includeArchived, "include-archived", false, "Include archived repositories in audit")
	cmd.Flags().BoolVar(&limitedAccess, "limited-access", false, "Skip repositories that return 403 errors (for limited access scenarios)")
	cmd.Flags().BoolVar(&errorsOnly, "errors-only", false, "Show only errors, suppress informational messages")

	return cmd
}

func runChecks(ctx context.Context, githubClient *github.Client, orgName string, includeAll bool, includeArchived bool, limitedAccess bool, errorsOnly bool) error {
	// Add errorsOnly to context for downstream functions
	ctx = config.WithErrorsOnly(ctx, errorsOnly)

	// Initialize global result collector (always JSON)
	gherror.InitGlobalResultSet("json")

	// Fetch organization data once with retry
	var org *github.Organization
	err := gherror.WithRetry(ctx, "fetch organization "+orgName, func() error {
		var err error
		org, _, err = githubClient.Organizations.Get(ctx, orgName)
		return err
	})
	if err != nil {
		return gherror.WrapAPIError(err, "fetching organization data", orgName, "")
	}

	// Run all org-level checks with the cached org data
	runOrgLevelChecks(ctx, org, orgName, includeAll)

	// Fetch repos once with pagination
	var allRepos []*github.Repository
	opts := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		var repos []*github.Repository
		var resp *github.Response

		err := gherror.WithRetry(ctx, fmt.Sprintf("list repositories page %d", opts.Page), func() error {
			var err error
			repos, resp, err = githubClient.Repositories.ListByOrg(ctx, orgName, opts)
			return err
		})
		if err != nil {
			return gherror.WrapAPIError(err, "listing repositories", orgName, "")
		}
		allRepos = append(allRepos, repos...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	// Run repo-level checks in parallel with context cancellation on first error
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // Limit concurrent API calls
	errChan := make(chan error, 1) // Buffer of 1 to avoid goroutine leak

	for _, repository := range allRepos {
		repo := repository

		// Skip archived repositories unless explicitly included
		if !includeArchived && repo.GetArchived() {
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()

			// Check if context is cancelled before acquiring semaphore
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			// Check context again before executing
			if ctx.Err() != nil {
				return
			}

			if err := runRepoChecks(ctx, githubClient, orgName, *repo.Name, includeAll, limitedAccess, errorsOnly); err != nil {
				// Send error and cancel all other operations
				select {
				case errChan <- fmt.Errorf("failed checking %s/%s: %w", orgName, *repo.Name, err):
					cancel() // Cancel all other goroutines
				default:
					// Another error was already sent
				}
			}
		}()
	}

	wg.Wait()

	// Check if any error occurred
	select {
	case err := <-errChan:
		// Always output JSON results even on error
		if rs := gherror.GetGlobalResultSet(); rs != nil {
			if outputErr := rs.Output(); outputErr != nil {
				// Return the output error if it occurs
				return fmt.Errorf("failed to output results: %w", outputErr)
			}
		}
		return err
	default:
		// Always output JSON results
		if rs := gherror.GetGlobalResultSet(); rs != nil {
			return rs.Output()
		}
		return nil
	}
}

func runOrgLevelChecks(_ context.Context, org *github.Organization, orgName string, includeAll bool) {
	// Two-factor authentication check (excluded in standard mode)
	if includeAll {
		if !org.GetTwoFactorRequirementEnabled() {
			message := "Two-factor authentication not required"
			gherror.AddGlobalResult(gherror.Fail("Two-factor authentication", orgName, "", "error", message))
		} else {
			gherror.AddGlobalResult(gherror.Pass("Two-factor authentication", orgName, ""))
		}
	}

	// Member repo creation check
	if org.GetMembersCanCreateRepos() {
		message := "Members can create repositories (should require github-iac)"
		gherror.AddGlobalResult(gherror.Fail("Members can create repositories", orgName, "", "error", message))
	} else {
		gherror.AddGlobalResult(gherror.Pass("Members can create repositories", orgName, ""))
	}

	// External collaborator invite check (excluded in standard mode)
	if includeAll {
		if org.GetMembersCanInviteOutsideCollaborators() {
			message := "Members can invite outside collaborators (should be disabled for production orgs)"
			gherror.AddGlobalResult(gherror.Fail("External collaborator invites", orgName, "", "error", message))
		} else {
			gherror.AddGlobalResult(gherror.Pass("External collaborator invites", orgName, ""))
		}
	}

	// Default repository permissions check
	defaultPerm := org.GetDefaultRepoPermission()
	if defaultPerm == "write" || defaultPerm == "admin" {
		message := fmt.Sprintf("Organization members have '%s' access to all repositories in %s by default (should be 'read' or 'none')", defaultPerm, orgName)
		result := gherror.Fail("Default member permissions", orgName, "", "error", message)
		result.Value = defaultPerm
		gherror.AddGlobalResult(result)
	} else {
		result := gherror.Pass("Default member permissions", orgName, "")
		result.Value = defaultPerm
		gherror.AddGlobalResult(result)
	}
}

// checkHelper wraps common error handling logic
func checkHelper(err error, checkName string, limitedAccess bool) error {
	if err == nil {
		return nil
	}
	if limitedAccess && gherror.Is403(err) {
		return nil // Skip this check silently in limited access mode
	}
	return fmt.Errorf("%s check failed: %w", checkName, err)
}

func runRepoChecks(ctx context.Context, githubClient *github.Client, orgName, repoName string, includeAll bool, limitedAccess bool, errorsOnly bool) error {
	// Fetch all repo data in a single API call
	repoData, _, err := githubClient.Repositories.Get(ctx, orgName, repoName)
	if err != nil {
		if limitedAccess && gherror.Is403(err) {
			return nil // Skip this repo silently in limited access mode
		}
		return gherror.WrapAPIError(err, "fetching repository data", orgName, repoName)
	}

	// Check if Actions are enabled - only in 'all' mode as disabled Actions is secure
	actionsEnabled := true // Assume enabled by default
	if includeAll {
		enabled, err := repo.IsActionsEnabled(ctx, githubClient, orgName, repoName)
		if err := checkHelper(err, "actions enabled", limitedAccess); err != nil {
			return err
		}
		actionsEnabled = enabled
		// No console output in JSON mode
	}

	// Check default workflow permissions only if Actions are enabled
	if actionsEnabled {
		if err := checkHelper(repo.DefaultWorkflowPermissions(ctx, githubClient, orgName, repoName), "default workflow permissions", limitedAccess); err != nil {
			return err
		}
	}

	// Check deploy keys - still needs its own API call
	if err := checkHelper(repo.DeployKeys(ctx, githubClient, orgName, repoName), "deploy keys", limitedAccess); err != nil {
		return err
	}

	// Check vulnerability reporting - only for public repos and only in 'all' mode
	// Private vulnerability reporting is only available for public repositories
	if includeAll && !repoData.GetPrivate() {
		if err := checkHelper(repo.VulnerabilityReporting(ctx, githubClient, orgName, repoName, repoData), "vulnerability reporting", limitedAccess); err != nil {
			return err
		}
	}

	// Check vulnerability alerts (Dependabot) - pass pre-fetched repository data
	if err := checkHelper(repo.VulnerabilityAlerts(ctx, githubClient, orgName, repoName, repoData), "vulnerability alerts", limitedAccess); err != nil {
		return err
	}

	// Check commit signoff (excluded in standard mode) - pass pre-fetched repository data
	if includeAll {
		if err := checkHelper(repo.CommitSignoff(ctx, githubClient, orgName, repoName, repoData), "commit signoff", limitedAccess); err != nil {
			return err
		}
	}

	// Check secret scanning - pass pre-fetched repository data
	if err := checkHelper(repo.SecretScanning(ctx, githubClient, orgName, repoName, repoData), "secret scanning", limitedAccess); err != nil {
		return err
	}

	// Check push protection (excluded in standard mode) - pass pre-fetched repository data
	if includeAll {
		if err := checkHelper(repo.PushProtection(ctx, githubClient, orgName, repoName, repoData), "push protection", limitedAccess); err != nil {
			return err
		}
	}

	// Check validity checks - pass pre-fetched repository data
	if err := checkHelper(repo.SecretValidityChecks(ctx, githubClient, orgName, repoName, repoData), "secret validity checks", limitedAccess); err != nil {
		return err
	}

	// Non-provider patterns (excluded in standard mode)
	if includeAll {
		if err := checkHelper(repo.NonProviderPatterns(ctx, githubClient, orgName, repoName), "non-provider patterns", limitedAccess); err != nil {
			return err
		}
	}

	return nil
}
