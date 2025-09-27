// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"fmt"
	"sync"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/chainguard-dev/ghaudit/pkg/repo"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

func all(githubClient *github.Client, org *string) *cobra.Command {
	var includeArchived bool

	cmd := &cobra.Command{
		Use:           "all",
		Short:         "Run all organization security audits",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runChecks(cmd.Context(), githubClient, *org, true, includeArchived)
		},
	}

	cmd.Flags().BoolVar(&includeArchived, "include-archived", false, "Include archived repositories in audit")

	return cmd
}

func standard(githubClient *github.Client, org *string) *cobra.Command {
	var includeArchived bool

	cmd := &cobra.Command{
		Use:           "standard",
		Short:         "Run standard organization security audits (excludes PVR, non-provider patterns, 2FA, external collaborators, commit signoff, and push protection)",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runChecks(cmd.Context(), githubClient, *org, false, includeArchived)
		},
	}

	cmd.Flags().BoolVar(&includeArchived, "include-archived", false, "Include archived repositories in audit")

	return cmd
}

func runChecks(ctx context.Context, githubClient *github.Client, orgName string, includeAll bool, includeArchived bool) error {
	// Fetch organization data once
	org, _, err := githubClient.Organizations.Get(ctx, orgName)
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
		repos, resp, err := githubClient.Repositories.ListByOrg(ctx, orgName, opts)
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

			if err := runRepoChecks(ctx, githubClient, orgName, *repo.Name, includeAll); err != nil {
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
		return err
	default:
		return nil
	}
}

func runOrgLevelChecks(ctx context.Context, org *github.Organization, orgName string, includeAll bool) {
	// Two-factor authentication check (excluded in standard mode)
	if includeAll && !org.GetTwoFactorRequirementEnabled() {
		errTwoFactorDisabled.Emit("Two-factor authentication not required in %s", orgName)
	}

	// Member repo creation check
	if org.GetMembersCanCreateRepos() {
		errMembersCanCreateRepos.Emit("Members can create repositories in %s (should require github-iac)", orgName)
	}

	// External collaborator invite check (excluded in standard mode)
	if includeAll && org.GetMembersCanInviteOutsideCollaborators() {
		errExternalCollaboratorInvite.Emit("Members can invite outside collaborators in %s (should be disabled for production orgs)", orgName)
	}

	// Default repository permissions check
	defaultPerm := org.GetDefaultRepoPermission()
	if defaultPerm == "write" || defaultPerm == "admin" {
		gherror.New("Elevated default member permissions").Emit("Organization members have '%s' access to all repositories in %s by default (should be 'read' or 'none')", defaultPerm, orgName)
	}
}

func runRepoChecks(ctx context.Context, githubClient *github.Client, orgName, repoName string, includeAll bool) error {
	// Fetch all repo data in a single API call
	repoData, _, err := githubClient.Repositories.Get(ctx, orgName, repoName)
	if err != nil {
		return gherror.WrapAPIError(err, "fetching repository data", orgName, repoName)
	}

	// Check default workflow permissions - still needs its own API call
	if err := repo.DefaultPermissions(ctx, githubClient, orgName, repoName); err != nil {
		return fmt.Errorf("default permissions check failed: %w", err)
	}

	// Check deploy keys - still needs its own API call
	if err := repo.DeployKeys(ctx, githubClient, orgName, repoName); err != nil {
		return fmt.Errorf("deploy keys check failed: %w", err)
	}

	// Check vulnerability reporting - only for public repos and only in 'all' mode
	// Private vulnerability reporting is only available for public repositories
	if includeAll && !repoData.GetPrivate() {
		if err := repo.VulnerabilityReporting(ctx, githubClient, orgName, repoName, repoData); err != nil {
			return fmt.Errorf("vulnerability reporting check failed: %w", err)
		}
	}

	// Check vulnerability alerts (Dependabot) - pass pre-fetched repository data
	if err := repo.VulnerabilityAlerts(ctx, githubClient, orgName, repoName, repoData); err != nil {
		return fmt.Errorf("vulnerability alerts check failed: %w", err)
	}

	// Check commit signoff (excluded in standard mode) - pass pre-fetched repository data
	if includeAll {
		if err := repo.CommitSignoff(ctx, githubClient, orgName, repoName, repoData); err != nil {
			return fmt.Errorf("commit signoff check failed: %w", err)
		}
	}

	// Check secret scanning - pass pre-fetched repository data
	if err := repo.SecretScanning(ctx, githubClient, orgName, repoName, repoData); err != nil {
		return fmt.Errorf("secret scanning check failed: %w", err)
	}

	// Check push protection (excluded in standard mode) - pass pre-fetched repository data
	if includeAll {
		if err := repo.PushProtection(ctx, githubClient, orgName, repoName, repoData); err != nil {
			return fmt.Errorf("push protection check failed: %w", err)
		}
	}

	// Check validity checks - pass pre-fetched repository data
	if err := repo.SecretValidityChecks(ctx, githubClient, orgName, repoName, repoData); err != nil {
		return fmt.Errorf("secret validity checks failed: %w", err)
	}

	// Non-provider patterns (excluded in standard mode)
	if includeAll {
		if err := repo.NonProviderPatterns(ctx, githubClient, orgName, repoName); err != nil {
			return fmt.Errorf("non-provider patterns check failed: %w", err)
		}
	}

	return nil
}
