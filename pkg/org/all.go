// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"sync"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/chainguard-dev/ghaudit/pkg/repo"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

func all(ghc *github.Client, org *string) *cobra.Command {
	return &cobra.Command{
		Use:           "all",
		Short:         "Run all organization security audits",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runChecks(cmd.Context(), ghc, *org, true)
		},
	}
}

func standard(ghc *github.Client, org *string) *cobra.Command {
	return &cobra.Command{
		Use:           "standard",
		Short:         "Run standard organization security audits (excludes PVR, non-provider patterns, 2FA, external collaborators, commit signoff, and push protection)",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runChecks(cmd.Context(), ghc, *org, false)
		},
	}
}

func runChecks(ctx context.Context, ghc *github.Client, orgName string, includeAll bool) error {
	// Fetch organization data once
	org, _, err := ghc.Organizations.Get(ctx, orgName)
	if err != nil {
		return err
	}

	// Run all org-level checks with the cached org data
	runOrgLevelChecks(ctx, org, orgName, includeAll)

	// Fetch repos once with pagination
	var allRepos []*github.Repository
	opts := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		repos, resp, err := ghc.Repositories.ListByOrg(ctx, orgName, opts)
		if err != nil {
			return err
		}
		allRepos = append(allRepos, repos...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	// Run repo-level checks in parallel
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // Limit concurrent API calls

	for _, r := range allRepos {
		repo := r
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			runRepoChecks(ctx, ghc, orgName, *repo.Name, includeAll)
		}()
	}

	wg.Wait()
	return nil
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

func runRepoChecks(ctx context.Context, ghc *github.Client, orgName, repoName string, includeAll bool) {
	// Fetch all repo data in a single API call
	repository, _, err := ghc.Repositories.Get(ctx, orgName, repoName)
	if err != nil {
		return
	}

	// Check default workflow permissions - still needs its own API call
	_ = repo.DefaultPermissions(ctx, ghc, orgName, repoName)

	// Check deploy keys - still needs its own API call
	_ = repo.DeployKeys(ctx, ghc, orgName, repoName)

	// Check vulnerability reporting - only for public repos and only in 'all' mode
	// Private vulnerability reporting is only available for public repositories
	if includeAll && !repository.GetPrivate() {
		_ = repo.VulnerabilityReporting(ctx, ghc, orgName, repoName)
	}

	// Check vulnerability alerts (Dependabot) - pass pre-fetched repository data
	_ = repo.VulnerabilityAlerts(ctx, ghc, orgName, repoName, repository)

	// Check commit signoff (excluded in standard mode) - pass pre-fetched repository data
	if includeAll {
		_ = repo.CommitSignoff(ctx, ghc, orgName, repoName, repository)
	}

	// Check secret scanning - pass pre-fetched repository data
	_ = repo.SecretScanning(ctx, ghc, orgName, repoName, repository)

	// Check push protection (excluded in standard mode) - pass pre-fetched repository data
	if includeAll {
		_ = repo.PushProtection(ctx, ghc, orgName, repoName, repository)
	}

	// Check validity checks - pass pre-fetched repository data
	_ = repo.SecretValidityChecks(ctx, ghc, orgName, repoName, repository)

	// Non-provider patterns (excluded in standard mode)
	if includeAll {
		_ = repo.NonProviderPatterns(ctx, ghc, orgName, repoName)
	}
}
