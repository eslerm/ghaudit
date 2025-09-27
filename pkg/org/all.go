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

	// Check default workflow permissions
	dwp, _, _ := ghc.Repositories.GetDefaultWorkflowPermissions(ctx, orgName, repoName)
	if dwp != nil && dwp.GetDefaultWorkflowPermissions() == "write" {
		repo.ErrDefaultPermissions.Emit("Elevated permissions in %s/%s", orgName, repoName)
	}
	if dwp != nil && dwp.GetCanApprovePullRequestReviews() {
		repo.ErrApprovePullRequests.Emit("Actions can approve pull requests in %s/%s", orgName, repoName)
	}

	// Check deploy keys - requires separate API call
	keys, _, _ := ghc.Repositories.ListKeys(ctx, orgName, repoName, nil)
	if len(keys) > 0 {
		repo.ErrDeployKeys.Emit("Deploy keys used in %s/%s", orgName, repoName)
		// Also check for write-enabled deploy keys
		for _, k := range keys {
			if !k.GetReadOnly() {
				repo.ErrWriteDeployKey.Emit("Deploy key with write permission in %s/%s: %s", orgName, repoName, k.GetTitle())
			}
		}
	}

	// Check vulnerability reporting - only for public repos and only in 'all' mode
	// Private vulnerability reporting is only available for public repositories
	if includeAll {
		var pvr struct {
			Enabled bool `json:"enabled"`
		}
		req, _ := ghc.NewRequest("GET", "repos/"+orgName+"/"+repoName+"/private-vulnerability-reporting", nil)
		resp, _ := ghc.Do(ctx, req, &pvr)
		if resp != nil && resp.StatusCode == 404 || !pvr.Enabled {
			// Only report if it's a public repo (PVR is only for public repos)
			if repository.GetPrivate() == false {
				repo.ErrVulnerabilityReporting.Emit("Private vulnerability reporting disabled in %s/%s", orgName, repoName)
			}
		}
	}

	// Check vulnerability alerts (Dependabot)
	if repository.SecurityAndAnalysis == nil ||
	   repository.SecurityAndAnalysis.DependabotSecurityUpdates == nil ||
	   repository.SecurityAndAnalysis.DependabotSecurityUpdates.GetStatus() != "enabled" {
		repo.ErrVulnerabilityAlerts.Emit("Vulnerability alerts (Dependabot security updates) disabled in %s/%s", orgName, repoName)
	}

	// Check commit signoff (excluded in standard mode)
	if includeAll && !repository.GetWebCommitSignoffRequired() {
		repo.ErrCommitSignoff.Emit("Web commit signoff not required in %s/%s", orgName, repoName)
	}

	// Check secret scanning
	if repository.SecurityAndAnalysis == nil ||
	   repository.SecurityAndAnalysis.SecretScanning == nil ||
	   repository.SecurityAndAnalysis.SecretScanning.GetStatus() != "enabled" {
		repo.ErrSecretScanning.Emit("Secret scanning disabled in %s/%s", orgName, repoName)
	}

	// Check push protection (excluded in standard mode)
	if includeAll && (repository.SecurityAndAnalysis == nil ||
	   repository.SecurityAndAnalysis.SecretScanningPushProtection == nil ||
	   repository.SecurityAndAnalysis.SecretScanningPushProtection.GetStatus() != "enabled") {
		repo.ErrPushProtection.Emit("Secret scanning push protection disabled in %s/%s", orgName, repoName)
	}

	// Check validity checks
	if repository.SecurityAndAnalysis == nil ||
	   repository.SecurityAndAnalysis.SecretScanningValidityChecks == nil ||
	   repository.SecurityAndAnalysis.SecretScanningValidityChecks.GetStatus() != "enabled" {
		repo.ErrSecretValidityChecks.Emit("Secret validity checks disabled in %s/%s", orgName, repoName)
	}

	// Non-provider patterns still requires custom API call (excluded in standard mode)
	if includeAll {
		type NonProviderPatternsResponse struct {
			Enabled bool `json:"secret_scanning_non_provider_patterns_enabled"`
		}
		var response NonProviderPatternsResponse
		req, _ := ghc.NewRequest("GET", "repos/"+orgName+"/"+repoName, nil)
		ghc.Do(ctx, req, &response)
		if !response.Enabled {
			repo.ErrNonProviderPatterns.Emit("Non-provider secret patterns disabled in %s/%s", orgName, repoName)
		}
	}
}