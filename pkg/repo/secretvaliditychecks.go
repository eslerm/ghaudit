// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

var ErrSecretValidityChecks = gherror.New("Secret validity checks disabled")

func secretValidityChecks(ghc *github.Client, org, repo *string) *cobra.Command {
	return &cobra.Command{
		Use:           "secret-validity-checks",
		Short:         "Audit secret scanning validity checks settings.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return SecretValidityChecks(cmd.Context(), ghc, *org, *repo, nil)
		},
	}
}

// SecretValidityChecks checks if secret validity verification is enabled
// Pass repoData as nil to fetch it, or provide pre-fetched data to avoid API call
func SecretValidityChecks(ctx context.Context, ghc *github.Client, orgName, repoName string, cachedRepoData *github.Repository) error {
	repository, err := getRepository(ctx, ghc, orgName, repoName, cachedRepoData)
	if err != nil {
		return err
	}

	// Check if secret scanning validity checks are enabled
	// This verifies with providers if detected secrets are active/valid
	checkSecurityFeature(
		repository,
		func(sa *github.SecurityAndAnalysis) string {
			if sa.SecretScanningValidityChecks == nil {
				return ""
			}
			return sa.SecretScanningValidityChecks.GetStatus()
		},
		ErrSecretValidityChecks,
		orgName,
		repoName,
		"Secret validity checks",
	)

	return nil
}
