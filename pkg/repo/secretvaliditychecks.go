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
func SecretValidityChecks(ctx context.Context, ghc *github.Client, org, repo string, repoData *github.Repository) error {
	var repository *github.Repository
	var err error

	if repoData != nil {
		repository = repoData
	} else {
		repository, _, err = ghc.Repositories.Get(ctx, org, repo)
		if err != nil {
			return err
		}
	}

	// Check if secret scanning validity checks are enabled
	// This verifies with providers if detected secrets are active/valid
	if repository.SecurityAndAnalysis != nil &&
		repository.SecurityAndAnalysis.SecretScanningValidityChecks != nil &&
		repository.SecurityAndAnalysis.SecretScanningValidityChecks.Status != nil {

		status := repository.SecurityAndAnalysis.SecretScanningValidityChecks.GetStatus()
		if status != "enabled" {
			ErrSecretValidityChecks.Emit("Secret validity checks disabled in %s/%s", org, repo)
		}
	} else {
		// If the field is not present or null, it means the feature is not enabled
		ErrSecretValidityChecks.Emit("Secret validity checks disabled in %s/%s", org, repo)
	}

	return nil
}
