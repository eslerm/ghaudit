// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

var errSecretValidityChecks = gherror.New("Secret validity checks disabled")

func secretValidityChecks(ghc *github.Client, org, repo *string) *cobra.Command {
	return &cobra.Command{
		Use:           "secret-validity-checks",
		Short:         "Audit secret scanning validity checks settings.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return SecretValidityChecks(cmd.Context(), ghc, *org, *repo)
		},
	}
}

func SecretValidityChecks(ctx context.Context, ghc *github.Client, org, repo string) error {
	// Get repository information to check secret validity checks status
	repository, _, err := ghc.Repositories.Get(ctx, org, repo)
	if err != nil {
		return err
	}

	// Check if secret scanning validity checks are enabled
	// This verifies with providers if detected secrets are active/valid
	if repository.SecurityAndAnalysis != nil &&
		repository.SecurityAndAnalysis.SecretScanningValidityChecks != nil &&
		repository.SecurityAndAnalysis.SecretScanningValidityChecks.Status != nil {

		status := repository.SecurityAndAnalysis.SecretScanningValidityChecks.GetStatus()
		if status != "enabled" {
			errSecretValidityChecks.Emit("Secret validity checks disabled in %s/%s", org, repo)
		}
	} else {
		// If the field is not present or null, it means the feature is not enabled
		errSecretValidityChecks.Emit("Secret validity checks disabled in %s/%s", org, repo)
	}

	return nil
}