// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

var ErrSecretScanning = gherror.New("Secret scanning disabled")

func secretScanning(ghc *github.Client, org, repo *string) *cobra.Command {
	return &cobra.Command{
		Use:           "secret-scanning",
		Short:         "Audit secret scanning settings.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return SecretScanning(cmd.Context(), ghc, *org, *repo, nil)
		},
	}
}

// SecretScanning checks if secret scanning is enabled
// Pass repoData as nil to fetch it, or provide pre-fetched data to avoid API call
func SecretScanning(ctx context.Context, ghc *github.Client, org, repo string, repoData *github.Repository) error {
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

	// Check if secret scanning is enabled
	// This detects secrets that are already in the repository
	if repository.SecurityAndAnalysis != nil &&
		repository.SecurityAndAnalysis.SecretScanning != nil &&
		repository.SecurityAndAnalysis.SecretScanning.Status != nil {

		status := repository.SecurityAndAnalysis.SecretScanning.GetStatus()
		if status != "enabled" {
			ErrSecretScanning.Emit("Secret scanning disabled in %s/%s", org, repo)
		}
	} else {
		// If the field is not present or null, it means the feature is not enabled
		ErrSecretScanning.Emit("Secret scanning disabled in %s/%s", org, repo)
	}

	return nil
}
