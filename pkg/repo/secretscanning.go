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
			return SecretScanning(cmd.Context(), ghc, *org, *repo)
		},
	}
}

func SecretScanning(ctx context.Context, ghc *github.Client, org, repo string) error {
	// Get repository information to check secret scanning status
	repository, _, err := ghc.Repositories.Get(ctx, org, repo)
	if err != nil {
		return err
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
