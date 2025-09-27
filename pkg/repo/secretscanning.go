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

func secretScanning(githubClient *github.Client, org, repo *string) *cobra.Command {
	return &cobra.Command{
		Use:           "secret-scanning",
		Short:         "Audit secret scanning settings.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return SecretScanning(cmd.Context(), githubClient, *org, *repo, nil)
		},
	}
}

// SecretScanning checks if secret scanning is enabled
// Pass repoData as nil to fetch it, or provide pre-fetched data to avoid API call
func SecretScanning(ctx context.Context, githubClient *github.Client, orgName, repoName string, cachedRepoData *github.Repository) error {
	repository, err := getRepository(ctx, githubClient, orgName, repoName, cachedRepoData)
	if err != nil {
		return err
	}

	// Check if secret scanning is enabled
	// This detects secrets that are already in the repository
	checkSecurityFeature(
		repository,
		func(sa *github.SecurityAndAnalysis) string {
			if sa.SecretScanning == nil {
				return ""
			}
			return sa.SecretScanning.GetStatus()
		},
		ErrSecretScanning,
		orgName,
		repoName,
		"Secret scanning",
	)

	return nil
}
