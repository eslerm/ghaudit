// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

var ErrPushProtection = gherror.New("Secret scanning push protection disabled")

func pushProtection(githubClient *github.Client, org, repo *string) *cobra.Command {
	return &cobra.Command{
		Use:           "push-protection",
		Short:         "Audit secret scanning push protection settings.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return PushProtection(cmd.Context(), githubClient, *org, *repo, nil)
		},
	}
}

// PushProtection checks if secret scanning push protection is enabled
// Pass repoData as nil to fetch it, or provide pre-fetched data to avoid API call
func PushProtection(ctx context.Context, githubClient *github.Client, orgName, repoName string, cachedRepoData *github.Repository) error {
	repository, err := getRepository(ctx, githubClient, orgName, repoName, cachedRepoData)
	if err != nil {
		return err
	}

	// Check if secret scanning push protection is enabled
	// This prevents commits containing secrets from being pushed
	checkSecurityFeature(
		repository,
		func(sa *github.SecurityAndAnalysis) string {
			if sa.SecretScanningPushProtection == nil {
				return ""
			}
			return sa.SecretScanningPushProtection.GetStatus()
		},
		ErrPushProtection,
		orgName,
		repoName,
		"Secret scanning push protection",
	)

	return nil
}
