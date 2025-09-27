// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

var ErrCommitSignoff = gherror.New("Web commit signoff disabled")

func commitSignoff(ghc *github.Client, org, repo *string) *cobra.Command {
	return &cobra.Command{
		Use:           "commit-signoff",
		Short:         "Audit web commit signoff requirements.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return CommitSignoff(cmd.Context(), ghc, *org, *repo, nil)
		},
	}
}

// CommitSignoff checks if web commit signoff is required
// Pass repoData as nil to fetch it, or provide pre-fetched data to avoid API call
func CommitSignoff(ctx context.Context, ghc *github.Client, orgName, repoName string, cachedRepoData *github.Repository) error {
	repository, err := getRepository(ctx, ghc, orgName, repoName, cachedRepoData)
	if err != nil {
		return err
	}

	// Check if web commit signoff is required
	// This ensures proper attribution and provides audit trail for code changes
	checkBooleanSetting(
		repository.GetWebCommitSignoffRequired(),
		true,
		ErrCommitSignoff,
		"Web commit signoff not required in %s/%s",
		orgName,
		repoName,
	)

	return nil
}
