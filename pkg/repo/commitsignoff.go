// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"
	"fmt"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

func commitSignoff(githubClient *github.Client, org, repo *string) *cobra.Command {
	return &cobra.Command{
		Use:           "commit-signoff",
		Short:         "Audit web commit signoff requirements.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return CommitSignoff(cmd.Context(), githubClient, *org, *repo, nil)
		},
	}
}

// CommitSignoff checks if web commit signoff is required
// Pass repoData as nil to fetch it, or provide pre-fetched data to avoid API call
func CommitSignoff(ctx context.Context, githubClient *github.Client, orgName, repoName string, cachedRepoData *github.Repository) error {
	repository, err := getRepository(ctx, githubClient, orgName, repoName, cachedRepoData)
	if err != nil {
		gherror.AddGlobalResult(gherror.ErrorResult("Web commit signoff", orgName, repoName, err))
		return err
	}

	// Check if web commit signoff is required
	// This ensures proper attribution and provides audit trail for code changes
	signoffRequired := repository.GetWebCommitSignoffRequired()

	if !signoffRequired {
		message := fmt.Sprintf("Web commit signoff not required in %s/%s", orgName, repoName)
		result := gherror.Fail("Web commit signoff", orgName, repoName, "error", message)
		result.Value = signoffRequired
		gherror.AddGlobalResult(result)
	} else {
		result := gherror.Pass("Web commit signoff", orgName, repoName)
		result.Value = signoffRequired
		gherror.AddGlobalResult(result)
	}

	return nil
}
