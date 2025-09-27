// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

var (
	ErrDefaultPermissions  = gherror.New("Elevated default actions permissions")
	ErrApprovePullRequests = gherror.New("Actions can approve PRs")
)

func defaultPermissions(ghc *github.Client, org, repo *string) *cobra.Command {
	return &cobra.Command{
		Use:           "default-permissions",
		Short:         "Audit the default permissions.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return DefaultPermissions(cmd.Context(), ghc, *org, *repo)
		},
	}
}

// DefaultPermissions checks if default workflow permissions are elevated
// Note: This always needs its own API call as workflow permissions are not included in Repository.Get()
func DefaultPermissions(ctx context.Context, ghc *github.Client, org, repo string) error {
	dwp, _, err := ghc.Repositories.GetDefaultWorkflowPermissions(ctx, org, repo)
	if err != nil {
		return err
	}

	// Check whether the default workflow permissions are write.
	if dwp.GetDefaultWorkflowPermissions() == "write" {
		ErrDefaultPermissions.Emit("Elevated permissions in %s/%s", org, repo)
	}

	// Check whether workflows can approve PRs.
	// TODO(mattmoor): We need to figure out how to disable checks for
	// repos, since the advisory repos approve PRs from actions.
	if dwp.GetCanApprovePullRequestReviews() {
		ErrApprovePullRequests.Emit("Action approvers in %s/%s", org, repo)
	}
	return nil
}
