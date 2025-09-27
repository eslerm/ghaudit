// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"
	"fmt"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

var (
	ErrDefaultPermissions  = gherror.New("Elevated default actions permissions")
	ErrApprovePullRequests = gherror.New("Actions can approve PRs")
)

func defaultPermissions(githubClient *github.Client, org, repo *string) *cobra.Command {
	return &cobra.Command{
		Use:           "default-permissions",
		Short:         "Audit the default permissions.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return DefaultPermissions(cmd.Context(), githubClient, *org, *repo)
		},
	}
}

// DefaultPermissions checks if default workflow permissions are elevated
// Note: Cannot accept pre-fetched repository data as this requires a completely different API endpoint
// (GetDefaultWorkflowPermissions) that returns data not included in the standard Repository object
func DefaultPermissions(ctx context.Context, githubClient *github.Client, org, repo string) error {
	var workflowPerms *github.DefaultWorkflowPermissionRepository

	err := gherror.WithRetry(ctx, fmt.Sprintf("fetch workflow permissions for %s/%s", org, repo), func() error {
		var err error
		workflowPerms, _, err = githubClient.Repositories.GetDefaultWorkflowPermissions(ctx, org, repo)
		return err
	})
	if err != nil {
		// 404 means Actions are disabled for this repository - this is actually secure
		if gherror.Is404(err) {
			return nil // Actions disabled is not a security issue
		}
		return gherror.WrapAPIError(err, "fetching workflow permissions", org, repo)
	}

	// Check whether the default workflow permissions are write.
	if workflowPerms.GetDefaultWorkflowPermissions() == "write" {
		ErrDefaultPermissions.Emit("Elevated permissions in %s/%s", org, repo)
	}

	// Check whether workflows can approve PRs.
	// TODO(mattmoor): We need to figure out how to disable checks for
	// repos, since the advisory repos approve PRs from actions.
	if workflowPerms.GetCanApprovePullRequestReviews() {
		ErrApprovePullRequests.Emit("Action approvers in %s/%s", org, repo)
	}
	return nil
}
