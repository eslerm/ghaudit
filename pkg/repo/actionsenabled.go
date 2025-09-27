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

func actionsEnabled(githubClient *github.Client, org, repo *string) *cobra.Command {
	return &cobra.Command{
		Use:           "actions-enabled",
		Short:         "Check if GitHub Actions are enabled for the repository.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return ActionsEnabled(cmd.Context(), githubClient, *org, *repo)
		},
	}
}

// ActionsEnabled checks if GitHub Actions are enabled for a repository
// Returns true if enabled, false if disabled, and error for actual failures
func ActionsEnabled(ctx context.Context, githubClient *github.Client, org, repo string) error {
	var actionsPerms *github.ActionsPermissionsRepository

	err := gherror.WithRetry(ctx, fmt.Sprintf("fetch actions permissions for %s/%s", org, repo), func() error {
		var err error
		actionsPerms, _, err = githubClient.Repositories.GetActionsPermissions(ctx, org, repo)
		return err
	})
	if err != nil {
		// 404 means Actions are completely disabled for this repository
		if gherror.Is404(err) {
			fmt.Printf("::info title=Actions disabled (secure)::Actions disabled in %s/%s reduces attack surface\n", org, repo)
			return nil
		}
		return gherror.WrapAPIError(err, "fetching actions permissions", org, repo)
	}

	// Check if actions are enabled
	if !actionsPerms.GetEnabled() {
		fmt.Printf("::info title=Actions disabled (secure)::Actions disabled in %s/%s reduces attack surface\n", org, repo)
	}

	return nil
}

// IsActionsEnabled is a helper function that returns whether Actions are enabled
// without emitting errors. Useful for other checks that depend on Actions status.
func IsActionsEnabled(ctx context.Context, githubClient *github.Client, org, repo string) (bool, error) {
	var actionsPerms *github.ActionsPermissionsRepository

	err := gherror.WithRetry(ctx, fmt.Sprintf("fetch actions permissions for %s/%s", org, repo), func() error {
		var err error
		actionsPerms, _, err = githubClient.Repositories.GetActionsPermissions(ctx, org, repo)
		return err
	})
	if err != nil {
		// 404 means Actions are completely disabled
		if gherror.Is404(err) {
			return false, nil
		}
		return false, gherror.WrapAPIError(err, "fetching actions permissions", org, repo)
	}

	return actionsPerms.GetEnabled(), nil
}
