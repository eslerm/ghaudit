// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"
	"fmt"

	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
)

func actionsEnabled(githubClient *github.Client, org, repo string) *cobra.Command {
	return &cobra.Command{
		Use:           "actions-enabled",
		Short:         "Check if GitHub Actions are enabled for the repository.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return ActionsEnabled(cmd.Context(), githubClient, org, repo)
		},
	}
}

// ActionsEnabled checks if GitHub Actions are enabled for a repository
// Returns true if enabled, false if disabled, and error for actual failures
func ActionsEnabled(ctx context.Context, githubClient *github.Client, org, repo string) error {
	var actionsPermissions *github.ActionsPermissionsRepository

	err := gherror.WithRetry(ctx, fmt.Sprintf("fetch actions permissions for %s/%s", org, repo), func() error {
		var err error
		actionsPermissions, _, err = githubClient.Repositories.GetActionsPermissions(ctx, org, repo)
		return err
	})
	if err != nil {
		// 404 means Actions are completely disabled for this repository
		if gherror.Is404(err) {
			message := fmt.Sprintf("Actions disabled in %s/%s reduces attack surface", org, repo)
			gherror.AddGlobalResult(gherror.Info("Actions status", org, repo, message))
			// No console output in JSON mode
			return nil
		}
		gherror.AddGlobalResult(gherror.ErrorResult("Actions status", org, repo, gherror.WrapAPIError(err, "fetching actions permissions", org, repo)))
		return gherror.WrapAPIError(err, "fetching actions permissions", org, repo)
	}

	// Check if actions are enabled
	if !actionsPermissions.GetEnabled() {
		message := fmt.Sprintf("Actions disabled in %s/%s reduces attack surface", org, repo)
		gherror.AddGlobalResult(gherror.Info("Actions status", org, repo, message))
		// No console output in JSON mode
	} else {
		result := gherror.Pass("Actions status", org, repo)
		result.Value = "enabled"
		gherror.AddGlobalResult(result)
	}

	return nil
}

// IsActionsEnabled is a helper function that returns whether Actions are enabled
// without emitting errors. Useful for other checks that depend on Actions status.
func IsActionsEnabled(ctx context.Context, githubClient *github.Client, org, repo string) (bool, error) {
	var actionsPermissions *github.ActionsPermissionsRepository

	err := gherror.WithRetry(ctx, fmt.Sprintf("fetch actions permissions for %s/%s", org, repo), func() error {
		var err error
		actionsPermissions, _, err = githubClient.Repositories.GetActionsPermissions(ctx, org, repo)
		return err
	})
	if err != nil {
		// 404 means Actions are completely disabled
		if gherror.Is404(err) {
			return false, nil
		}
		return false, gherror.WrapAPIError(err, "fetching actions permissions", org, repo)
	}

	return actionsPermissions.GetEnabled(), nil
}
