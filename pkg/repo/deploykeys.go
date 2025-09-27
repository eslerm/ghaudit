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
	ErrDeployKeys     = gherror.New("Found deploy keys")
	ErrWriteDeployKey = gherror.New("Write deploy key")
)

func deployKeys(githubClient *github.Client, org, repo *string) *cobra.Command {
	return &cobra.Command{
		Use:           "deploy-keys",
		Short:         "Audit for usage of deploy keys.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return DeployKeys(cmd.Context(), githubClient, *org, *repo)
		},
	}
}

// DeployKeys checks if deploy keys are used in the repository
// Note: Cannot accept pre-fetched repository data as this requires a completely different API endpoint
// (ListKeys) that returns data not included in the standard Repository object
func DeployKeys(ctx context.Context, githubClient *github.Client, org, repo string) error {
	var keys []*github.Key

	err := gherror.WithRetry(ctx, fmt.Sprintf("list deploy keys for %s/%s", org, repo), func() error {
		var err error
		keys, _, err = githubClient.Repositories.ListKeys(ctx, org, repo, &github.ListOptions{})
		return err
	})
	if err != nil {
		// 404 means we don't have admin access to view deploy keys for this repo
		if gherror.Is404(err) {
			return nil // Skip repos where we lack admin access
		}
		return gherror.WrapAPIError(err, "listing deploy keys", org, repo)
	}

	// Check whether there are any deploy keys.
	// TODO(mattmoor): bump the severity if there are any non-readonly ones?
	if len(keys) > 0 {
		ErrDeployKeys.Emit("Deploy keys used in %s/%s", org, repo)
	}
	return nil
}
