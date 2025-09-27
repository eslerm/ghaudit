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
	ErrDeployKeys     = gherror.New("Found deploy keys")
	ErrWriteDeployKey = gherror.New("Write deploy key")
)

func deployKeys(ghc *github.Client, org, repo *string) *cobra.Command {
	return &cobra.Command{
		Use:           "deploy-keys",
		Short:         "Audit for usage of deploy keys.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return DeployKeys(cmd.Context(), ghc, *org, *repo)
		},
	}
}

// DeployKeys checks if deploy keys are used in the repository
// Note: This always needs its own API call as deploy keys are not included in Repository.Get()
func DeployKeys(ctx context.Context, ghc *github.Client, org, repo string) error {
	keys, _, err := ghc.Repositories.ListKeys(ctx, org, repo, &github.ListOptions{})
	if err != nil {
		return err
	}

	// Check whether there are any deploy keys.
	// TODO(mattmoor): bump the severity if there are any non-readonly ones?
	if len(keys) > 0 {
		ErrDeployKeys.Emit("Deploy keys used in %s/%s", org, repo)
	}
	return nil
}
