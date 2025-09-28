// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"

	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"

	"github.com/chainguard-dev/ghaudit/pkg/repo"
)

func secretValidityChecks(githubClient *github.Client, org string) *cobra.Command {
	checkFunction := func(ctx context.Context, githubClient *github.Client, org, repoName string) error {
		return repo.SecretValidityChecks(ctx, githubClient, org, repoName, nil)
	}
	repoMapper := NewRepoMapper("secret-validity-checks", githubClient, org, checkFunction)

	return &cobra.Command{
		Use:           "secret-validity-checks",
		Short:         "Audit secret scanning validity checks settings.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return repoMapper.Execute(cmd.Context())
		},
	}
}
