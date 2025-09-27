// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"

	"github.com/chainguard-dev/ghaudit/pkg/repo"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

func pushProtection(githubClient *github.Client, org *string) *cobra.Command {
	wrapper := func(ctx context.Context, githubClient *github.Client, org, repoName string) error {
		return repo.PushProtection(ctx, githubClient, org, repoName, nil)
	}
	rm := NewRepoMapper("push-protection", githubClient, org, wrapper)

	return &cobra.Command{
		Use:           "push-protection",
		Short:         "Audit secret scanning push protection settings.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return rm.Execute(cmd.Context())
		},
	}
}
