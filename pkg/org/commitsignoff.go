// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"

	"github.com/chainguard-dev/ghaudit/pkg/repo"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

func commitSignoff(ghc *github.Client, org *string) *cobra.Command {
	wrapper := func(ctx context.Context, ghc *github.Client, org, repoName string) error {
		return repo.CommitSignoff(ctx, ghc, org, repoName, nil)
	}
	rm := NewRepoMapper("commit-signoff", ghc, org, wrapper)

	return &cobra.Command{
		Use:           "commit-signoff",
		Short:         "Audit web commit signoff requirements.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return rm.Execute(cmd.Context())
		},
	}
}
