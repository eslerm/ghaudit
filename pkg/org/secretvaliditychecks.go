// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"

	"github.com/chainguard-dev/ghaudit/pkg/repo"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

func secretValidityChecks(ghc *github.Client, org *string) *cobra.Command {
	wrapper := func(ctx context.Context, ghc *github.Client, org, repoName string) error {
		return repo.SecretValidityChecks(ctx, ghc, org, repoName, nil)
	}
	rm := NewRepoMapper("secret-validity-checks", ghc, org, wrapper)

	return &cobra.Command{
		Use:           "secret-validity-checks",
		Short:         "Audit secret scanning validity checks settings.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return rm.Execute(cmd.Context())
		},
	}
}
