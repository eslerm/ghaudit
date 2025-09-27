// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"github.com/chainguard-dev/ghaudit/pkg/repo"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

func nonProviderPatterns(ghc *github.Client, org *string) *cobra.Command {
	rm := NewRepoMapper("non-provider-patterns", ghc, org, repo.NonProviderPatterns)

	return &cobra.Command{
		Use:           "non-provider-patterns",
		Short:         "Audit secret scanning for custom non-provider patterns.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return rm.Execute(cmd.Context())
		},
	}
}