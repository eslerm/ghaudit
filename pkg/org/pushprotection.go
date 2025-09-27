// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"github.com/chainguard-dev/ghaudit/pkg/repo"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

func pushProtection(ghc *github.Client, org *string) *cobra.Command {
	rm := NewRepoMapper("push-protection", ghc, org, repo.PushProtection)

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
