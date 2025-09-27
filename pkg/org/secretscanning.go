// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"

	"github.com/chainguard-dev/ghaudit/pkg/repo"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

func secretScanning(githubClient *github.Client, org *string) *cobra.Command {
	// Wrapper to match RepoFunc signature
	wrapper := func(ctx context.Context, githubClient *github.Client, org, repoName string) error {
		return repo.SecretScanning(ctx, githubClient, org, repoName, nil)
	}
	rm := NewRepoMapper("secret-scanning", githubClient, org, wrapper)

	return &cobra.Command{
		Use:           "secret-scanning",
		Short:         "Audit secret scanning settings.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return rm.Execute(cmd.Context())
		},
	}
}
