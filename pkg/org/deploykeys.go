// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"

	"github.com/chainguard-dev/ghaudit/pkg/repo"
)

func deployKeys(githubClient *github.Client, orgPtr *string) *cobra.Command {
	return &cobra.Command{
		Use:           "deploy-keys",
		Short:         "Audit for usage of deploy keys.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			repoMapper := NewRepoMapper("deploy-keys", githubClient, *orgPtr, repo.DeployKeys)
			return repoMapper.Execute(cmd.Context())
		},
	}
}
