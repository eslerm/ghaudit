// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

func New(githubClient *github.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "repo",
		Short:         "Commands to audit github repositories.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Usage()
		},
	}

	var org, repo string
	cmd.PersistentFlags().StringVarP(&org, "organization", "o", "", "organization to perform audits on.")
	cmd.PersistentFlags().StringVarP(&repo, "repository", "r", "", "repository to perform audits on.")

	// Add sub-commands.
	cmd.AddCommand(
		actionsEnabled(githubClient, &org, &repo),
		deployKeys(githubClient, &org, &repo),
		defaultPermissions(githubClient, &org, &repo),
		vulnerabilityReporting(githubClient, &org, &repo),
		vulnerabilityAlerts(githubClient, &org, &repo),
		commitSignoff(githubClient, &org, &repo),
		secretScanning(githubClient, &org, &repo),
		pushProtection(githubClient, &org, &repo),
		secretValidityChecks(githubClient, &org, &repo),
		nonProviderPatterns(githubClient, &org, &repo),
	)

	return cmd
}
