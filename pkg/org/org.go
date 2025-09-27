// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

func New(githubClient *github.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "org",
		Short:         "Commands to audit github organizations.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Usage()
		},
	}

	var org string
	cmd.PersistentFlags().StringVarP(&org, "organization", "o", "", "organization to perform audits on.")

	// Add sub-commands.
	cmd.AddCommand(
		all(githubClient, &org),
		standard(githubClient, &org),
		deployKeys(githubClient, &org),
		defaultPermissions(githubClient, &org),
		vulnerabilityReporting(githubClient, &org),
		vulnerabilityAlerts(githubClient, &org),
		commitSignoff(githubClient, &org),
		secretScanning(githubClient, &org),
		pushProtection(githubClient, &org),
		secretValidityChecks(githubClient, &org),
		nonProviderPatterns(githubClient, &org),
		memberRepoCreation(githubClient, &org),
		twoFactor(githubClient, &org),
		externalCollaboratorInvite(githubClient, &org),
	)

	return cmd
}
