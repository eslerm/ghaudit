// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"github.com/chainguard-dev/ghaudit/pkg/config"
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
	var errorsOnly bool
	var format string
	cmd.PersistentFlags().StringVarP(&org, "organization", "o", "", "organization to perform audits on.")
	cmd.PersistentFlags().StringVarP(&repo, "repository", "r", "", "repository to perform audits on.")
	cmd.PersistentFlags().BoolVar(&errorsOnly, "errors-only", false, "Show only errors, suppress informational messages")
	cmd.PersistentFlags().StringVar(&format, "format", "github", "Output format: github (default), json, or text")

	// Add errorsOnly and format to context for all subcommands
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		ctx := config.WithErrorsOnly(cmd.Context(), errorsOnly)
		ctx = config.WithFormat(ctx, format)
		cmd.SetContext(ctx)
		return nil
	}

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
