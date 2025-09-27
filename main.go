// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log"
	"os"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/chainguard-dev/ghaudit/pkg/org"
	"github.com/chainguard-dev/ghaudit/pkg/repo"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

func New(githubClient *github.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "ghaudit",
		Short:         "GitHub Audit",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Usage()
		},
	}

	// Add sub-commands.
	cmd.AddCommand(
		org.New(githubClient),
		repo.New(githubClient),
	)

	return cmd
}

func main() {
	ctx := context.Background()

	token, ok := os.LookupEnv("GITHUB_TOKEN")
	if !ok {
		token, ok = os.LookupEnv("GH_TOKEN")
		if !ok {
			log.Fatal("GITHUB_TOKEN or GH_TOKEN must be set")
		}
	}

	githubClient := github.NewClient(
		oauth2.NewClient(ctx,
			oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: token,
			}),
		),
	)

	cmd := New(githubClient)

	if err := cmd.ExecuteContext(ctx); err != nil {
		log.Fatal(err)
	}

	// Exit with a non-zero status code if there were any errors.
	if gherror.HadErrors() {
		os.Exit(1)
	}
}
