// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

var errMembersCanCreateRepos = gherror.New("Members can create repositories")

func memberRepoCreation(ghc *github.Client, org *string) *cobra.Command {
	return &cobra.Command{
		Use:           "member-repo-creation",
		Short:         "Audit if members can create repositories.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return MemberRepoCreation(cmd.Context(), ghc, *org)
		},
	}
}

func MemberRepoCreation(ctx context.Context, ghc *github.Client, org string) error {
	// Get organization information
	organization, _, err := ghc.Organizations.Get(ctx, org)
	if err != nil {
		return err
	}

	// Check if members can create repositories
	// In production orgs, this should be false (require github-iac)
	if organization.GetMembersCanCreateRepos() {
		errMembersCanCreateRepos.Emit("Members can create repositories in %s (should require github-iac)", org)
	}

	return nil
}
