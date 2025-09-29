// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"

	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
)

func memberRepoCreation(githubClient *github.Client, orgPtr *string) *cobra.Command {
	return &cobra.Command{
		Use:           "member-repo-creation",
		Short:         "Audit if members can create repositories.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return MemberRepoCreation(cmd.Context(), githubClient, *orgPtr)
		},
	}
}

func MemberRepoCreation(ctx context.Context, githubClient *github.Client, org string) error {
	// Get organization information
	organization, _, err := githubClient.Organizations.Get(ctx, org)
	if err != nil {
		return gherror.WrapAPIError(err, "fetching organization settings", org, "")
	}

	// Check if members can create repositories
	// In production orgs, this should be false (require github-iac)
	if organization.GetMembersCanCreateRepos() {
		message := "Members can create repositories (should require github-iac)"
		gherror.AddGlobalResult(gherror.Fail("Member repo creation", org, "", "error", message))
	} else {
		gherror.AddGlobalResult(gherror.Pass("Member repo creation", org, ""))
	}

	return nil
}
