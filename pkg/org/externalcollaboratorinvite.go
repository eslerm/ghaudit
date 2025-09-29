// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"

	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
)

func externalCollaboratorInvite(githubClient *github.Client, orgPtr *string) *cobra.Command {
	return &cobra.Command{
		Use:           "external-collaborator-invite",
		Short:         "Audit if members can invite outside collaborators.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return ExternalCollaboratorInvite(cmd.Context(), githubClient, *orgPtr)
		},
	}
}

func ExternalCollaboratorInvite(ctx context.Context, githubClient *github.Client, org string) error {
	// Get organization information
	organization, _, err := githubClient.Organizations.Get(ctx, org)
	if err != nil {
		return gherror.WrapAPIError(err, "fetching organization settings", org, "")
	}

	// Check if members can invite outside collaborators
	// In production orgs, this should be false to prevent unauthorized access
	if organization.GetMembersCanInviteOutsideCollaborators() {
		message := "Members can invite outside collaborators (should be disabled for production orgs)"
		gherror.AddGlobalResult(gherror.Fail("External collaborator invite", org, "", "error", message))
	} else {
		gherror.AddGlobalResult(gherror.Pass("External collaborator invite", org, ""))
	}

	return nil
}
