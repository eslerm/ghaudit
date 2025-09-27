// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

var errExternalCollaboratorInvite = gherror.New("Members can invite external collaborators")

func externalCollaboratorInvite(ghc *github.Client, org *string) *cobra.Command {
	return &cobra.Command{
		Use:           "external-collaborator-invite",
		Short:         "Audit if members can invite outside collaborators.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return ExternalCollaboratorInvite(cmd.Context(), ghc, *org)
		},
	}
}

func ExternalCollaboratorInvite(ctx context.Context, ghc *github.Client, org string) error {
	// Get organization information
	organization, _, err := ghc.Organizations.Get(ctx, org)
	if err != nil {
		return err
	}

	// Check if members can invite outside collaborators
	// In production orgs, this should be false to prevent unauthorized access
	if organization.GetMembersCanInviteOutsideCollaborators() {
		errExternalCollaboratorInvite.Emit("Members can invite outside collaborators in %s (should be disabled for production orgs)", org)
	}

	return nil
}
