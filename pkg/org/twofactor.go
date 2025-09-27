// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

var errTwoFactorDisabled = gherror.New("Two-factor authentication not required")

func twoFactor(githubClient *github.Client, org *string) *cobra.Command {
	return &cobra.Command{
		Use:           "two-factor",
		Short:         "Audit two-factor authentication requirement.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return TwoFactor(cmd.Context(), githubClient, *org)
		},
	}
}

func TwoFactor(ctx context.Context, githubClient *github.Client, org string) error {
	// Get organization information
	organization, _, err := githubClient.Organizations.Get(ctx, org)
	if err != nil {
		return gherror.WrapAPIError(err, "fetching organization settings", org, "")
	}

	// Check if two-factor authentication is required
	// This is critical for protecting against account compromise
	if !organization.GetTwoFactorRequirementEnabled() {
		errTwoFactorDisabled.Emit("Two-factor authentication not required in %s", org)
	}

	return nil
}
