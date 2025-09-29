// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"

	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
)

func twoFactor(githubClient *github.Client, orgPtr *string) *cobra.Command {
	return &cobra.Command{
		Use:           "two-factor",
		Short:         "Audit two-factor authentication requirement.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return TwoFactor(cmd.Context(), githubClient, *orgPtr)
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
		message := "Two-factor authentication not required"
		gherror.AddGlobalResult(gherror.Fail("Two-factor authentication", org, "", "error", message))
	} else {
		gherror.AddGlobalResult(gherror.Pass("Two-factor authentication", org, ""))
	}

	return nil
}
