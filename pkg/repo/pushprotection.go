// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

var errPushProtection = gherror.New("Secret scanning push protection disabled")

func pushProtection(ghc *github.Client, org, repo *string) *cobra.Command {
	return &cobra.Command{
		Use:           "push-protection",
		Short:         "Audit secret scanning push protection settings.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return PushProtection(cmd.Context(), ghc, *org, *repo)
		},
	}
}

func PushProtection(ctx context.Context, ghc *github.Client, org, repo string) error {
	// Get repository information to check push protection status
	repository, _, err := ghc.Repositories.Get(ctx, org, repo)
	if err != nil {
		return err
	}

	// Check if secret scanning push protection is enabled
	// This prevents commits containing secrets from being pushed
	if repository.SecurityAndAnalysis != nil &&
		repository.SecurityAndAnalysis.SecretScanningPushProtection != nil &&
		repository.SecurityAndAnalysis.SecretScanningPushProtection.Status != nil {

		status := repository.SecurityAndAnalysis.SecretScanningPushProtection.GetStatus()
		if status != "enabled" {
			errPushProtection.Emit("Secret scanning push protection disabled in %s/%s", org, repo)
		}
	} else {
		// If the field is not present or null, it means the feature is not enabled
		errPushProtection.Emit("Secret scanning push protection disabled in %s/%s", org, repo)
	}

	return nil
}
