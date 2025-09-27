// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"
	"fmt"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

var errNonProviderPatterns = gherror.New("Non-provider secret patterns disabled")

func nonProviderPatterns(ghc *github.Client, org, repo *string) *cobra.Command {
	return &cobra.Command{
		Use:           "non-provider-patterns",
		Short:         "Audit secret scanning for custom non-provider patterns.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return NonProviderPatterns(cmd.Context(), ghc, *org, *repo)
		},
	}
}

func NonProviderPatterns(ctx context.Context, ghc *github.Client, org, repo string) error {
	// The non-provider patterns field is not yet available in go-github v75
	// We need to make a direct API call to check this field

	url := fmt.Sprintf("repos/%s/%s", org, repo)

	req, err := ghc.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	var result struct {
		SecurityAndAnalysis struct {
			SecretScanningNonProviderPatterns struct {
				Status string `json:"status"`
			} `json:"secret_scanning_non_provider_patterns"`
		} `json:"security_and_analysis"`
	}

	_, err = ghc.Do(ctx, req, &result)
	if err != nil {
		return err
	}

	// Check if non-provider patterns are enabled
	if result.SecurityAndAnalysis.SecretScanningNonProviderPatterns.Status != "enabled" {
		errNonProviderPatterns.Emit("Non-provider secret patterns disabled in %s/%s", org, repo)
	}

	return nil
}
