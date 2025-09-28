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

var ErrNonProviderPatterns = gherror.New("Non-provider secret patterns disabled")

func nonProviderPatterns(githubClient *github.Client, org, repo *string) *cobra.Command {
	return &cobra.Command{
		Use:           "non-provider-patterns",
		Short:         "Audit secret scanning for custom non-provider patterns.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return NonProviderPatterns(cmd.Context(), githubClient, *org, *repo)
		},
	}
}

// NonProviderPatterns checks if custom secret patterns are enabled
// Note: Cannot accept pre-fetched repository data as the secret_scanning_non_provider_patterns field
// is not available in go-github v75's Repository struct, requiring a custom API call
func NonProviderPatterns(ctx context.Context, githubClient *github.Client, org, repo string) error {
	// The non-provider patterns field is not yet available in go-github v75
	// We need to make a direct API call to check this field

	url := fmt.Sprintf("repos/%s/%s", org, repo)

	req, err := githubClient.NewRequest("GET", url, nil)
	if err != nil {
		gherror.AddGlobalResult(gherror.ErrorResult("Non-provider patterns", org, repo, err))
		return err
	}

	var result struct {
		SecurityAndAnalysis struct {
			SecretScanningNonProviderPatterns struct {
				Status string `json:"status"`
			} `json:"secret_scanning_non_provider_patterns"`
		} `json:"security_and_analysis"`
	}

	_, err = githubClient.Do(ctx, req, &result)
	if err != nil {
		gherror.AddGlobalResult(gherror.ErrorResult("Non-provider patterns", org, repo, err))
		return err
	}

	// Check if non-provider patterns are enabled
	status := result.SecurityAndAnalysis.SecretScanningNonProviderPatterns.Status
	if status != "enabled" {
		message := fmt.Sprintf("Non-provider secret patterns disabled in %s/%s", org, repo)
		result := gherror.Fail("Non-provider patterns", org, repo, "error", message)
		result.Value = status
		gherror.AddGlobalResult(result)
		if gherror.ShouldEmitGitHub() {
			ErrNonProviderPatterns.Emit(message)
		}
	} else {
		result := gherror.Pass("Non-provider patterns", org, repo)
		result.Value = status
		gherror.AddGlobalResult(result)
	}

	return nil
}
