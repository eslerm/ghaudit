// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"
	"fmt"

	"github.com/chainguard-dev/ghaudit/pkg/config"
	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

func deployKeys(githubClient *github.Client, org, repo *string) *cobra.Command {
	return &cobra.Command{
		Use:           "deploy-keys",
		Short:         "Audit for usage of deploy keys.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			// Initialize global result collector for individual command
			format := config.GetFormat(ctx)
			gherror.InitGlobalResultSet(format)

			// Run the check
			err := DeployKeys(ctx, githubClient, *org, *repo)

			// Output results if JSON or text format
			if rs := gherror.GetGlobalResultSet(); rs != nil && format != "github" {
				if outputErr := rs.Output(); outputErr != nil {
					return outputErr
				}
			}

			return err
		},
	}
}

// DeployKeys checks if deploy keys are used in the repository
// Note: Cannot accept pre-fetched repository data as this requires a completely different API endpoint
// (ListKeys) that returns data not included in the standard Repository object
func DeployKeys(ctx context.Context, githubClient *github.Client, org, repo string) error {
	var keys []*github.Key

	err := gherror.WithRetry(ctx, fmt.Sprintf("list deploy keys for %s/%s", org, repo), func() error {
		var err error
		keys, _, err = githubClient.Repositories.ListKeys(ctx, org, repo, &github.ListOptions{})
		return err
	})
	if err != nil {
		// 404 means we don't have admin access to view deploy keys for this repo
		if gherror.Is404(err) {
			// Record skip result for JSON output
			gherror.AddGlobalResult(gherror.Skip("Deploy keys", org, repo, "No admin access"))
			return nil // Skip repos where we lack admin access
		}
		// Record error result for JSON output
		gherror.AddGlobalResult(gherror.ErrorResult("Deploy keys", org, repo, gherror.WrapAPIError(err, "listing deploy keys", org, repo)))
		return gherror.WrapAPIError(err, "listing deploy keys", org, repo)
	}

	// Check whether there are any deploy keys.
	if len(keys) > 0 {
		// Count read-only vs write keys
		writeKeys := 0
		for _, key := range keys {
			if !key.GetReadOnly() {
				writeKeys++
			}
		}

		message := fmt.Sprintf("Deploy keys used in %s/%s", org, repo)

		// Create result for JSON output
		result := gherror.Fail("Deploy keys", org, repo, "error", message)
		result.Value = len(keys)
		result.Metadata = map[string]interface{}{
			"total_keys":     len(keys),
			"write_keys":     writeKeys,
			"read_only_keys": len(keys) - writeKeys,
		}
		gherror.AddGlobalResult(result)
	} else {
		// Record pass result for JSON output
		gherror.AddGlobalResult(gherror.Pass("Deploy keys", org, repo))
	}

	return nil
}
