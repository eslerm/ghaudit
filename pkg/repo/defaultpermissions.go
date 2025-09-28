// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"
	"fmt"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"
)

func defaultPermissions(githubClient *github.Client, org, repo *string) *cobra.Command {
	return &cobra.Command{
		Use:           "default-permissions",
		Short:         "Audit the default permissions.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return DefaultWorkflowPermissions(cmd.Context(), githubClient, *org, *repo)
		},
	}
}

// DefaultWorkflowPermissions checks if default workflow permissions are elevated
// Note: Cannot accept pre-fetched repository data as this requires a completely different API endpoint
// (GetDefaultWorkflowPermissions) that returns data not included in the standard Repository object
func DefaultWorkflowPermissions(ctx context.Context, githubClient *github.Client, org, repo string) error {
	var workflowPerms *github.DefaultWorkflowPermissionRepository

	err := gherror.WithRetry(ctx, fmt.Sprintf("fetch workflow permissions for %s/%s", org, repo), func() error {
		var err error
		workflowPerms, _, err = githubClient.Repositories.GetDefaultWorkflowPermissions(ctx, org, repo)
		return err
	})
	if err != nil {
		// 404 means Actions are disabled for this repository - this is actually secure
		// TODO: This 404 handling may become unnecessary once we always check Actions status first
		// in all code paths (including standard mode and direct CLI calls). Consider removing
		// this once the Actions check is consistently performed before workflow permissions.
		if gherror.Is404(err) {
			gherror.AddGlobalResult(gherror.Skip("Workflow permissions", org, repo, "Actions disabled"))
			return nil // Actions disabled is not a security issue
		}
		gherror.AddGlobalResult(gherror.ErrorResult("Workflow permissions", org, repo, gherror.WrapAPIError(err, "fetching workflow permissions", org, repo)))
		return gherror.WrapAPIError(err, "fetching workflow permissions", org, repo)
	}

	// Check whether the default workflow permissions are write.
	permission := workflowPerms.GetDefaultWorkflowPermissions()
	canApprove := workflowPerms.GetCanApprovePullRequestReviews()

	if permission == "write" || canApprove {
		// Build comprehensive error message
		issues := []string{}
		if permission == "write" {
			issues = append(issues, "elevated permissions")
		}
		if canApprove {
			issues = append(issues, "can approve PRs")
		}
		// Note: issues variable is built but not currently used in the message
		// Consider using it in future to provide more detailed feedback
		_ = issues

		message := fmt.Sprintf("Elevated permissions in %s/%s", org, repo)
		result := gherror.Fail("Workflow permissions", org, repo, "error", message)
		result.Metadata = map[string]interface{}{
			"permission_level": permission,
			"can_approve_prs":  canApprove,
		}
		gherror.AddGlobalResult(result)
	} else {
		result := gherror.Pass("Workflow permissions", org, repo)
		result.Metadata = map[string]interface{}{
			"permission_level": permission,
			"can_approve_prs":  canApprove,
		}
		gherror.AddGlobalResult(result)
	}

	return nil
}
