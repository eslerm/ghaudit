// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"

	"github.com/google/go-github/v75/github"
	"github.com/spf13/cobra"

	"github.com/chainguard-dev/ghaudit/pkg/repo"
)

// SecurityAudit represents an org-wide security audit
type SecurityAudit struct {
	CommandUse   string
	CommandShort string
	CheckFunc    func(context.Context, *github.Client, string, string, *github.Repository) error
}

var securityAudits = []SecurityAudit{
	{
		CommandUse:   "secret-scanning",
		CommandShort: "Audit secret scanning settings.",
		CheckFunc:    repo.SecretScanning,
	},
	{
		CommandUse:   "push-protection",
		CommandShort: "Audit secret scanning push protection settings.",
		CheckFunc:    repo.PushProtection,
	},
	{
		CommandUse:   "secret-validity-checks",
		CommandShort: "Audit secret scanning validity checks settings.",
		CheckFunc:    repo.SecretValidityChecks,
	},
	{
		CommandUse:   "vulnerability-alerts",
		CommandShort: "Audit vulnerability alerts settings.",
		CheckFunc:    repo.VulnerabilityAlerts,
	},
	{
		CommandUse:   "vulnerability-reporting",
		CommandShort: "Audit private vulnerability reporting settings.",
		CheckFunc:    repo.VulnerabilityReporting,
	},
	{
		CommandUse:   "commit-signoff",
		CommandShort: "Audit repository for commit signoff policy.",
		CheckFunc:    repo.CommitSignoff,
	},
}

// createSecurityCommand creates a cobra command for an org-wide security audit
func createSecurityCommand(githubClient *github.Client, org string, audit SecurityAudit) *cobra.Command {
	checkFunction := func(ctx context.Context, githubClient *github.Client, org, repoName string) error {
		return audit.CheckFunc(ctx, githubClient, org, repoName, nil)
	}
	repoMapper := NewRepoMapper(audit.CommandUse, githubClient, org, checkFunction)

	return &cobra.Command{
		Use:           audit.CommandUse,
		Short:         audit.CommandShort,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return repoMapper.Execute(cmd.Context())
		},
	}
}
