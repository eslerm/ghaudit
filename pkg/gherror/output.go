// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package gherror

import (
	"encoding/json"
	"fmt"
	"strings"
)

// JSONOutput represents the standard JSON output structure
type JSONOutput struct {
	Organization string                            `json:"organization"`
	OrgSettings  map[string]interface{}            `json:"org_settings,omitempty"`
	Repositories map[string]map[string]interface{} `json:"repositories,omitempty"`
}

// ConvertToJSON converts a ResultSet to standard JSON format
func (resultSet *ResultSet) ConvertToJSON(orgName string) *JSONOutput {
	output := &JSONOutput{
		Organization: orgName,
		OrgSettings:  make(map[string]interface{}),
		Repositories: make(map[string]map[string]interface{}),
	}

	for _, result := range resultSet.Results {
		// Skip error results
		if result.Status == StatusError {
			continue
		}

		key := normalizeCheckName(result.Check)

		if result.Repo == "" {
			// Organization-level check
			output.OrgSettings[key] = getCheckValue(result)
		} else {
			// Repository-level check
			if output.Repositories[result.Repo] == nil {
				output.Repositories[result.Repo] = make(map[string]interface{})
			}
			output.Repositories[result.Repo][key] = getCheckValue(result)
		}
	}

	return output
}

// normalizeCheckName converts check names to consistent JSON field names
func normalizeCheckName(check string) string {
	// Map verbose check names to minimal but clear keys
	mappings := map[string]string{
		// Organization policies
		"Two-factor authentication":       "two_factor_required",
		"Members can create repositories": "member_can_create_repos",
		"Member repository creation":      "member_can_create_repos",
		"Member repo creation":            "member_can_create_repos",
		"External collaborator invites":   "member_can_invite_collaborators",
		"External collaborator invite":    "member_can_invite_collaborators",
		"Default member permissions":      "default_member_permission",

		// Repository security settings
		"Actions status":       "actions_enabled",
		"Deploy keys":          "deploy_keys_count",
		"Workflow permissions": "workflow_permissions",
		"Vulnerability alerts (Dependabot security updates)": "dependabot_alerts",
		"Private vulnerability reporting":                    "private_vulnerability_reporting",
		"Web commit signoff":                                 "web_commit_signoff",
		"Secret scanning":                                    "secret_scanning",
		"Secret scanning push protection":                    "push_protection",
		"Push protection":                                    "push_protection",
		"Secret validity checks":                             "secret_validity_checks",
		"Non-provider patterns":                              "custom_secret_patterns",
	}

	if mapped, ok := mappings[check]; ok {
		return mapped
	}

	// Fallback: convert to snake_case
	key := strings.ToLower(check)
	key = strings.ReplaceAll(key, " ", "_")
	key = strings.ReplaceAll(key, "-", "_")
	return key
}

// getCheckValue returns the appropriate value for a check result
func getCheckValue(result Result) interface{} {
	// Special handling for specific checks
	switch result.Check {
	case "Deploy keys":
		// For deploy keys, return count if available, otherwise 0 for pass
		if result.Value != nil {
			return result.Value
		}
		// If passing with no value, means 0 deploy keys
		if result.Status == StatusPass {
			return 0
		}
		// If failing, return true to indicate presence
		return true

	case "Default member permissions":
		// Return the permission level
		if result.Value != nil {
			return result.Value
		}
		return "unknown"

	case "Workflow permissions":
		// Return structured data if available
		if result.Metadata != nil {
			return map[string]interface{}{
				"permission":     result.Metadata["permission_level"],
				"can_approve_pr": result.Metadata["can_approve_prs"],
			}
		}
		if result.Value != nil {
			return result.Value
		}
		return result.Status == "pass"

	default:
		// For boolean checks (most security features)
		if result.Value != nil {
			// Convert "enabled"/"disabled" to boolean
			if result.Value == "enabled" {
				return true
			} else if result.Value == "disabled" {
				return false
			}
			return result.Value
		}

		// For security features: pass means enabled (good), fail means disabled (bad)
		// This is inverted for some checks, so we need to be careful
		switch result.Check {
		case "Members can create repositories",
			"External collaborator invites":
			// For these, pass means the feature is disabled (good)
			return result.Status == StatusFail
		case "Two-factor authentication",
			"Secret scanning",
			"Secret scanning push protection",
			"Vulnerability alerts (Dependabot security updates)",
			"Private vulnerability reporting",
			"Web commit signoff",
			"Secret validity checks",
			"Non-provider patterns":
			// For these, pass means the feature is enabled (good)
			return result.Status == StatusPass
		default:
			// Default: pass = good = true for security features
			return result.Status == StatusPass
		}
	}
}

// OutputJSON outputs results in standard JSON format
func (resultSet *ResultSet) OutputJSON() error {
	// Extract org name from first result
	orgName := ""
	for _, result := range resultSet.Results {
		if result.Org != "" {
			orgName = result.Org
			break
		}
	}

	jsonOutput := resultSet.ConvertToJSON(orgName)
	encoder := json.NewEncoder(resultSet.writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(jsonOutput); err != nil {
		return fmt.Errorf("encoding JSON output: %w", err)
	}
	return nil
}
