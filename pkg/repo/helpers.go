// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"
	"fmt"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/google/go-github/v75/github"
)

// getRepository returns a cached repository or fetches it if not cached
func getRepository(ctx context.Context, githubClient *github.Client, orgName, repoName string, cachedRepoData *github.Repository) (*github.Repository, error) {
	if cachedRepoData != nil {
		return cachedRepoData, nil
	}

	var repository *github.Repository
	operation := fmt.Sprintf("fetch repository %s/%s", orgName, repoName)

	err := gherror.WithRetry(ctx, operation, func() error {
		var err error
		repository, _, err = githubClient.Repositories.Get(ctx, orgName, repoName)
		if err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		return nil, gherror.WrapAPIError(err, "fetching repository", orgName, repoName)
	}
	return repository, nil
}

// checkSecurityFeature checks if a security feature is enabled in SecurityAndAnalysis
// The getStatus function should return the status string from the specific feature type
func checkSecurityFeature(
	repoData *github.Repository,
	getStatus func(*github.SecurityAndAnalysis) string,
	err gherror.Error,
	orgName, repoName string,
	featureDescription string,
) {
	if repoData.SecurityAndAnalysis == nil {
		err.Emit("%s disabled in %s/%s", featureDescription, orgName, repoName)
		return
	}

	status := getStatus(repoData.SecurityAndAnalysis)
	if status != "enabled" {
		err.Emit("%s disabled in %s/%s", featureDescription, orgName, repoName)
	}
}

// checkBooleanSetting checks if a boolean setting matches expected value
func checkBooleanSetting(value bool, expected bool, err gherror.Error, msgFormat string, args ...interface{}) {
	if value != expected {
		err.Emit(msgFormat, args...)
	}
}
