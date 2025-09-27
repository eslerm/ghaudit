// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"fmt"

	"github.com/chainguard-dev/ghaudit/pkg/gherror"
	"github.com/google/go-github/v75/github"
)

type RepoMapper interface {
	Execute(context.Context) error
}

type RepoFunc func(ctx context.Context, githubClient *github.Client, org, repo string) error

func NewRepoMapper(name string, githubClient *github.Client, org *string, rf RepoFunc) RepoMapper {
	return &repoMapper{
		name:         name,
		githubClient: githubClient,
		org:          org,
		rf:           rf,
	}
}

type repoMapper struct {
	name         string
	githubClient *github.Client
	org          *string
	rf           RepoFunc
}

func (rm *repoMapper) Execute(ctx context.Context) error {
	page := 0

	for {
		var repos []*github.Repository
		var resp *github.Response

		err := gherror.WithRetry(ctx, fmt.Sprintf("list %s repositories page %d", *rm.org, page), func() error {
			var err error
			repos, resp, err = rm.githubClient.Repositories.ListByOrg(ctx, *rm.org, &github.RepositoryListByOrgOptions{
				ListOptions: github.ListOptions{
					Page:    page,
					PerPage: 100,
				},
			})
			return err
		})
		if err != nil {
			return gherror.WrapAPIError(err, "listing repositories", *rm.org, "")
		}

		for _, repository := range repos {
			// Skip archived repositories.
			if repository.GetArchived() {
				continue
			}

			if err := rm.rf(ctx, rm.githubClient, *rm.org, repository.GetName()); err != nil {
				return fmt.Errorf("failed checking %s/%s: %w", *rm.org, repository.GetName(), err)
			}
		}

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	return nil
}
