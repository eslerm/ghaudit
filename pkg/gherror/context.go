// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package gherror

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-github/v75/github"
)

// WrapAPIError adds context to GitHub API errors for better debugging
func WrapAPIError(err error, operation string, org string, repo string) error {
	if err == nil {
		return nil
	}

	var githubError *github.ErrorResponse
	var rateLimitErr *github.RateLimitError
	var abuseRateLimitErr *github.AbuseRateLimitError

	// Build the context string
	context := operation
	if org != "" {
		context = fmt.Sprintf("%s for %s", operation, org)
		if repo != "" {
			context = fmt.Sprintf("%s/%s", context, repo)
		}
	}

	// Handle rate limit errors
	if errors.As(err, &rateLimitErr) {
		return fmt.Errorf("%s: rate limit exceeded (resets at %s)",
			context, rateLimitErr.Rate.Reset.Time.Format("15:04:05"))
	}

	// Handle abuse rate limit errors
	if errors.As(err, &abuseRateLimitErr) {
		return fmt.Errorf("%s: abuse detection triggered (retry after %v)",
			context, abuseRateLimitErr.RetryAfter)
	}

	// Handle GitHub API errors with enhanced context
	if errors.As(err, &githubError) {
		// Add request ID if available for support purposes
		if githubError.Response != nil && githubError.Response.Header != nil {
			requestID := githubError.Response.Header.Get("X-GitHub-Request-Id")
			if requestID != "" {
				return fmt.Errorf("%s: %s (status: %d, request-id: %s)",
					context, githubError.Message, githubError.Response.StatusCode, requestID)
			}
		}
		return fmt.Errorf("%s: %s (status: %d)",
			context, githubError.Message, githubError.Response.StatusCode)
	}

	// Default error wrapping
	return fmt.Errorf("%s: %w", context, err)
}

// IsRetryableError determines if an error can be retried
func IsRetryableError(err error) bool {
	var githubError *github.ErrorResponse
	if errors.As(err, &githubError) && githubError.Response != nil {
		// Retry on server errors and rate limits
		return githubError.Response.StatusCode >= 500 ||
			githubError.Response.StatusCode == http.StatusTooManyRequests ||
			githubError.Response.StatusCode == http.StatusRequestTimeout
	}
	return false
}

// IsPermissionError checks if error is due to insufficient permissions
func IsPermissionError(err error) bool {
	var githubError *github.ErrorResponse
	if errors.As(err, &githubError) && githubError.Response != nil {
		return githubError.Response.StatusCode == http.StatusForbidden ||
			githubError.Response.StatusCode == http.StatusUnauthorized
	}
	return false
}

// Is403 checks if error is a 403 Forbidden error
func Is403(err error) bool {
	if err == nil {
		return false
	}

	// Check if the error contains a 403 status in the error message (for wrapped errors)
	errStr := err.Error()
	if strings.Contains(errStr, "status: 403") {
		return true
	}

	// Check the actual GitHub error
	var githubError *github.ErrorResponse
	if errors.As(err, &githubError) && githubError.Response != nil {
		return githubError.Response.StatusCode == http.StatusForbidden
	}
	return false
}

// Is404 checks if error is a 404 Not Found error
func Is404(err error) bool {
	if err == nil {
		return false
	}

	// Check if the error contains a 404 status in the error message (for wrapped errors)
	errStr := err.Error()
	if strings.Contains(errStr, "status: 404") {
		return true
	}

	// Check the actual GitHub error
	var githubError *github.ErrorResponse
	if errors.As(err, &githubError) && githubError.Response != nil {
		return githubError.Response.StatusCode == http.StatusNotFound
	}
	return false
}
