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

	var ghErr *github.ErrorResponse
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
	if errors.As(err, &ghErr) {
		// Add request ID if available for support purposes
		if ghErr.Response != nil && ghErr.Response.Header != nil {
			requestID := ghErr.Response.Header.Get("X-GitHub-Request-Id")
			if requestID != "" {
				return fmt.Errorf("%s: %s (status: %d, request-id: %s)",
					context, ghErr.Message, ghErr.Response.StatusCode, requestID)
			}
		}
		return fmt.Errorf("%s: %s (status: %d)",
			context, ghErr.Message, ghErr.Response.StatusCode)
	}

	// Default error wrapping
	return fmt.Errorf("%s: %w", context, err)
}

// IsRetryableError determines if an error can be retried
func IsRetryableError(err error) bool {
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		// Retry on server errors and rate limits
		return ghErr.Response.StatusCode >= 500 ||
			ghErr.Response.StatusCode == http.StatusTooManyRequests ||
			ghErr.Response.StatusCode == http.StatusRequestTimeout
	}
	return false
}

// IsPermissionError checks if error is due to insufficient permissions
func IsPermissionError(err error) bool {
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		return ghErr.Response.StatusCode == http.StatusForbidden ||
			ghErr.Response.StatusCode == http.StatusUnauthorized
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
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		return ghErr.Response.StatusCode == http.StatusForbidden
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
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		return ghErr.Response.StatusCode == http.StatusNotFound
	}
	return false
}
