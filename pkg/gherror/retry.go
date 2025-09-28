// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package gherror

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"time"

	"github.com/google/go-github/v75/github"
)

// RetryConfig defines retry behavior
type RetryConfig struct {
	MaxRetries     int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	BackoffFactor  float64
}

// DefaultRetryConfig provides sensible defaults for GitHub API
var DefaultRetryConfig = RetryConfig{
	MaxRetries:     3,
	InitialBackoff: 1 * time.Second,
	MaxBackoff:     32 * time.Second,
	BackoffFactor:  2.0,
}

// WithRetry executes a function with exponential backoff retry logic
func WithRetry(ctx context.Context, operation string, fn func() error) error {
	return WithRetryConfig(ctx, operation, fn, DefaultRetryConfig)
}

// WithRetryConfig executes a function with custom retry configuration
func WithRetryConfig(ctx context.Context, operation string, fn func() error, config RetryConfig) error {
	var lastErr error

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		// Check context before attempt
		if ctx.Err() != nil {
			return fmt.Errorf("%s cancelled: %w", operation, ctx.Err())
		}

		// Execute the function
		err := fn()
		if err == nil {
			return nil // Success
		}

		lastErr = err

		// Don't retry if context is cancelled
		if ctx.Err() != nil {
			return fmt.Errorf("%s cancelled after error: %w", operation, err)
		}

		// Check if error is retryable
		if !shouldRetry(err, attempt, config.MaxRetries) {
			return err
		}

		// Calculate backoff duration
		backoff := calculateBackoff(err, attempt, config)

		// Wait with jitter
		jitteredBackoff := addJitter(backoff)

		// Log retry attempt for debugging
		logRetryAttempt(operation, attempt, config.MaxRetries, jitteredBackoff, err)

		// Wait for backoff duration or context cancellation
		select {
		case <-time.After(jitteredBackoff):
			// Continue to next attempt
		case <-ctx.Done():
			return fmt.Errorf("%s cancelled during retry backoff: %w", operation, ctx.Err())
		}
	}

	return fmt.Errorf("%s failed after %d retries: %w", operation, config.MaxRetries, lastErr)
}

// shouldRetry determines if an error is retryable
func shouldRetry(err error, attempt int, maxRetries int) bool {
	if attempt >= maxRetries {
		return false
	}

	var ghErr *github.ErrorResponse
	var rateLimitErr *github.RateLimitError
	var abuseRateLimitErr *github.AbuseRateLimitError

	// Always retry rate limit errors
	if errors.As(err, &rateLimitErr) || errors.As(err, &abuseRateLimitErr) {
		return true
	}

	// Check GitHub API errors
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		switch ghErr.Response.StatusCode {
		case http.StatusTooManyRequests, // 429
			http.StatusRequestTimeout,     // 408
			http.StatusBadGateway,         // 502
			http.StatusServiceUnavailable, // 503
			http.StatusGatewayTimeout:     // 504
			return true
		case http.StatusUnauthorized, // 401
			http.StatusForbidden,           // 403
			http.StatusNotFound,            // 404
			http.StatusUnprocessableEntity: // 422
			return false // Don't retry client errors
		default:
			// Retry on 5xx errors
			return ghErr.Response.StatusCode >= 500
		}
	}

	// Don't retry unknown errors
	return false
}

// calculateBackoff determines the wait time based on error type and attempt
func calculateBackoff(err error, attempt int, config RetryConfig) time.Duration {
	var rateLimitErr *github.RateLimitError
	var abuseRateLimitErr *github.AbuseRateLimitError

	// Use rate limit reset time if available
	if errors.As(err, &rateLimitErr) {
		waitTime := time.Until(rateLimitErr.Rate.Reset.Time)
		if waitTime > 0 {
			// Add small buffer to avoid hitting limit exactly at reset
			return waitTime + (2 * time.Second)
		}
	}

	// Use abuse rate limit retry-after if available
	if errors.As(err, &abuseRateLimitErr) {
		if abuseRateLimitErr.RetryAfter != nil {
			return *abuseRateLimitErr.RetryAfter
		}
	}

	// Check for Retry-After header
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		if retryAfter := ghErr.Response.Header.Get("Retry-After"); retryAfter != "" {
			if seconds, err := time.ParseDuration(retryAfter + "s"); err == nil {
				return seconds
			}
		}
	}

	// Exponential backoff calculation
	backoff := float64(config.InitialBackoff) * math.Pow(config.BackoffFactor, float64(attempt))

	// Cap at max backoff
	if backoff > float64(config.MaxBackoff) {
		backoff = float64(config.MaxBackoff)
	}

	return time.Duration(backoff)
}

// addJitter adds random jitter to prevent thundering herd
func addJitter(duration time.Duration) time.Duration {
	// Add 0-20% jitter
	// #nosec G404 -- math/rand is acceptable for jitter calculation (non-cryptographic use)
	jitter := time.Duration(rand.Float64() * 0.2 * float64(duration))
	return duration + jitter
}

// logRetryAttempt logs retry information for debugging
func logRetryAttempt(_ string, _, _ int, _ time.Duration, _ error) {
	// No console output in JSON mode - retries are handled silently
	// Consider adding retry information to the JSON output if needed
}

// PreCheckRateLimit checks rate limits before making requests
func PreCheckRateLimit(ctx context.Context, client *github.Client) error {
	limits, _, err := client.RateLimit.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to check rate limits: %w", err)
	}

	// Check core API rate limit
	if limits.Core.Remaining < 10 {
		waitTime := time.Until(limits.Core.Reset.Time)
		if waitTime > 0 {
			return fmt.Errorf("rate limit too low (%d remaining), resets in %v at %s",
				limits.Core.Remaining,
				waitTime.Round(time.Second),
				limits.Core.Reset.Time.Format("15:04:05"))
		}
	}

	return nil
}

// GetRequestID extracts the GitHub request ID from an error for support
func GetRequestID(err error) string {
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		return ghErr.Response.Header.Get("X-GitHub-Request-Id")
	}
	return ""
}
