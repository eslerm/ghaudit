// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"net/http"
	"time"

	"github.com/google/go-github/v75/github"
	"golang.org/x/oauth2"
)

// Config holds GitHub client configuration
type Config struct {
	Token           string
	Timeout         time.Duration
	MaxIdleConns    int
	IdleConnTimeout time.Duration
}

// DefaultConfig provides sensible defaults
var DefaultConfig = Config{
	Timeout:         30 * time.Second,
	MaxIdleConns:    100,
	IdleConnTimeout: 90 * time.Second,
}

// NewGitHubClient creates an optimized GitHub client
func NewGitHubClient(ctx context.Context, config Config) *github.Client {
	// Create OAuth2 client with token
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: config.Token})

	// Customize the HTTP client for better performance
	httpClient := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			MaxIdleConns:        config.MaxIdleConns,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     config.IdleConnTimeout,
			// Enable HTTP/2
			ForceAttemptHTTP2: true,
			// Compression
			DisableCompression: false,
		},
	}

	// Wrap the OAuth transport with our custom transport
	httpClient.Transport = &oauth2.Transport{
		Source: ts,
		Base:   httpClient.Transport,
	}

	// Create GitHub client
	client := github.NewClient(httpClient)

	// Add custom user agent for better tracking
	client.UserAgent = "ghaudit/1.0 (+https://github.com/chainguard-dev/ghaudit)"

	return client
}

// RoundTripperFunc allows functions to implement http.RoundTripper
type RoundTripperFunc func(*http.Request) (*http.Response, error)

func (f RoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	// GitHubRequestIDKey is the context key for GitHub request ID
	GitHubRequestIDKey contextKey = "github-request-id"
)

// WithRequestID adds request tracking for debugging
func WithRequestID(transport http.RoundTripper) http.RoundTripper {
	return RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		// Add request ID header for tracking
		if req.Header.Get("X-Request-ID") == "" {
			req.Header.Set("X-Request-ID", generateRequestID())
		}

		resp, err := transport.RoundTrip(req)

		// Log request ID from response for correlation
		if resp != nil && resp.Header.Get("X-GitHub-Request-Id") != "" {
			// Store the GitHub request ID in context for potential debugging
			// Note: This context is not propagated back since req is not returned
			_ = context.WithValue(req.Context(), GitHubRequestIDKey, resp.Header.Get("X-GitHub-Request-Id"))
		}

		return resp, err
	})
}

// generateRequestID creates a unique request identifier
func generateRequestID() string {
	// Simple timestamp-based ID for now
	return time.Now().Format("20060102-150405.000")
}
