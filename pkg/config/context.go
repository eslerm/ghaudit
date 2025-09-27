// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import "context"

type contextKey string

const errorsOnlyKey contextKey = "errorsOnly"

// WithErrorsOnly adds the errorsOnly flag to the context
func WithErrorsOnly(ctx context.Context, errorsOnly bool) context.Context {
	return context.WithValue(ctx, errorsOnlyKey, errorsOnly)
}

// GetErrorsOnly retrieves the errorsOnly flag from the context
func GetErrorsOnly(ctx context.Context) bool {
	if v, ok := ctx.Value(errorsOnlyKey).(bool); ok {
		return v
	}
	return false
}
