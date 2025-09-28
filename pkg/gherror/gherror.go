// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package gherror

// Error is an interface for emitting errors.
type Error interface {
	// Emit records an error (for JSON output).
	Emit(msg string, args ...interface{})
}

// New creates a new class of errors with the given title.
func New(title string) Error {
	return &errorImpl{title: title}
}

type errorImpl struct {
	title string
}

// Emit implements the Error interface.
func (e *errorImpl) Emit(msg string, args ...interface{}) {
	sawError()
	// Errors are now only recorded in the global result set for JSON output
	// No direct output to stdout
}
