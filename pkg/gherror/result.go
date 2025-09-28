// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package gherror

import (
	"io"
	"os"
	"sync"
)

// Result represents the outcome of a security check
type Result struct {
	Check    string                 `json:"check"`
	Org      string                 `json:"org,omitempty"`
	Repo     string                 `json:"repo,omitempty"`
	Status   string                 `json:"status"`             // "pass", "fail", "skip", "error"
	Severity string                 `json:"severity,omitempty"` // "error", "warning", "info"
	Message  string                 `json:"message,omitempty"`
	Value    interface{}            `json:"value,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Error    string                 `json:"error,omitempty"`
}

// ResultSet collects multiple check results
type ResultSet struct {
	Results []Result `json:"results"`
	format  string   // "github" (default), "json", "text"
	writer  io.Writer
	mu      sync.Mutex // For concurrent access
}

var globalResultSet *ResultSet
var globalMutex sync.Mutex

// NewResultSet creates a new result collector
func NewResultSet(format string) *ResultSet {
	if format == "" {
		format = "github" // Default to GitHub Actions format
	}
	return &ResultSet{
		format: format,
		writer: os.Stdout,
	}
}

// Add adds a result to the set
func (rs *ResultSet) Add(r Result) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.Results = append(rs.Results, r)

	// Don't emit for GitHub format - the checks handle this via err.Emit()
	// We only collect results for JSON/text output
}

// InitGlobalResultSet initializes the global result collector
func InitGlobalResultSet(format string) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	globalResultSet = NewResultSet(format)
}

// AddGlobalResult adds a result to the global collector if it exists
func AddGlobalResult(r Result) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	if globalResultSet != nil {
		globalResultSet.Add(r)
	}
}

// GetGlobalResultSet returns the global result set
func GetGlobalResultSet() *ResultSet {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	return globalResultSet
}

// IsJSONFormat checks if JSON output is requested
func IsJSONFormat() bool {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	return globalResultSet != nil && globalResultSet.format == "json"
}

// ShouldEmitGitHub checks if GitHub format output should be emitted
func ShouldEmitGitHub() bool {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	return globalResultSet == nil || globalResultSet.format == "github" || globalResultSet.format == ""
}

// Output writes all results in JSON format
func (rs *ResultSet) Output() error {
	return rs.OutputCompactJSON()
}

// Pass creates a passing result
func Pass(check string, org, repo string) Result {
	return Result{
		Check:  check,
		Org:    org,
		Repo:   repo,
		Status: "pass",
	}
}

// Fail creates a failing result
func Fail(check string, org, repo string, severity, message string) Result {
	return Result{
		Check:    check,
		Org:      org,
		Repo:     repo,
		Status:   "fail",
		Severity: severity,
		Message:  message,
	}
}

// Info creates an informational result
func Info(check string, org, repo string, message string) Result {
	return Result{
		Check:    check,
		Org:      org,
		Repo:     repo,
		Status:   "pass",
		Severity: "info",
		Message:  message,
	}
}

// Skip creates a skipped result
func Skip(check string, org, repo string, reason string) Result {
	return Result{
		Check:   check,
		Org:     org,
		Repo:    repo,
		Status:  "skip",
		Message: reason,
	}
}

// ErrorResult creates an error result
func ErrorResult(check string, org, repo string, err error) Result {
	return Result{
		Check:  check,
		Org:    org,
		Repo:   repo,
		Status: "error",
		Error:  err.Error(),
	}
}
