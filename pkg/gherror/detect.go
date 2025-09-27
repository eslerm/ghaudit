// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package gherror

import "sync/atomic"

var hadErrors = atomic.Bool{}

// HadErrors returns true if any errors have been emitted.
func HadErrors() bool {
	return hadErrors.Load()
}

func sawError() {
	hadErrors.Store(true)
}
