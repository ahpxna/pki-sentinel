//go:build !(darwin || linux)

package main

import "sync"

var baselineStateFallbackMu sync.Mutex

func acquireBaselineStateLock(_ string) (func() error, error) {
	// Windows trust-store support is out of scope in v1. Keep same-process
	// callers serialized on other platforms so tests and future ports do not
	// silently regress to an unlocked read-modify-write transaction.
	baselineStateFallbackMu.Lock()
	return func() error {
		baselineStateFallbackMu.Unlock()
		return nil
	}, nil
}
