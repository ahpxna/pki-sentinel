//go:build darwin || linux

package main

import (
	"fmt"
	"os"
	"syscall"
)

func acquireBaselineStateLock(statePath string) (func() error, error) {
	root, stateName, err := openBaselineStateRoot(statePath)
	if err != nil {
		return nil, err
	}
	lockName := "." + stateName + ".lock"
	file, err := root.OpenFile(lockName, os.O_CREATE|os.O_RDWR, 0o600)
	_ = root.Close()
	if err != nil {
		return nil, fmt.Errorf("open baseline state lock: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("restrict baseline state lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock baseline state: %w", err)
	}
	return func() error {
		unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		closeErr := file.Close()
		if unlockErr != nil {
			return fmt.Errorf("unlock baseline state: %w", unlockErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close baseline state lock: %w", closeErr)
		}
		return nil
	}, nil
}
