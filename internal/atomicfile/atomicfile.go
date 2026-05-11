// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteAtomic atomically writes data to path using a temp file in the same
// directory (avoids EXDEV cross-device rename). Creates the target directory
// with 0700 permissions. File is written with 0600 permissions.
func WriteAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("atomicfile: mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "atomicfile-*.tmp")
	if err != nil {
		return fmt.Errorf("atomicfile: create temp: %w", err)
	}
	success := false
	defer func() {
		if !success {
			tmp.Close()        //nolint:errcheck — best-effort cleanup
			os.Remove(tmp.Name()) //nolint:errcheck — best-effort cleanup
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("atomicfile: write: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		return fmt.Errorf("atomicfile: chmod: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("atomicfile: close: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("atomicfile: rename: %w", err)
	}
	success = true
	return nil
}
