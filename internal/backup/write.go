// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package backup

import (
	"os"
	"path/filepath"

	"deskotp/internal/atomicfile"
)

// WriteFile atomically writes data to outPath using a temp file in the same
// directory (avoids EXDEV cross-device rename). Permissions: dir 0700, file 0600.
func WriteFile(outPath string, data []byte) error {
	return atomicfile.WriteAtomic(outPath, data)
}

// DefaultDir returns the XDG-compliant default backup directory
// (~/.local/share/deskotp/backups).
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share", "deskotp", "backups")
}
