// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package backup

import (
	"os"
	"path/filepath"
	"sort"
)

// Rotate deletes the oldest backup files in dir beyond the retention count.
// Files matching "deskotp-backup-*.json" are sorted lexicographically
// (YYYYMMDD-HHMMSS filename format = chronological order).
// .tmp files are excluded by the glob pattern (BMGT-03).
// Returns first delete error encountered; continues deleting remaining files.
func Rotate(dir string, retention int) error {
	if retention <= 0 {
		return nil
	}

	files, err := filepath.Glob(filepath.Join(dir, "deskotp-backup-*.json"))
	if err != nil {
		return err
	}

	sort.Strings(files)

	if len(files) <= retention {
		return nil
	}

	toDelete := files[:len(files)-retention]

	var firstErr error
	for _, f := range toDelete {
		if err := os.Remove(f); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
