// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"deskotp/internal/storage"
	"deskotp/internal/totp"
)

// TestCopyCodeUsageCount verifies that CopyCode increments UsageCount and persists.
//
// CopyCode calls runtime.ClipboardSetText which requires a live Wails context
// (panics without it). We test the entry mutation logic by directly exercising
// the Manager's GenerateAndAdvance (which is what CopyCode now delegates to).
func TestCopyCodeUsageCount(t *testing.T) {
	// Redirect storage to temp dir so tests don't corrupt real data
	restore := storage.SetConfigDirOverride(t.TempDir())
	defer restore()

	t.Run("TOTP entry: UsageCount increments from 0 to 1", func(t *testing.T) {
		app := setupTestApp(t)

		// Pre-populate the manager via AddEntry
		err := app.AddEntry("alice", "Example", "JBSWY3DPEHPK3PXP", "totp", "SHA1", 30, 6, 0, "", "", false)
		if err != nil {
			t.Fatalf("AddEntry: %v", err)
		}

		// Get the UUID from GetEntryGroups... actually get it from GetDetails via snapshot
		snap := app.entryMgr.Snapshot()
		if len(snap) == 0 {
			t.Fatal("no entries in manager after AddEntry")
		}
		id := snap[0].UUID

		// GenerateAndAdvance increments UsageCount (what CopyCode delegates to)
		_, err = app.entryMgr.GenerateAndAdvance(id, time.Now())
		if err != nil {
			t.Fatalf("GenerateAndAdvance: %v", err)
		}

		snap = app.entryMgr.Snapshot()
		if snap[0].UsageCount != 1 {
			t.Errorf("UsageCount = %d, want 1", snap[0].UsageCount)
		}
	})

	t.Run("HOTP entry: both Counter and UsageCount increment", func(t *testing.T) {
		app := setupTestApp(t)

		err := app.AddEntry("bob", "Corp", "JBSWY3DPEHPK3PXP", "hotp", "SHA1", 30, 6, 5, "", "", false)
		if err != nil {
			t.Fatalf("AddEntry: %v", err)
		}

		snap := app.entryMgr.Snapshot()
		if len(snap) == 0 {
			t.Fatal("no entries in manager after AddEntry")
		}
		id := snap[0].UUID
		initialCounter := snap[0].Counter

		_, err = app.entryMgr.GenerateAndAdvance(id, time.Now())
		if err != nil {
			t.Fatalf("GenerateAndAdvance: %v", err)
		}

		snap = app.entryMgr.Snapshot()
		if snap[0].Counter != initialCounter+1 {
			t.Errorf("Counter = %d, want %d", snap[0].Counter, initialCounter+1)
		}
		if snap[0].UsageCount != 1 {
			t.Errorf("UsageCount = %d, want 1", snap[0].UsageCount)
		}
	})

	t.Run("unknown UUID returns not-found", func(t *testing.T) {
		app := setupTestApp(t)

		_, err := app.entryMgr.GenerateAndAdvance("nonexistent", time.Now())
		if err == nil {
			t.Error("expected not-found error for unknown UUID")
		}
	})
}

// TestDoBackupWrite_LockedVault verifies that doBackupWriteAt silently skips
// (returns nil, no file written) when vault_enabled=true and vault is locked (BFMT-04).
func TestDoBackupWrite_LockedVault(t *testing.T) {
	tmpDir := t.TempDir()

	app := setupTestApp(t)
	if err := app.settings.Set("vault_enabled", "true"); err != nil {
		t.Fatalf("set vault_enabled: %v", err)
	}

	outPath := filepath.Join(tmpDir, "test.json")
	err := app.doBackupWriteAt(outPath)
	if err != nil {
		t.Fatalf("doBackupWriteAt: expected nil, got %v", err)
	}
	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Error("doBackupWriteAt: file was written for locked vault, expected no file")
	}
}

// TestExportNow_ProducesFile verifies ExportNow returns a non-empty path to an existing file.
func TestExportNow_ProducesFile(t *testing.T) {
	tmpDir := t.TempDir()

	app := setupTestApp(t)
	if err := app.settings.Set("backup_dir", tmpDir); err != nil {
		t.Fatalf("set backup_dir: %v", err)
	}
	app.entryMgr.Set([]totp.Entry{
		{
			UUID:   "exp-1",
			Name:   "alice",
			Issuer: "Example",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
		},
	})

	path, err := app.ExportNow()
	if err != nil {
		t.Fatalf("ExportNow: %v", err)
	}
	if path == "" {
		t.Fatal("ExportNow: expected non-empty path")
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("ExportNow: file not found at %q: %v", path, statErr)
	}
}

// TestExportNow_TimestampedFilename verifies the file produced by ExportNow matches
// the pattern deskotp-backup-YYYYMMDD-HHMMSS.json.
func TestExportNow_TimestampedFilename(t *testing.T) {
	tmpDir := t.TempDir()

	app := setupTestApp(t)
	if err := app.settings.Set("backup_dir", tmpDir); err != nil {
		t.Fatalf("set backup_dir: %v", err)
	}

	path, err := app.ExportNow()
	if err != nil {
		t.Fatalf("ExportNow: %v", err)
	}

	base := filepath.Base(path)
	pattern := regexp.MustCompile(`^deskotp-backup-\d{8}-\d{6}\.json$`)
	if !pattern.MatchString(base) {
		t.Errorf("ExportNow: filename %q does not match expected pattern deskotp-backup-YYYYMMDD-HHMMSS.json", base)
	}
}
