// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

import (
	"testing"
)

// ---------------------------------------------------------------------------
// TestImportFile_Success: importing a valid Aegis plain backup adds entries.
// ---------------------------------------------------------------------------

func TestImportFile_Success(t *testing.T) {
	app := setupTestApp(t)

	result, err := app.ImportFile("internal/parser/testdata/aegis_plain.json", "")
	if err != nil {
		t.Fatalf("ImportFile() unexpected error: %v", err)
	}
	if result.Added <= 0 {
		t.Errorf("ImportFile() result.Added = %d, want > 0", result.Added)
	}
	if len(app.entryMgr.Snapshot()) == 0 {
		t.Error("ImportFile() entryMgr.Snapshot() is empty after import, want entries")
	}
}

// ---------------------------------------------------------------------------
// TestImportFile_EmptyPath: empty path (user cancelled) returns zero result, nil error.
// ---------------------------------------------------------------------------

func TestImportFile_EmptyPath(t *testing.T) {
	app := setupTestApp(t)

	result, err := app.ImportFile("", "")
	if err != nil {
		t.Fatalf("ImportFile(\"\", \"\") unexpected error: %v", err)
	}
	if result.Added != 0 {
		t.Errorf("ImportFile(\"\", \"\") result.Added = %d, want 0", result.Added)
	}
}

// ---------------------------------------------------------------------------
// TestImportFile_InvalidFile: non-existent file returns an error.
// ---------------------------------------------------------------------------

func TestImportFile_InvalidFile(t *testing.T) {
	app := setupTestApp(t)

	_, err := app.ImportFile("/nonexistent/file.json", "")
	if err == nil {
		t.Fatal("ImportFile() with non-existent file should return error, got nil")
	}
}
