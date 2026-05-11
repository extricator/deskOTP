// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package backup_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"deskotp/internal/backup"
)

// TestWriteFile verifies WriteFile writes correct content and sets file permissions
// to 0600. It also verifies that a newly created directory gets permissions 0700.
func TestWriteFile(t *testing.T) {
	base := t.TempDir()
	// Use a subdirectory that WriteFile itself will create, so we can check its perms.
	dir := filepath.Join(base, "backups")
	outPath := filepath.Join(dir, "test-backup.json")
	data := []byte(`{"test": true}`)

	if err := backup.WriteFile(outPath, data); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("file contents: got %q, want %q", got, data)
	}

	fi, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("Stat file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("file permission: got %o, want 0600", perm)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm != 0700 {
		t.Errorf("dir permission: got %o, want 0700", perm)
	}
}

// TestWriteFile_CreatesDir verifies WriteFile creates the target directory
// if it does not yet exist.
func TestWriteFile_CreatesDir(t *testing.T) {
	base := t.TempDir()
	subDir := filepath.Join(base, "new", "nested", "dir")
	outPath := filepath.Join(subDir, "backup.json")
	data := []byte(`{"created": true}`)

	if err := backup.WriteFile(outPath, data); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

// TestDefaultDir verifies DefaultDir returns a non-empty path ending with
// the expected XDG-compliant suffix.
func TestDefaultDir(t *testing.T) {
	dir := backup.DefaultDir()
	if dir == "" {
		t.Fatal("DefaultDir returned empty string")
	}
	if !strings.HasSuffix(dir, filepath.Join(".local", "share", "deskotp", "backups")) {
		t.Errorf("DefaultDir = %q, want suffix %q", dir, ".local/share/deskotp/backups")
	}
}
