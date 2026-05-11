// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package atomicfile_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"deskotp/internal/atomicfile"
)

// TestWriteAtomic_Content verifies WriteAtomic writes correct content to the target path.
func TestWriteAtomic_Content(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "file.dat")
	data := []byte("hello atomicfile")

	if err := atomicfile.WriteAtomic(path, data); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content: got %q, want %q", got, data)
	}
}

// TestWriteAtomic_FilePermissions verifies WriteAtomic sets file permissions to 0600.
func TestWriteAtomic_FilePermissions(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "file.dat")

	if err := atomicfile.WriteAtomic(path, []byte("data")); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("file permission: got %o, want 0600", perm)
	}
}

// TestWriteAtomic_CreatesParentDir verifies WriteAtomic creates parent directory
// with 0700 permissions if it does not exist.
func TestWriteAtomic_CreatesParentDir(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "newdir")
	path := filepath.Join(dir, "file.dat")

	if err := atomicfile.WriteAtomic(path, []byte("data")); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm != 0700 {
		t.Errorf("dir permission: got %o, want 0700", perm)
	}
}

// TestWriteAtomic_DeeplyNestedDir verifies WriteAtomic creates deeply nested directories.
func TestWriteAtomic_DeeplyNestedDir(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "a", "b", "c", "file.dat")

	if err := atomicfile.WriteAtomic(path, []byte("deep")); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created at deep path: %v", err)
	}
}

// TestWriteAtomic_NoTempFilesOnSuccess verifies WriteAtomic leaves no temp files
// in the directory on success — only the target file.
func TestWriteAtomic_NoTempFilesOnSuccess(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "data")
	path := filepath.Join(dir, "file.dat")

	if err := atomicfile.WriteAtomic(path, []byte("content")); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("directory contains %d files, want 1: %v", len(entries), names)
	}
	if entries[0].Name() != "file.dat" {
		t.Errorf("unexpected file: %q, want %q", entries[0].Name(), "file.dat")
	}
}

// TestWriteAtomic_Overwrites verifies WriteAtomic overwrites an existing file
// atomically (content fully replaced, not appended).
func TestWriteAtomic_Overwrites(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "file.dat")

	if err := atomicfile.WriteAtomic(path, []byte("original")); err != nil {
		t.Fatalf("WriteAtomic (first): %v", err)
	}
	if err := atomicfile.WriteAtomic(path, []byte("replaced")); err != nil {
		t.Fatalf("WriteAtomic (second): %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "replaced" {
		t.Errorf("content after overwrite: got %q, want %q", got, "replaced")
	}
}

// TestWriteAtomic_ErrorPrefix verifies WriteAtomic error messages start with "atomicfile: ".
func TestWriteAtomic_ErrorPrefix(t *testing.T) {
	// Attempt to write to a path whose parent we make read-only (unwritable).
	base := t.TempDir()
	dir := filepath.Join(base, "readonly")
	if err := os.MkdirAll(dir, 0500); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Restore permissions after test so TempDir cleanup works.
	t.Cleanup(func() { os.Chmod(dir, 0700) }) //nolint:errcheck

	path := filepath.Join(dir, "sub", "file.dat")
	err := atomicfile.WriteAtomic(path, []byte("data"))
	if err == nil {
		t.Fatal("expected error for unwritable parent, got nil")
	}
	if !strings.HasPrefix(err.Error(), "atomicfile: ") {
		t.Errorf("error %q does not start with %q", err.Error(), "atomicfile: ")
	}
}
