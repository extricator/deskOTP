// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// redirectToTempDir overrides the config directory to an isolated temp directory
// for the duration of the test. Prevents tests from touching ~/.config/deskotp/.
func redirectToTempDir(t *testing.T) {
	t.Helper()
	original := configDirOverride
	configDirOverride = t.TempDir()
	t.Cleanup(func() { configDirOverride = original })
}

// TestSaveLoad_RoundTrip verifies Set persists through a reload cycle.
func TestSaveLoad_RoundTrip(t *testing.T) {
	redirectToTempDir(t)

	s := New()
	if err := s.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if err := s.Set("theme", "dark"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Create a fresh store and reload from disk.
	s2 := New()
	if err := s2.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	got := s2.Get("theme")
	if got != "dark" {
		t.Errorf("Get(\"theme\") = %q, want \"dark\"", got)
	}
}

// TestLoad_MissingFile verifies that Load on an empty dir creates settings.json with "{}".
func TestLoad_MissingFile(t *testing.T) {
	redirectToTempDir(t)

	s := New()
	if err := s.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// File should now exist with empty JSON object.
	p, err := settingsPath()
	if err != nil {
		t.Fatalf("settingsPath() error = %v", err)
	}

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	trimmed := strings.TrimSpace(string(data))
	if trimmed != "{}" {
		t.Errorf("missing file created with content %q, want \"{}\"", trimmed)
	}
}

// TestGet_DefaultFallback verifies Get returns empty string for nonexistent keys.
func TestGet_DefaultFallback(t *testing.T) {
	redirectToTempDir(t)

	s := New()
	if err := s.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	got := s.Get("nonexistent")
	if got != "" {
		t.Errorf("Get(\"nonexistent\") = %q, want \"\"", got)
	}
}

// TestSave_FilePermissions verifies settings.json has 0600 permissions after Set.
func TestSave_FilePermissions(t *testing.T) {
	redirectToTempDir(t)

	s := New()
	if err := s.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if err := s.Set("theme", "dark"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	p, err := settingsPath()
	if err != nil {
		t.Fatalf("settingsPath() error = %v", err)
	}

	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("file permissions = %04o, want 0600", info.Mode().Perm())
	}
}

// TestSave_AtomicWrite_NoTempLeft verifies no *.tmp files remain after Set.
func TestSave_AtomicWrite_NoTempLeft(t *testing.T) {
	redirectToTempDir(t)

	s := New()
	if err := s.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if err := s.Set("theme", "dark"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	p, err := settingsPath()
	if err != nil {
		t.Fatalf("settingsPath() error = %v", err)
	}

	dir := filepath.Dir(p)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}

	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file left behind: %q", e.Name())
		}
	}
}

// TestSet_Overwrites verifies that Set overwrites previous values.
func TestSet_Overwrites(t *testing.T) {
	redirectToTempDir(t)

	s := New()
	if err := s.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if err := s.Set("theme", "dark"); err != nil {
		t.Fatalf("Set(dark) error = %v", err)
	}
	if err := s.Set("theme", "light"); err != nil {
		t.Fatalf("Set(light) error = %v", err)
	}

	got := s.Get("theme")
	if got != "light" {
		t.Errorf("Get(\"theme\") = %q, want \"light\"", got)
	}
}

// TestLoad_PreservesUnknownKeys verifies that unknown keys in the file are readable.
func TestLoad_PreservesUnknownKeys(t *testing.T) {
	redirectToTempDir(t)

	// Write a file with keys directly.
	p, err := settingsPath()
	if err != nil {
		t.Fatalf("settingsPath() error = %v", err)
	}

	// Ensure directory exists.
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	content := `{"theme":"dark","future":"val"}`
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	s := New()
	if err := s.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got := s.Get("theme"); got != "dark" {
		t.Errorf("Get(\"theme\") = %q, want \"dark\"", got)
	}
	if got := s.Get("future"); got != "val" {
		t.Errorf("Get(\"future\") = %q, want \"val\"", got)
	}
}
