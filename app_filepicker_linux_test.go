// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

//go:build linux

package main

import (
	"strings"
	"testing"
)

// TestURIToPath_Valid verifies that a plain file:// URI returns the correct path.
func TestURIToPath_Valid(t *testing.T) {
	path, err := uriToPath("file:///home/alice/backup.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "/home/alice/backup.json" {
		t.Errorf("got %q, want %q", path, "/home/alice/backup.json")
	}
}

// TestURIToPath_SpacesDecoded verifies that percent-encoded spaces are decoded.
func TestURIToPath_SpacesDecoded(t *testing.T) {
	path, err := uriToPath("file:///home/alice/my%20file.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "/home/alice/my file.json" {
		t.Errorf("got %q, want %q", path, "/home/alice/my file.json")
	}
}

// TestURIToPath_UnicodeDecoded verifies that percent-encoded Unicode characters are decoded.
func TestURIToPath_UnicodeDecoded(t *testing.T) {
	path, err := uriToPath("file:///path/with/%C3%A9/file.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "/path/with/\u00e9/file.txt" {
		t.Errorf("got %q, want %q", path, "/path/with/\u00e9/file.txt")
	}
}

// TestURIToPath_NonFileScheme verifies that a non-file:// URI returns an error.
func TestURIToPath_NonFileScheme(t *testing.T) {
	_, err := uriToPath("https://example.com")
	if err == nil {
		t.Fatal("expected error for https:// URI, got nil")
	}
	want := `expected file:// URI, got scheme "https"`
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not contain %q", err.Error(), want)
	}
}

// TestURIToPath_EmptyString verifies that an empty string returns an error.
func TestURIToPath_EmptyString(t *testing.T) {
	_, err := uriToPath("")
	if err == nil {
		t.Fatal("expected error for empty URI, got nil")
	}
}
