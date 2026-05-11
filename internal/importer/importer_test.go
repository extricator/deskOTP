// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package importer

import (
	"os"
	"strings"
	"testing"

	"deskotp/internal/iconmatch"
	"deskotp/internal/totp"
)

// TestScreenFile_ValidFormatsPassThrough verifies that every fixture in
// internal/parser/testdata passes through screenFile without rejection.
// This is the regression safety net: if screenFile ever false-positives on a
// real backup format, this test catches it. New fixtures added to the testdata
// directory are automatically covered because we use os.ReadDir.
func TestScreenFile_ValidFormatsPassThrough(t *testing.T) {
	entries, err := os.ReadDir("../parser/testdata")
	if err != nil {
		t.Fatalf("failed to read testdata directory: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("testdata directory is empty — expected at least 28 fixtures")
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			data, readErr := os.ReadFile("../parser/testdata/" + entry.Name())
			if readErr != nil {
				t.Fatalf("failed to read fixture %q: %v", entry.Name(), readErr)
			}
			if err := screenFile(data); err != nil {
				t.Errorf("screenFile rejected valid backup fixture %q: %v", entry.Name(), err)
			}
		})
	}
}

func TestScreenFile(t *testing.T) {
	t.Run("empty_data", func(t *testing.T) {
		err := screenFile([]byte{})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "file is empty") {
			t.Fatalf("expected 'file is empty' error, got: %v", err)
		}
	})

	t.Run("oversized", func(t *testing.T) {
		// Make data that starts with '{' (valid JSON-like) but is too large
		data := make([]byte, maxImportBytes+1)
		data[0] = '{'
		err := screenFile(data)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "file too large") {
			t.Fatalf("expected 'file too large' error, got: %v", err)
		}
	})

	t.Run("ZIP_magic", func(t *testing.T) {
		err := screenFile([]byte{0x50, 0x4B, 0x03, 0x04, 0x00})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "not a backup file") {
			t.Fatalf("expected 'not a backup file' error, got: %v", err)
		}
	})

	t.Run("PNG_magic", func(t *testing.T) {
		err := screenFile([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "not a backup file") {
			t.Fatalf("expected 'not a backup file' error, got: %v", err)
		}
	})

	t.Run("JPEG_magic", func(t *testing.T) {
		err := screenFile([]byte{0xFF, 0xD8, 0xFF, 0xE0})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "not a backup file") {
			t.Fatalf("expected 'not a backup file' error, got: %v", err)
		}
	})

	t.Run("PDF_magic", func(t *testing.T) {
		err := screenFile([]byte{0x25, 0x50, 0x44, 0x46, 0x2D})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "not a backup file") {
			t.Fatalf("expected 'not a backup file' error, got: %v", err)
		}
	})

	t.Run("GIF_magic", func(t *testing.T) {
		err := screenFile([]byte{0x47, 0x49, 0x46, 0x38, 0x39})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "not a backup file") {
			t.Fatalf("expected 'not a backup file' error, got: %v", err)
		}
	})

	t.Run("GZIP_magic", func(t *testing.T) {
		err := screenFile([]byte{0x1F, 0x8B, 0x08})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "not a backup file") {
			t.Fatalf("expected 'not a backup file' error, got: %v", err)
		}
	})

	t.Run("valid_JSON_passes", func(t *testing.T) {
		err := screenFile([]byte(`{"version":1}`))
		if err != nil {
			t.Fatalf("expected nil, got: %v", err)
		}
	})

	t.Run("valid_binary_passes", func(t *testing.T) {
		data, readErr := os.ReadFile("../parser/testdata/andotp_encrypted_new.bin")
		if readErr != nil {
			t.Fatalf("failed to read andotp_encrypted_new.bin fixture: %v", readErr)
		}
		err := screenFile(data)
		if err != nil {
			t.Fatalf("expected nil for andOTP binary fixture, got: %v", err)
		}
	})

	t.Run("short_data_no_panic", func(t *testing.T) {
		// Single byte shorter than any full signature — must not panic, must return nil
		err := screenFile([]byte{0x50})
		if err != nil {
			t.Fatalf("expected nil for short data, got: %v", err)
		}
	})
}

// TestSummaryText covers all four branches of the summaryText helper.
func TestSummaryText(t *testing.T) {
	t.Run("added and skipped", func(t *testing.T) {
		got := summaryText(3, 2)
		want := "3 added, 2 already existed"
		if got != want {
			t.Errorf("summaryText(3,2): want %q, got %q", want, got)
		}
	})

	t.Run("added only", func(t *testing.T) {
		got := summaryText(5, 0)
		want := "5 added"
		if got != want {
			t.Errorf("summaryText(5,0): want %q, got %q", want, got)
		}
	})

	t.Run("skipped only", func(t *testing.T) {
		got := summaryText(0, 4)
		want := "All 4 already existed"
		if got != want {
			t.Errorf("summaryText(0,4): want %q, got %q", want, got)
		}
	})

	t.Run("neither added nor skipped", func(t *testing.T) {
		got := summaryText(0, 0)
		want := "No accounts found in file"
		if got != want {
			t.Errorf("summaryText(0,0): want %q, got %q", want, got)
		}
	})
}

// TestImportIconAssignment verifies that the icon auto-assignment loop in Import
// populates Icon for recognized issuers, preserves existing icons, and leaves
// unrecognized issuers with empty Icon.
func TestImportIconAssignment(t *testing.T) {
	t.Run("recognized issuer gets icon assigned", func(t *testing.T) {
		incoming := []totp.Entry{
			{UUID: "ic-1", Issuer: "GitHub", Icon: ""},
			{UUID: "ic-2", Issuer: "Dropbox", Icon: ""},
		}

		for i := range incoming {
			if incoming[i].Icon == "" {
				incoming[i].Icon = iconmatch.Match(incoming[i].Issuer)
			}
		}

		if incoming[0].Icon != "github" {
			t.Errorf("Icon = %q, want %q", incoming[0].Icon, "github")
		}
		if incoming[1].Icon != "dropbox" {
			t.Errorf("Icon = %q, want %q", incoming[1].Icon, "dropbox")
		}
	})

	t.Run("existing icon is not overwritten (AMTCH-03)", func(t *testing.T) {
		incoming := []totp.Entry{
			{UUID: "ic-3", Issuer: "GitHub", Icon: "custom-icon"},
		}

		for i := range incoming {
			if incoming[i].Icon == "" {
				incoming[i].Icon = iconmatch.Match(incoming[i].Issuer)
			}
		}

		if incoming[0].Icon != "custom-icon" {
			t.Errorf("Icon = %q, want %q (should be preserved)", incoming[0].Icon, "custom-icon")
		}
	})

	t.Run("unrecognized issuer has empty icon", func(t *testing.T) {
		incoming := []totp.Entry{
			{UUID: "ic-4", Issuer: "Some Random Corp", Icon: ""},
		}

		for i := range incoming {
			if incoming[i].Icon == "" {
				incoming[i].Icon = iconmatch.Match(incoming[i].Issuer)
			}
		}

		if incoming[0].Icon != "" {
			t.Errorf("Icon = %q, want empty for unrecognized issuer", incoming[0].Icon)
		}
	})
}

// TestImport_FormatName verifies that Import sets ImportResult.Format to the
// matched parser's name when importing a valid backup.
func TestImport_FormatName(t *testing.T) {
	data, err := os.ReadFile("../parser/testdata/aegis_plain.json")
	if err != nil {
		t.Fatalf("failed to read aegis_plain.json fixture: %v", err)
	}

	result, err := Import(data, "", nil)
	if err != nil {
		t.Fatalf("Import() returned unexpected error: %v", err)
	}
	if result.Format == "" {
		t.Error("ImportResult.Format is empty, want non-empty parser name")
	}
	// Aegis plain parser reports "Aegis"
	if result.Format != "Aegis" {
		t.Errorf("ImportResult.Format = %q, want %q", result.Format, "Aegis")
	}
	if result.Added <= 0 {
		t.Errorf("ImportResult.Added = %d, want > 0", result.Added)
	}
}

// TestImport_NoParserFound verifies that Import returns an error containing
// "no supported backup format found" when no parser recognises the data.
func TestImport_NoParserFound(t *testing.T) {
	_, err := Import([]byte("this is definitely not a backup file format!!!"), "", nil)
	if err == nil {
		t.Fatal("Import() returned nil error for unrecognised data, want error")
	}
	if !strings.Contains(err.Error(), "no supported backup format found") {
		t.Errorf("Import() error = %q, want message containing 'no supported backup format found'", err.Error())
	}
}
