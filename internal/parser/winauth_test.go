// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"os"
	"testing"
)

// TestWinAuthParser_Name verifies WinAuthParser returns the expected display name.
func TestWinAuthParser_Name(t *testing.T) {
	p := &WinAuthParser{}
	if got := p.Name(); got != "WinAuth" {
		t.Errorf("Name() = %q, want %q", got, "WinAuth")
	}
}

// TestWinAuthParser_CanParse verifies CanParse always returns false.
// WinAuth cannot be auto-detected: its URI text format is identical to Google Auth.
// GoogleAuthParser is registered first and handles URI text files in auto-detection.
// WinAuthParser.CanParse always returns false so it does not shadow GoogleAuthParser.
func TestWinAuthParser_CanParse(t *testing.T) {
	plainTxt, err := os.ReadFile("testdata/plain.txt")
	if err != nil {
		t.Fatalf("failed to read plain.txt fixture: %v", err)
	}
	aegisJSON, err := os.ReadFile("testdata/aegis_plain.json")
	if err != nil {
		t.Fatalf("failed to read aegis_plain.json fixture: %v", err)
	}

	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "plain.txt URI file",
			input: plainTxt,
			want:  false, // always false — WinAuth cannot be auto-detected (identical format to Google Auth)
		},
		{
			name:  "aegis_plain.json JSON file",
			input: aegisJSON,
			want:  false,
		},
		{
			name:  "empty data",
			input: []byte{},
			want:  false,
		},
	}

	p := &WinAuthParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(tt.input)
			if got != tt.want {
				t.Errorf("CanParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestWinAuthParser_Parse_NameSwap verifies WinAuthParser applies the Aegis WinAuthImporter
// name swap: original Name becomes Issuer, and Name is set to "WinAuth" for all entries.
func TestWinAuthParser_Parse_NameSwap(t *testing.T) {
	data, err := os.ReadFile("testdata/plain.txt")
	if err != nil {
		t.Fatalf("failed to read plain.txt: %v", err)
	}

	// Also parse with GoogleAuthParser to get the original names for comparison.
	gp := &GoogleAuthParser{}
	origEntries, err := gp.Parse(data, "")
	if err != nil {
		t.Fatalf("GoogleAuthParser.Parse() returned unexpected error: %v", err)
	}

	wp := &WinAuthParser{}
	entries, err := wp.Parse(data, "")
	if err != nil {
		t.Fatalf("WinAuthParser.Parse() returned unexpected error: %v", err)
	}

	// Entry count must match GoogleAuthParser (same underlying file)
	if len(entries) != len(origEntries) {
		t.Fatalf("WinAuthParser.Parse() returned %d entries, want %d (same as GoogleAuthParser)", len(entries), len(origEntries))
	}

	// Verify name swap: original Name -> Issuer, Name -> "WinAuth"
	for i, e := range entries {
		orig := origEntries[i]

		// The original Name becomes the new Issuer
		if e.Issuer != orig.Name {
			t.Errorf("entries[%d].Issuer = %q, want %q (original Name)", i, e.Issuer, orig.Name)
		}

		// Name must be "WinAuth" for all entries
		if e.Name != "WinAuth" {
			t.Errorf("entries[%d].Name = %q, want %q", i, e.Name, "WinAuth")
		}

		// Other fields must be preserved
		if e.Secret != orig.Secret {
			t.Errorf("entries[%d].Secret = %q, want %q", i, e.Secret, orig.Secret)
		}
		if e.Type != orig.Type {
			t.Errorf("entries[%d].Type = %q, want %q", i, e.Type, orig.Type)
		}
	}
}

// TestWinAuthParser_Parse_EntryCount verifies WinAuthParser produces the same number
// of entries as GoogleAuthParser for the same fixture file.
func TestWinAuthParser_Parse_EntryCount(t *testing.T) {
	data, err := os.ReadFile("testdata/plain.txt")
	if err != nil {
		t.Fatalf("failed to read plain.txt: %v", err)
	}

	gp := &GoogleAuthParser{}
	gEntries, err := gp.Parse(data, "")
	if err != nil {
		t.Fatalf("GoogleAuthParser.Parse() returned unexpected error: %v", err)
	}

	wp := &WinAuthParser{}
	wEntries, err := wp.Parse(data, "")
	if err != nil {
		t.Fatalf("WinAuthParser.Parse() returned unexpected error: %v", err)
	}

	if len(wEntries) != len(gEntries) {
		t.Errorf("WinAuthParser returned %d entries, GoogleAuthParser returned %d — must be equal for same input", len(wEntries), len(gEntries))
	}
}

// TestWinAuthParser_Parse_UUIDGenerated verifies each WinAuth entry has a non-empty UUID.
func TestWinAuthParser_Parse_UUIDGenerated(t *testing.T) {
	data, err := os.ReadFile("testdata/plain.txt")
	if err != nil {
		t.Fatalf("failed to read plain.txt: %v", err)
	}

	wp := &WinAuthParser{}
	entries, err := wp.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}

	for i, e := range entries {
		if e.UUID == "" {
			t.Errorf("entries[%d].UUID is empty, want non-empty UUID", i)
		}
	}
}
