// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"os"
	"testing"
)

// TestGoogleAuthParser_Name verifies the parser returns the expected display name.
func TestGoogleAuthParser_Name(t *testing.T) {
	p := &GoogleAuthParser{}
	if got := p.Name(); got != "Google Authenticator" {
		t.Errorf("Name() = %q, want %q", got, "Google Authenticator")
	}
}

// TestGoogleAuthParser_CanParse verifies CanParse returns true for URI text files
// and false for JSON or empty input.
func TestGoogleAuthParser_CanParse(t *testing.T) {
	plainTxt, err := os.ReadFile("testdata/plain.txt")
	if err != nil {
		t.Fatalf("failed to read plain.txt fixture: %v", err)
	}
	enteTxt, err := os.ReadFile("testdata/ente_auth.txt")
	if err != nil {
		t.Fatalf("failed to read ente_auth.txt fixture: %v", err)
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
			want:  true,
		},
		{
			name:  "ente_auth.txt URI file",
			input: enteTxt,
			want:  true,
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
		{
			name:  "random text",
			input: []byte("hello world"),
			want:  false,
		},
	}

	p := &GoogleAuthParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(tt.input)
			if got != tt.want {
				t.Errorf("CanParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGoogleAuthParser_Parse_PlainTxt verifies Parse on plain.txt returns correct entries.
func TestGoogleAuthParser_Parse_PlainTxt(t *testing.T) {
	data, err := os.ReadFile("testdata/plain.txt")
	if err != nil {
		t.Fatalf("failed to read plain.txt: %v", err)
	}

	p := &GoogleAuthParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}

	// plain.txt has 7 entries (3 totp, 3 hotp, 1 steam)
	if len(entries) != 7 {
		t.Fatalf("Parse() returned %d entries, want 7", len(entries))
	}

	// Verify first entry: Deno:Mason TOTP
	e := entries[0]
	if e.Issuer != "Deno" {
		t.Errorf("entries[0].Issuer = %q, want %q", e.Issuer, "Deno")
	}
	if e.Name != "Mason" {
		t.Errorf("entries[0].Name = %q, want %q", e.Name, "Mason")
	}
	if e.Secret != "4SJHB4GSD43FZBAI7C2HLRJGPQ" {
		t.Errorf("entries[0].Secret = %q, want %q", e.Secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ")
	}
	if e.Type != "totp" {
		t.Errorf("entries[0].Type = %q, want %q", e.Type, "totp")
	}
	if e.Algo != "SHA1" {
		t.Errorf("entries[0].Algo = %q, want %q", e.Algo, "SHA1")
	}
	if e.Digits != 6 {
		t.Errorf("entries[0].Digits = %d, want 6", e.Digits)
	}
	if e.Period != 30 {
		t.Errorf("entries[0].Period = %d, want 30", e.Period)
	}
	if e.UUID == "" {
		t.Error("entries[0].UUID is empty, want non-empty UUID")
	}

	// Verify fourth entry: Issuu:James HOTP
	h := entries[3]
	if h.Issuer != "Issuu" {
		t.Errorf("entries[3].Issuer = %q, want %q", h.Issuer, "Issuu")
	}
	if h.Type != "hotp" {
		t.Errorf("entries[3].Type = %q, want %q", h.Type, "hotp")
	}
	if h.Counter != 1 {
		t.Errorf("entries[3].Counter = %d, want 1", h.Counter)
	}

	// Verify last entry: Boeing:Sophia Steam
	s := entries[6]
	if s.Issuer != "Boeing" {
		t.Errorf("entries[6].Issuer = %q, want %q", s.Issuer, "Boeing")
	}
	if s.Type != "steam" {
		t.Errorf("entries[6].Type = %q, want %q", s.Type, "steam")
	}
}

// TestGoogleAuthParser_Parse_EnteAuth verifies Parse on ente_auth.txt returns correct entries.
// Ente Auth adds a codeDisplay query param that ParseURI ignores — same parser handles it.
func TestGoogleAuthParser_Parse_EnteAuth(t *testing.T) {
	data, err := os.ReadFile("testdata/ente_auth.txt")
	if err != nil {
		t.Fatalf("failed to read ente_auth.txt: %v", err)
	}

	p := &GoogleAuthParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}

	// ente_auth.txt has 7 entries (same as plain.txt, different order)
	if len(entries) != 7 {
		t.Fatalf("Parse() returned %d entries, want 7", len(entries))
	}

	// Spot-check: first entry is Air Canada:Benjamin HOTP with codeDisplay param ignored
	e := entries[0]
	if e.Name != "Benjamin" {
		t.Errorf("entries[0].Name = %q, want %q", e.Name, "Benjamin")
	}
	if e.Type != "hotp" {
		t.Errorf("entries[0].Type = %q, want %q", e.Type, "hotp")
	}
	if e.Secret != "KUVJJOM753IHTNDSZVCNKL7GII" {
		t.Errorf("entries[0].Secret = %q, want %q", e.Secret, "KUVJJOM753IHTNDSZVCNKL7GII")
	}
	// UUID must be set
	if e.UUID == "" {
		t.Error("entries[0].UUID is empty, want non-empty UUID")
	}
}

// TestGoogleAuthParser_Parse_BlankLines verifies blank lines are skipped without error.
func TestGoogleAuthParser_Parse_BlankLines(t *testing.T) {
	data := []byte("otpauth://totp/Deno:Mason?secret=4SJHB4GSD43FZBAI7C2HLRJGPQ&issuer=Deno&algorithm=SHA1&digits=6&period=30\n\n\notpauth://totp/SPDX:James?secret=5OM4WOOGPLQEF6UGN3CPEOOLWU&issuer=SPDX&algorithm=SHA256&digits=7&period=20\n")

	p := &GoogleAuthParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error on input with blank lines: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("Parse() returned %d entries, want 2 (blank lines should be skipped)", len(entries))
	}
}

// TestGoogleAuthParser_Parse_PasswordIgnored verifies Parse ignores the password parameter.
func TestGoogleAuthParser_Parse_PasswordIgnored(t *testing.T) {
	data, err := os.ReadFile("testdata/plain.txt")
	if err != nil {
		t.Fatalf("failed to read plain.txt: %v", err)
	}

	p := &GoogleAuthParser{}
	entries, err := p.Parse(data, "somepassword")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 7 {
		t.Fatalf("Parse() returned %d entries, want 7", len(entries))
	}
}
