// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"errors"
	"os"
	"testing"
)

// TestAegisEncryptedParser_CanParse verifies that CanParse returns true for encrypted
// Aegis vaults (non-null slots array) and false for all other inputs.
func TestAegisEncryptedParser_CanParse(t *testing.T) {
	encryptedFixture, err := os.ReadFile("testdata/aegis_encrypted.json")
	if err != nil {
		t.Fatalf("failed to read encrypted fixture: %v", err)
	}

	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "real encrypted vault fixture",
			input: encryptedFixture,
			want:  true,
		},
		{
			name:  "plain vault (null slots) -> false",
			input: []byte(`{"version":1,"header":{"slots":null,"params":null},"db":{"version":2,"entries":[]}}`),
			want:  false,
		},
		{
			name:  "random JSON object -> false",
			input: []byte(`{"foo":"bar"}`),
			want:  false,
		},
		{
			name:  "non-JSON input -> false",
			input: []byte("hello world"),
			want:  false,
		},
		{
			name:  "empty input -> false",
			input: []byte(""),
			want:  false,
		},
	}

	p := &AegisEncryptedParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(tt.input)
			if got != tt.want {
				t.Errorf("CanParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAegisEncryptedParser_Parse_CorrectPassword verifies that the real Aegis encrypted
// fixture (password: "test") decrypts to 7 entries with correct types and known UUIDs.
// Expected entries (from aegis_plain.json): 3 TOTP, 3 HOTP, 1 Steam.
func TestAegisEncryptedParser_Parse_CorrectPassword(t *testing.T) {
	data, err := os.ReadFile("testdata/aegis_encrypted.json")
	if err != nil {
		t.Fatalf("failed to read encrypted fixture: %v", err)
	}

	p := &AegisEncryptedParser{}
	entries, err := p.Parse(data, "test")
	if err != nil {
		t.Fatalf("Parse(data, \"test\") returned unexpected error: %v", err)
	}

	if len(entries) != 7 {
		t.Fatalf("Parse() returned %d entries, want 7", len(entries))
	}

	// Count by type
	var totpCount, hotpCount, steamCount int
	for _, e := range entries {
		switch e.Type {
		case "totp":
			totpCount++
		case "hotp":
			hotpCount++
		case "steam":
			steamCount++
		}
	}
	if totpCount != 3 {
		t.Errorf("TOTP count = %d, want 3", totpCount)
	}
	if hotpCount != 3 {
		t.Errorf("HOTP count = %d, want 3", hotpCount)
	}
	if steamCount != 1 {
		t.Errorf("Steam count = %d, want 1", steamCount)
	}

	// Verify a known UUID from the fixture (first TOTP entry: Mason / Deno)
	firstUUID := entries[0].UUID
	if firstUUID != "3ae6f1ad-2e65-4ed2-a953-1ec0dff2386d" {
		t.Errorf("first entry UUID = %q, want %q", firstUUID, "3ae6f1ad-2e65-4ed2-a953-1ec0dff2386d")
	}
}

// TestAegisEncryptedParser_Parse_WrongPassword verifies that supplying an incorrect
// password returns ErrWrongPassword (verifiable with errors.Is).
func TestAegisEncryptedParser_Parse_WrongPassword(t *testing.T) {
	data, err := os.ReadFile("testdata/aegis_encrypted.json")
	if err != nil {
		t.Fatalf("failed to read encrypted fixture: %v", err)
	}

	p := &AegisEncryptedParser{}
	entries, err := p.Parse(data, "wrongpassword")
	if err == nil {
		t.Fatal("Parse() returned nil error for wrong password, want ErrWrongPassword")
	}
	if !errors.Is(err, ErrWrongPassword) {
		t.Errorf("errors.Is(err, ErrWrongPassword) = false, got error: %v", err)
	}
	if entries != nil {
		t.Errorf("Parse() returned non-nil entries for wrong password, want nil")
	}
}

// TestAegisEncryptedParser_Parse_EmptyPassword verifies that an empty password returns
// ErrPasswordRequired (sentinel for "no password provided yet") — not ErrWrongPassword.
// The frontend uses this sentinel to show the PasswordModal instead of an error message.
func TestAegisEncryptedParser_Parse_EmptyPassword(t *testing.T) {
	data, err := os.ReadFile("testdata/aegis_encrypted.json")
	if err != nil {
		t.Fatalf("failed to read encrypted fixture: %v", err)
	}

	p := &AegisEncryptedParser{}
	entries, err := p.Parse(data, "")
	if err == nil {
		t.Fatal("Parse() returned nil error for empty password, want ErrPasswordRequired")
	}
	if !errors.Is(err, ErrPasswordRequired) {
		t.Errorf("errors.Is(err, ErrPasswordRequired) = false, got error: %v", err)
	}
	if entries != nil {
		t.Errorf("Parse() returned non-nil entries for empty password, want nil")
	}
}

// TestImport_EncryptedVault_Dispatcher verifies the Import dispatcher routes encrypted
// vaults to AegisEncryptedParser (not AegisParser) and threads the password through.
func TestImport_EncryptedVault_Dispatcher(t *testing.T) {
	data, err := os.ReadFile("testdata/aegis_encrypted.json")
	if err != nil {
		t.Fatalf("failed to read encrypted fixture: %v", err)
	}

	entries, _, err := Import(data, "test")
	if err != nil {
		t.Fatalf("Import(data, \"test\") returned unexpected error: %v", err)
	}
	if len(entries) != 7 {
		t.Fatalf("Import() returned %d entries, want 7", len(entries))
	}
}

// TestImport_EncryptedVault_NoPassword verifies that Import propagates ErrPasswordRequired
// from AegisEncryptedParser when no password is supplied (empty string).
// This is the sentinel that app.go uses to show the PasswordModal.
func TestImport_EncryptedVault_NoPassword(t *testing.T) {
	data, err := os.ReadFile("testdata/aegis_encrypted.json")
	if err != nil {
		t.Fatalf("failed to read encrypted fixture: %v", err)
	}

	entries, _, err := Import(data, "")
	if err == nil {
		t.Fatal("Import() returned nil error for empty password, want ErrPasswordRequired")
	}
	if !errors.Is(err, ErrPasswordRequired) {
		t.Errorf("errors.Is(err, ErrPasswordRequired) = false, got error: %v", err)
	}
	_ = entries
}

// TestImport_EncryptedVault_WrongPassword verifies that Import propagates ErrWrongPassword
// from AegisEncryptedParser when a wrong password is supplied.
func TestImport_EncryptedVault_WrongPassword(t *testing.T) {
	data, err := os.ReadFile("testdata/aegis_encrypted.json")
	if err != nil {
		t.Fatalf("failed to read encrypted fixture: %v", err)
	}

	entries, _, err := Import(data, "wrong")
	if err == nil {
		t.Fatal("Import() returned nil error for wrong password, want ErrWrongPassword")
	}
	if !errors.Is(err, ErrWrongPassword) {
		t.Errorf("errors.Is(err, ErrWrongPassword) = false, got error: %v", err)
	}
	_ = entries
}
