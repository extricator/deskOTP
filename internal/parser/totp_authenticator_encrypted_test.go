// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// generateTotpAuthEncryptedFixture creates a synthetic TOTP Authenticator encrypted binary file.
//
// Format:
//  1. Build JSON: {"STATIC_TOTP_CODES_LIST": [entries]}
//  2. PKCS7-pad the JSON
//  3. Key derivation: SHA256(password)
//  4. AES-CBC encrypt with fixed zero IV
//  5. Base64-encode the ciphertext
//  6. Return base64 bytes (the file format is base64 text)
func generateTotpAuthEncryptedFixture(password string, entries []totpAuthEntry) ([]byte, error) {
	outerMap := map[string][]totpAuthEntry{
		"STATIC_TOTP_CODES_LIST": entries,
	}
	plainJSON, err := json.Marshal(outerMap)
	if err != nil {
		return nil, fmt.Errorf("generateTotpAuthEncryptedFixture: marshal: %w", err)
	}

	padded := pkcs7Pad(plainJSON, aes.BlockSize)

	keyBytes := sha256.Sum256([]byte(password))
	iv := make([]byte, 16) // fixed zero IV — matches decryptTotpAuthBinary

	block, err := aes.NewCipher(keyBytes[:])
	if err != nil {
		return nil, fmt.Errorf("generateTotpAuthEncryptedFixture: cipher: %w", err)
	}
	ct := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct, padded)

	encoded := base64.StdEncoding.EncodeToString(ct)
	return []byte(encoded), nil
}

// fixtureTotpAuthEntries contains a representative set of entries covering all
// supported secret bases (16=hex, 32=base32, 64=base64) for decodeTotpAuthSecret.
var fixtureTotpAuthEntries = []totpAuthEntry{
	// hex-encoded secret (base 16)
	{
		Base:   16,
		Key:    "E49270F0D21F365C8408F8B475C5267C",
		Name:   "mason",
		Issuer: "Deno",
		Digits: "6",
		Period: "30",
	},
	// base32-encoded secret (base 32)
	{
		Base:   32,
		Key:    "4SJHB4GSD43FZBAI7C2HLRJGPQ",
		Name:   "james",
		Issuer: "SPDX",
		Digits: "7",
		Period: "60",
	},
	// base64-encoded secret (base 64)
	{
		Base:   64,
		Key:    "5OM4WOOGPLQEF6UGN3CPEOOLWU==",
		Name:   "elijah",
		Issuer: "Airbnb",
		Digits: "8",
		Period: "30",
	},
}

// TestTotpAuthEncrypted_Name verifies the parser name.
func TestTotpAuthEncrypted_Name(t *testing.T) {
	p := &TotpAuthenticatorEncryptedParser{}
	if got := p.Name(); got != "TOTP Authenticator (Encrypted)" {
		t.Errorf("Name() = %q, want %q", got, "TOTP Authenticator (Encrypted)")
	}
}

// TestTotpAuthEncrypted_CanParse verifies that CanParse correctly identifies
// base64-encoded encrypted binary files, and rejects XML, JSON, raw binary, and empty data.
func TestTotpAuthEncrypted_CanParse(t *testing.T) {
	encryptedFixture, err := generateTotpAuthEncryptedFixture(totpAuthHardcodedPassword, fixtureTotpAuthEntries)
	if err != nil {
		t.Fatalf("failed to generate encrypted TOTP Authenticator fixture: %v", err)
	}

	// Load existing fixtures for false-positive checks.
	xmlFixture, err := os.ReadFile(filepath.Join("testdata", "totp_authenticator_internal.xml"))
	if err != nil {
		t.Fatalf("cannot read totp_authenticator_internal.xml: %v", err)
	}
	jsonFixture, err := os.ReadFile(filepath.Join("testdata", "stratum_plain.json"))
	if err != nil {
		t.Fatalf("cannot read stratum_plain.json: %v", err)
	}
	binFixture, err := os.ReadFile(filepath.Join("testdata", "andotp_encrypted_new.bin"))
	if err != nil {
		t.Fatalf("cannot read andotp_encrypted_new.bin: %v", err)
	}

	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "encrypted TOTP Authenticator binary (base64-encoded) returns true",
			input: encryptedFixture,
			want:  true,
		},
		{
			name:  "TOTP Authenticator XML (internal format) returns false",
			input: xmlFixture,
			want:  false,
		},
		{
			name:  "JSON data returns false",
			input: jsonFixture,
			want:  false,
		},
		{
			name:  "raw binary (andotp_encrypted_new.bin) returns false",
			input: binFixture,
			want:  false,
		},
		{
			name:  "empty data returns false",
			input: []byte{},
			want:  false,
		},
		{
			name:  "nil data returns false",
			input: nil,
			want:  false,
		},
	}

	p := &TotpAuthenticatorEncryptedParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(tt.input)
			if got != tt.want {
				t.Errorf("CanParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestTotpAuthEncrypted_Parse_HardcodedPassword verifies that a file encrypted with the
// hardcoded password "TotpAuthenticator" decrypts successfully without a user password.
// Passing empty string should NOT return ErrPasswordRequired.
func TestTotpAuthEncrypted_Parse_HardcodedPassword(t *testing.T) {
	fixture, err := generateTotpAuthEncryptedFixture(totpAuthHardcodedPassword, fixtureTotpAuthEntries)
	if err != nil {
		t.Fatalf("failed to generate fixture: %v", err)
	}

	p := &TotpAuthenticatorEncryptedParser{}
	// Pass empty string — hardcoded password should be tried silently first.
	entries, err := p.Parse(fixture, "")
	if err != nil {
		t.Fatalf("Parse() with hardcoded password returned unexpected error: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("Parse() returned 0 entries, want at least 1")
	}
}

// TestTotpAuthEncrypted_Parse_AltHardcodedPassword verifies that a file encrypted with the
// alternate hardcoded password "totpauthenticator" (lowercase) also decrypts without user prompt.
func TestTotpAuthEncrypted_Parse_AltHardcodedPassword(t *testing.T) {
	fixture, err := generateTotpAuthEncryptedFixture(totpAuthHardcodedPasswordAlt, fixtureTotpAuthEntries)
	if err != nil {
		t.Fatalf("failed to generate fixture: %v", err)
	}

	p := &TotpAuthenticatorEncryptedParser{}
	// Pass empty string — alternate hardcoded password should be tried silently.
	entries, err := p.Parse(fixture, "")
	if err != nil {
		t.Fatalf("Parse() with alternate hardcoded password returned unexpected error: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("Parse() returned 0 entries, want at least 1")
	}
}

// TestTotpAuthEncrypted_Parse_CustomPassword verifies that a file encrypted with a custom
// (non-hardcoded) password triggers ErrPasswordRequired when empty string is passed,
// and succeeds when the correct custom password is provided.
func TestTotpAuthEncrypted_Parse_CustomPassword(t *testing.T) {
	const customPassword = "my-custom-vault-password"
	fixture, err := generateTotpAuthEncryptedFixture(customPassword, fixtureTotpAuthEntries)
	if err != nil {
		t.Fatalf("failed to generate fixture: %v", err)
	}

	p := &TotpAuthenticatorEncryptedParser{}

	// Empty password: hardcoded passwords fail → should return ErrPasswordRequired.
	_, err = p.Parse(fixture, "")
	if err == nil {
		t.Fatal("Parse() with empty password returned nil error, want ErrPasswordRequired")
	}
	if !errors.Is(err, ErrPasswordRequired) {
		t.Errorf("Parse() with empty password error = %v, want ErrPasswordRequired", err)
	}

	// Correct custom password: should succeed.
	entries, err := p.Parse(fixture, customPassword)
	if err != nil {
		t.Fatalf("Parse() with correct custom password returned unexpected error: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("Parse() returned 0 entries, want at least 1")
	}
}

// TestTotpAuthEncrypted_Parse_WrongPassword verifies that a wrong password returns ErrWrongPassword.
func TestTotpAuthEncrypted_Parse_WrongPassword(t *testing.T) {
	const customPassword = "my-custom-vault-password"
	fixture, err := generateTotpAuthEncryptedFixture(customPassword, fixtureTotpAuthEntries)
	if err != nil {
		t.Fatalf("failed to generate fixture: %v", err)
	}

	p := &TotpAuthenticatorEncryptedParser{}
	_, err = p.Parse(fixture, "wrongpassword")
	if err == nil {
		t.Fatal("Parse() with wrong password returned nil error, want ErrWrongPassword")
	}
	if !errors.Is(err, ErrWrongPassword) {
		t.Errorf("Parse() error = %v, want ErrWrongPassword", err)
	}
}

// TestTotpAuthEncrypted_Parse_VerifyEntries verifies that decrypted entries have
// correct issuer, name, secret (via decodeTotpAuthSecret), digits, and period.
func TestTotpAuthEncrypted_Parse_VerifyEntries(t *testing.T) {
	// Use a fixture with only hex-encoded secrets (base 16) for deterministic secret comparison.
	entries := []totpAuthEntry{
		{
			Base:   16,
			Key:    "E49270F0D21F365C8408F8B475C5267C",
			Name:   "mason",
			Issuer: "Deno",
			Digits: "6",
			Period: "30",
		},
	}

	fixture, err := generateTotpAuthEncryptedFixture(totpAuthHardcodedPassword, entries)
	if err != nil {
		t.Fatalf("failed to generate fixture: %v", err)
	}

	p := &TotpAuthenticatorEncryptedParser{}
	got, err := p.Parse(fixture, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(got))
	}

	e := got[0]
	if e.Issuer != "Deno" {
		t.Errorf("Issuer = %q, want %q", e.Issuer, "Deno")
	}
	if e.Name != "mason" {
		t.Errorf("Name = %q, want %q", e.Name, "mason")
	}
	// Hex "E49270F0D21F365C8408F8B475C5267C" decoded to raw bytes then base32 encoded.
	// Verify via decodeTotpAuthSecret to get expected value.
	expectedSecret, err := decodeTotpAuthSecret(16, "E49270F0D21F365C8408F8B475C5267C")
	if err != nil {
		t.Fatalf("decodeTotpAuthSecret() reference call failed: %v", err)
	}
	if e.Secret != expectedSecret {
		t.Errorf("Secret = %q, want %q", e.Secret, expectedSecret)
	}
	if e.Digits != 6 {
		t.Errorf("Digits = %d, want 6", e.Digits)
	}
	if e.Period != 30 {
		t.Errorf("Period = %d, want 30", e.Period)
	}
	if e.Algo != "SHA1" {
		t.Errorf("Algo = %q, want SHA1", e.Algo)
	}
	if e.Type != "totp" {
		t.Errorf("Type = %q, want totp", e.Type)
	}
	if e.UUID == "" {
		t.Error("UUID is empty, want non-empty synthetic UUID")
	}
}
