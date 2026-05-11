// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// generateTwoFASEncryptedFixture creates an encrypted 2FAS backup from the given services.
// The encryption uses PBKDF2-SHA256 + AES-256-GCM with random salt and IV.
// Format: {"schemaVersion": 4, "servicesEncrypted": "ciphertext:salt:iv"} (all base64-encoded).
func generateTwoFASEncryptedFixture(password string, services []twoFASEntry) ([]byte, error) {
	// Marshal services array to JSON plaintext.
	plainJSON, err := json.Marshal(services)
	if err != nil {
		return nil, err
	}

	// Generate random 16-byte salt and 12-byte IV.
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Derive 32-byte key via PBKDF2-SHA256.
	key := pbkdf2.Key([]byte(password), salt, 10000, 32, sha256.New)

	// Encrypt with AES-256-GCM (Seal appends the 16-byte GCM tag to ciphertext).
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, iv, plainJSON, nil) // includes GCM tag appended

	// Build servicesEncrypted: base64(ciphertext) + ":" + base64(salt) + ":" + base64(iv)
	servicesEncrypted := base64.StdEncoding.EncodeToString(ciphertext) +
		":" + base64.StdEncoding.EncodeToString(salt) +
		":" + base64.StdEncoding.EncodeToString(iv)

	// Marshal outer JSON.
	outer := struct {
		SchemaVersion     int    `json:"schemaVersion"`
		ServicesEncrypted string `json:"servicesEncrypted"`
	}{
		SchemaVersion:     4,
		ServicesEncrypted: servicesEncrypted,
	}
	return json.Marshal(outer)
}

// fixtureServices are the known entries used to generate testdata/twofas_encrypted.2fas.
// These mirror the v4 plain fixture to allow cross-format comparison.
var fixtureServices = []twoFASEntry{
	{
		Name:   "Deno",
		Secret: "4SJHB4GSD43FZBAI7C2HLRJGPQ",
		OTP: twoFASOTP{
			Label:     "Mason",
			Account:   "Mason",
			Issuer:    "Deno",
			Algorithm: "SHA1",
			Digits:    6,
			Period:    30,
			TokenType: strPtr("TOTP"),
		},
	},
	{
		Name:   "Issuu",
		Secret: "YOOMIXWS5GN6RTBPUFFWKTW5M4",
		OTP: twoFASOTP{
			Label:     "James",
			Account:   "James",
			Issuer:    "Issuu",
			Algorithm: "SHA1",
			Digits:    6,
			Counter:   1,
			TokenType: strPtr("HOTP"),
		},
	},
	{
		Name:   "Boeing",
		Secret: "JRZCL47CMXVOQMNPZR2F7J4RGI",
		OTP: twoFASOTP{
			Label:     "Sophia",
			Account:   "Sophia",
			Issuer:    "Boeing",
			Algorithm: "SHA1",
			Digits:    5,
			Period:    30,
			TokenType: strPtr("STEAM"),
		},
	},
}

// strPtr is a test helper to create a *string from a literal.
func strPtr(s string) *string { return &s }

// TestTwoFASEncrypted_Name verifies the parser's human-readable name.
func TestTwoFASEncrypted_Name(t *testing.T) {
	p := &TwoFASEncryptedParser{}
	if got := p.Name(); got != "2FAS (Encrypted)" {
		t.Errorf("Name() = %q, want %q", got, "2FAS (Encrypted)")
	}
}

// TestTwoFASEncrypted_CanParse verifies CanParse accepts encrypted 2FAS files
// and rejects plain 2FAS, Aegis, non-JSON, and empty data.
func TestTwoFASEncrypted_CanParse(t *testing.T) {
	encData, err := os.ReadFile("testdata/twofas_encrypted.2fas")
	if err != nil {
		t.Fatalf("failed to read encrypted 2FAS fixture: %v", err)
	}
	plainV1, err := os.ReadFile("testdata/2fas_schema_v1.json")
	if err != nil {
		t.Fatalf("failed to read plain 2FAS v1 fixture: %v", err)
	}
	plainV4, err := os.ReadFile("testdata/2fas_schema_v4.2fas")
	if err != nil {
		t.Fatalf("failed to read plain 2FAS v4 fixture: %v", err)
	}
	aegisPlain, err := os.ReadFile("testdata/aegis_plain.json")
	if err != nil {
		t.Fatalf("failed to read aegis_plain.json fixture: %v", err)
	}

	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "encrypted 2FAS fixture",
			input: encData,
			want:  true,
		},
		{
			name:  "plain 2FAS v1 (services array)",
			input: plainV1,
			want:  false,
		},
		{
			name:  "plain 2FAS v4 (services array)",
			input: plainV4,
			want:  false,
		},
		{
			name:  "Aegis plain vault",
			input: aegisPlain,
			want:  false,
		},
		{
			name:  "empty data",
			input: []byte{},
			want:  false,
		},
		{
			name:  "non-JSON binary data",
			input: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE},
			want:  false,
		},
		{
			name:  "JSON without servicesEncrypted",
			input: []byte(`{"schemaVersion":4,"services":[]}`),
			want:  false,
		},
		{
			name:  "JSON with empty servicesEncrypted",
			input: []byte(`{"schemaVersion":4,"servicesEncrypted":""}`),
			want:  false,
		},
	}

	p := &TwoFASEncryptedParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(tt.input)
			if got != tt.want {
				t.Errorf("CanParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestTwoFASEncrypted_Parse_EmptyPassword verifies ErrPasswordRequired on empty password.
func TestTwoFASEncrypted_Parse_EmptyPassword(t *testing.T) {
	encData, err := os.ReadFile("testdata/twofas_encrypted.2fas")
	if err != nil {
		t.Fatalf("failed to read encrypted 2FAS fixture: %v", err)
	}

	p := &TwoFASEncryptedParser{}
	_, err = p.Parse(encData, "")
	if !errors.Is(err, ErrPasswordRequired) {
		t.Errorf("Parse(empty password) error = %v, want ErrPasswordRequired", err)
	}
}

// TestTwoFASEncrypted_Parse_CorrectPassword verifies decryption returns expected entries.
func TestTwoFASEncrypted_Parse_CorrectPassword(t *testing.T) {
	encData, err := os.ReadFile("testdata/twofas_encrypted.2fas")
	if err != nil {
		t.Fatalf("failed to read encrypted 2FAS fixture: %v", err)
	}

	p := &TwoFASEncryptedParser{}
	entries, err := p.Parse(encData, "testpassword")
	if err != nil {
		t.Fatalf("Parse(correct password) returned error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("Parse() returned %d entries, want 3", len(entries))
	}

	// Verify TOTP entry: Deno/Mason
	totp := entries[0]
	if totp.Issuer != "Deno" {
		t.Errorf("entries[0].Issuer = %q, want %q", totp.Issuer, "Deno")
	}
	if totp.Name != "Mason" {
		t.Errorf("entries[0].Name = %q, want %q", totp.Name, "Mason")
	}
	if totp.Secret != "4SJHB4GSD43FZBAI7C2HLRJGPQ" {
		t.Errorf("entries[0].Secret = %q, want %q", totp.Secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ")
	}
	if totp.Type != "totp" {
		t.Errorf("entries[0].Type = %q, want %q", totp.Type, "totp")
	}
	if totp.Algo != "SHA1" {
		t.Errorf("entries[0].Algo = %q, want %q", totp.Algo, "SHA1")
	}
	if totp.Digits != 6 {
		t.Errorf("entries[0].Digits = %d, want 6", totp.Digits)
	}
	if totp.Period != 30 {
		t.Errorf("entries[0].Period = %d, want 30", totp.Period)
	}
	if totp.UUID == "" || len(totp.UUID) != 36 {
		t.Errorf("entries[0].UUID = %q, want 36-char UUID v4", totp.UUID)
	}

	// Verify HOTP entry: Issuu/James
	hotp := entries[1]
	if hotp.Issuer != "Issuu" {
		t.Errorf("entries[1].Issuer = %q, want %q", hotp.Issuer, "Issuu")
	}
	if hotp.Name != "James" {
		t.Errorf("entries[1].Name = %q, want %q", hotp.Name, "James")
	}
	if hotp.Type != "hotp" {
		t.Errorf("entries[1].Type = %q, want %q", hotp.Type, "hotp")
	}
	if hotp.Counter != 1 {
		t.Errorf("entries[1].Counter = %d, want 1", hotp.Counter)
	}
	if hotp.Period != 0 {
		t.Errorf("entries[1].Period = %d, want 0 (HOTP is counter-based)", hotp.Period)
	}

	// Verify Steam entry: Boeing/Sophia
	steam := entries[2]
	if steam.Issuer != "Boeing" {
		t.Errorf("entries[2].Issuer = %q, want %q", steam.Issuer, "Boeing")
	}
	if steam.Name != "Sophia" {
		t.Errorf("entries[2].Name = %q, want %q", steam.Name, "Sophia")
	}
	if steam.Type != "steam" {
		t.Errorf("entries[2].Type = %q, want %q", steam.Type, "steam")
	}
	if steam.Algo != "SHA1" {
		t.Errorf("entries[2].Algo = %q, want %q (Steam always SHA1)", steam.Algo, "SHA1")
	}
	if steam.Digits != 5 {
		t.Errorf("entries[2].Digits = %d, want 5 (Steam always 5)", steam.Digits)
	}
	if steam.Period != 30 {
		t.Errorf("entries[2].Period = %d, want 30 (Steam always 30s)", steam.Period)
	}

	// All UUIDs must be non-empty and unique.
	seen := make(map[string]int, len(entries))
	for i, e := range entries {
		if e.UUID == "" {
			t.Errorf("entries[%d].UUID is empty, want non-empty UUID v4", i)
			continue
		}
		if prev, dup := seen[e.UUID]; dup {
			t.Errorf("entries[%d].UUID = %q collides with entries[%d]", i, e.UUID, prev)
		}
		seen[e.UUID] = i
	}
}

// TestTwoFASEncrypted_Parse_WrongPassword verifies ErrWrongPassword on incorrect password.
func TestTwoFASEncrypted_Parse_WrongPassword(t *testing.T) {
	encData, err := os.ReadFile("testdata/twofas_encrypted.2fas")
	if err != nil {
		t.Fatalf("failed to read encrypted 2FAS fixture: %v", err)
	}

	p := &TwoFASEncryptedParser{}
	_, err = p.Parse(encData, "wrongpassword")
	if !errors.Is(err, ErrWrongPassword) {
		t.Errorf("Parse(wrong password) error = %v, want ErrWrongPassword", err)
	}
}

// TestTwoFASEncrypted_Parse_MalformedEncrypted verifies error on malformed servicesEncrypted.
func TestTwoFASEncrypted_Parse_MalformedEncrypted(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "only one part (no colons)",
			input: []byte(`{"schemaVersion":4,"servicesEncrypted":"onlyonepart"}`),
		},
		{
			name:  "only two parts (one colon)",
			input: []byte(`{"schemaVersion":4,"servicesEncrypted":"part1:part2"}`),
		},
		{
			name:  "invalid base64 in ciphertext",
			input: []byte(`{"schemaVersion":4,"servicesEncrypted":"not-valid-b64!!!:c2FsdA==:aXY="}`),
		},
	}

	p := &TwoFASEncryptedParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.Parse(tt.input, "testpassword")
			if err == nil {
				t.Error("Parse() returned nil error for malformed input, want non-nil error")
			}
		})
	}
}
