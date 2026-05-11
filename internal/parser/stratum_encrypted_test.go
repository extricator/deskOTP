// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// --- Fixture generators ---

// pkcs7Pad pads data to a multiple of blockSize using PKCS7.
// This is a test-only helper used by generateStratumLegacyFixture.
func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+pad)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	return padded
}

// generateStratumCurrentFixture creates an in-memory Stratum current-format encrypted file.
//
// Binary layout:
//
//	[0:16]  16 bytes — "AUTHENTICATORPRO" magic
//	[16:32] 16 bytes — Argon2id salt
//	[32:44] 12 bytes — AES-GCM IV
//	[44:]   ciphertext + 16-byte GCM tag
//
// KDF: Argon2id, time=3, memory=65536 KiB (1<<16), threads=4, keyLen=32.
func generateStratumCurrentFixture(password string, entries []stratumEntry) ([]byte, error) {
	plainJSON, err := json.Marshal(stratumBackup{Authenticators: entries})
	if err != nil {
		return nil, err
	}

	const saltSize = 16
	const ivSize = 12

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	iv := make([]byte, ivSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Argon2id key derivation — MUST match decryptStratumCurrent parameters exactly.
	key := argon2.IDKey([]byte(password), salt, 3, 1<<16, 4, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertextWithTag := gcm.Seal(nil, iv, plainJSON, nil)

	// Build binary: magic + salt + iv + ciphertext+tag
	buf := make([]byte, stratumHeaderSize+saltSize+ivSize+len(ciphertextWithTag))
	copy(buf[0:stratumHeaderSize], stratumMagicCurrent)
	copy(buf[stratumHeaderSize:stratumHeaderSize+saltSize], salt)
	copy(buf[stratumHeaderSize+saltSize:stratumHeaderSize+saltSize+ivSize], iv)
	copy(buf[stratumHeaderSize+saltSize+ivSize:], ciphertextWithTag)

	return buf, nil
}

// generateStratumLegacyFixture creates an in-memory Stratum legacy-format encrypted file.
//
// Binary layout:
//
//	[0:16]  16 bytes — "AuthenticatorPro" magic
//	[16:36] 20 bytes — PBKDF2 salt
//	[36:52] 16 bytes — AES-CBC IV
//	[52:]   PKCS7-padded ciphertext
//
// KDF: PBKDF2-SHA1, 64000 iterations, 32-byte key.
func generateStratumLegacyFixture(password string, entries []stratumEntry) ([]byte, error) {
	plainJSON, err := json.Marshal(stratumBackup{Authenticators: entries})
	if err != nil {
		return nil, err
	}

	const saltSizeLegacy = 20
	const ivSizeCBC = 16

	salt := make([]byte, saltSizeLegacy)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	iv := make([]byte, ivSizeCBC)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	key := pbkdf2.Key([]byte(password), salt, 64000, 32, sha1.New)

	padded := pkcs7Pad(plainJSON, aes.BlockSize)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ct := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct, padded)

	// Build binary: magic + salt + iv + ciphertext
	buf := make([]byte, stratumHeaderSize+saltSizeLegacy+ivSizeCBC+len(ct))
	copy(buf[0:stratumHeaderSize], stratumMagicLegacy)
	copy(buf[stratumHeaderSize:stratumHeaderSize+saltSizeLegacy], salt)
	copy(buf[stratumHeaderSize+saltSizeLegacy:stratumHeaderSize+saltSizeLegacy+ivSizeCBC], iv)
	copy(buf[stratumHeaderSize+saltSizeLegacy+ivSizeCBC:], ct)

	return buf, nil
}

// fixtureStratumEntries is a representative set of entries covering TOTP, HOTP, and Steam types.
// These values match the stratum_plain.json fixture format.
var fixtureStratumEntries = []stratumEntry{
	// TOTP: Deno / Mason (Type=2, Algo=0=SHA1)
	{
		Type:      2,
		Issuer:    "Deno",
		Username:  "Mason",
		Secret:    "4SJHB4GSD43FZBAI7C2HLRJGPQ",
		Algorithm: 0,
		Digits:    6,
		Period:    30,
	},
	// HOTP: Issuu / James (Type=1, counter=1)
	{
		Type:      1,
		Issuer:    "Issuu",
		Username:  "James",
		Secret:    "YOOMIXWS5GN6RTBPUFFWKTW5M4",
		Algorithm: 0,
		Digits:    6,
		Counter:   1,
	},
	// Steam: Boeing / Sophia (Type=4)
	{
		Type:      4,
		Issuer:    "Boeing",
		Username:  "Sophia",
		Secret:    "JRZCL47CMXVOQMNPZR2F7J4RGI",
		Algorithm: 0,
		Digits:    5,
		Period:    30,
	},
}

// --- Tests ---

// TestStratumEncrypted_Name verifies the parser name.
func TestStratumEncrypted_Name(t *testing.T) {
	p := &StratumEncryptedParser{}
	if got := p.Name(); got != "Stratum (Encrypted)" {
		t.Errorf("Name() = %q, want %q", got, "Stratum (Encrypted)")
	}
}

// TestStratumEncrypted_CanParse verifies detection of both encrypted formats,
// and rejection of plain Stratum JSON, empty data, and short data.
func TestStratumEncrypted_CanParse(t *testing.T) {
	currentFixture, err := generateStratumCurrentFixture("testpassword", fixtureStratumEntries)
	if err != nil {
		t.Fatalf("failed to generate current-format fixture: %v", err)
	}
	legacyFixture, err := generateStratumLegacyFixture("testpassword", fixtureStratumEntries)
	if err != nil {
		t.Fatalf("failed to generate legacy-format fixture: %v", err)
	}

	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "current-format fixture (AUTHENTICATORPRO header)",
			input: currentFixture,
			want:  true,
		},
		{
			name:  "legacy-format fixture (AuthenticatorPro header)",
			input: legacyFixture,
			want:  true,
		},
		{
			name:  "plain Stratum JSON returns false",
			input: []byte(`{"Authenticators":[]}`),
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
		{
			name:  "short data (< 16 bytes) returns false",
			input: []byte("AUTHENTIC"),
			want:  false,
		},
		{
			name:  "wrong 16-byte header returns false",
			input: append([]byte("WRONGHEADERVALUE"), make([]byte, 32)...),
			want:  false,
		},
	}

	p := &StratumEncryptedParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(tt.input)
			if got != tt.want {
				t.Errorf("CanParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestStratumEncrypted_Parse_EmptyPassword verifies that empty password returns ErrPasswordRequired.
func TestStratumEncrypted_Parse_EmptyPassword(t *testing.T) {
	currentFixture, err := generateStratumCurrentFixture("testpassword", fixtureStratumEntries)
	if err != nil {
		t.Fatalf("failed to generate fixture: %v", err)
	}

	p := &StratumEncryptedParser{}
	_, err = p.Parse(currentFixture, "")
	if err == nil {
		t.Fatal("Parse() with empty password returned nil error, want ErrPasswordRequired")
	}
	if !errors.Is(err, ErrPasswordRequired) {
		t.Errorf("Parse() error = %v, want ErrPasswordRequired", err)
	}
}

// TestStratumEncrypted_Parse_CurrentFormat verifies decryption of current-format
// (Argon2id + AES-GCM) files and correct entry field mapping.
func TestStratumEncrypted_Parse_CurrentFormat(t *testing.T) {
	currentFixture, err := generateStratumCurrentFixture("testpassword", fixtureStratumEntries)
	if err != nil {
		t.Fatalf("failed to generate current-format fixture: %v", err)
	}

	p := &StratumEncryptedParser{}
	entries, err := p.Parse(currentFixture, "testpassword")
	if err != nil {
		t.Fatalf("Parse() current-format returned unexpected error: %v", err)
	}

	// Fixture has 3 entries: TOTP (Deno/Mason), HOTP (Issuu/James), Steam (Boeing/Sophia)
	if len(entries) != 3 {
		t.Fatalf("Parse() returned %d entries, want 3", len(entries))
	}

	// Verify TOTP entry: Deno / Mason
	e0 := entries[0]
	if e0.Issuer != "Deno" {
		t.Errorf("entries[0].Issuer = %q, want %q", e0.Issuer, "Deno")
	}
	if e0.Name != "Mason" {
		t.Errorf("entries[0].Name = %q, want %q", e0.Name, "Mason")
	}
	if e0.Secret != "4SJHB4GSD43FZBAI7C2HLRJGPQ" {
		t.Errorf("entries[0].Secret = %q, want %q", e0.Secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ")
	}
	if e0.Type != "totp" {
		t.Errorf("entries[0].Type = %q, want %q", e0.Type, "totp")
	}
	if e0.Algo != "SHA1" {
		t.Errorf("entries[0].Algo = %q, want %q", e0.Algo, "SHA1")
	}
	if e0.Digits != 6 {
		t.Errorf("entries[0].Digits = %d, want 6", e0.Digits)
	}
	if e0.Period != 30 {
		t.Errorf("entries[0].Period = %d, want 30", e0.Period)
	}
	if e0.UUID == "" {
		t.Error("entries[0].UUID is empty, want non-empty synthetic UUID")
	}

	// Verify HOTP entry: Issuu / James
	e1 := entries[1]
	if e1.Issuer != "Issuu" {
		t.Errorf("entries[1].Issuer = %q, want %q", e1.Issuer, "Issuu")
	}
	if e1.Name != "James" {
		t.Errorf("entries[1].Name = %q, want %q", e1.Name, "James")
	}
	if e1.Type != "hotp" {
		t.Errorf("entries[1].Type = %q, want %q", e1.Type, "hotp")
	}
	if e1.Counter != 1 {
		t.Errorf("entries[1].Counter = %d, want 1", e1.Counter)
	}
	if e1.Period != 0 {
		t.Errorf("entries[1].Period = %d, want 0 (HOTP has no period)", e1.Period)
	}

	// Verify Steam entry: Boeing / Sophia
	e2 := entries[2]
	if e2.Issuer != "Boeing" {
		t.Errorf("entries[2].Issuer = %q, want %q", e2.Issuer, "Boeing")
	}
	if e2.Name != "Sophia" {
		t.Errorf("entries[2].Name = %q, want %q", e2.Name, "Sophia")
	}
	if e2.Type != "steam" {
		t.Errorf("entries[2].Type = %q, want %q", e2.Type, "steam")
	}
	if e2.Algo != "SHA1" {
		t.Errorf("entries[2].Algo = %q, want %q (Steam hardcodes SHA1)", e2.Algo, "SHA1")
	}
	if e2.Digits != 5 {
		t.Errorf("entries[2].Digits = %d, want 5 (Steam hardcodes 5 digits)", e2.Digits)
	}
	if e2.Period != 30 {
		t.Errorf("entries[2].Period = %d, want 30 (Steam hardcodes 30s)", e2.Period)
	}
}

// TestStratumEncrypted_Parse_LegacyFormat verifies decryption of legacy-format
// (PBKDF2-SHA1 + AES-CBC) files and correct entry field mapping.
func TestStratumEncrypted_Parse_LegacyFormat(t *testing.T) {
	legacyFixture, err := generateStratumLegacyFixture("testpassword", fixtureStratumEntries)
	if err != nil {
		t.Fatalf("failed to generate legacy-format fixture: %v", err)
	}

	p := &StratumEncryptedParser{}
	entries, err := p.Parse(legacyFixture, "testpassword")
	if err != nil {
		t.Fatalf("Parse() legacy-format returned unexpected error: %v", err)
	}

	// Fixture has 3 entries: TOTP (Deno/Mason), HOTP (Issuu/James), Steam (Boeing/Sophia)
	if len(entries) != 3 {
		t.Fatalf("Parse() returned %d entries, want 3", len(entries))
	}

	// Verify TOTP entry: Deno / Mason
	e0 := entries[0]
	if e0.Issuer != "Deno" {
		t.Errorf("entries[0].Issuer = %q, want %q", e0.Issuer, "Deno")
	}
	if e0.Name != "Mason" {
		t.Errorf("entries[0].Name = %q, want %q", e0.Name, "Mason")
	}
	if e0.Type != "totp" {
		t.Errorf("entries[0].Type = %q, want %q", e0.Type, "totp")
	}
	if e0.Algo != "SHA1" {
		t.Errorf("entries[0].Algo = %q, want %q", e0.Algo, "SHA1")
	}
	if e0.Digits != 6 {
		t.Errorf("entries[0].Digits = %d, want 6", e0.Digits)
	}
	if e0.Period != 30 {
		t.Errorf("entries[0].Period = %d, want 30", e0.Period)
	}

	// Verify HOTP entry: Issuu / James
	e1 := entries[1]
	if e1.Type != "hotp" {
		t.Errorf("entries[1].Type = %q, want %q", e1.Type, "hotp")
	}
	if e1.Counter != 1 {
		t.Errorf("entries[1].Counter = %d, want 1", e1.Counter)
	}

	// Verify Steam entry: Boeing / Sophia
	e2 := entries[2]
	if e2.Type != "steam" {
		t.Errorf("entries[2].Type = %q, want %q", e2.Type, "steam")
	}
	if e2.Algo != "SHA1" {
		t.Errorf("entries[2].Algo = %q (Steam hardcodes SHA1)", e2.Algo)
	}
	if e2.Digits != 5 {
		t.Errorf("entries[2].Digits = %d, want 5", e2.Digits)
	}
}

// TestStratumEncrypted_Parse_WrongPassword verifies that a wrong password returns ErrWrongPassword
// for both current and legacy formats.
func TestStratumEncrypted_Parse_WrongPassword(t *testing.T) {
	currentFixture, err := generateStratumCurrentFixture("testpassword", fixtureStratumEntries)
	if err != nil {
		t.Fatalf("failed to generate current-format fixture: %v", err)
	}
	legacyFixture, err := generateStratumLegacyFixture("testpassword", fixtureStratumEntries)
	if err != nil {
		t.Fatalf("failed to generate legacy-format fixture: %v", err)
	}

	tests := []struct {
		name    string
		fixture []byte
	}{
		{name: "current-format with wrong password", fixture: currentFixture},
		{name: "legacy-format with wrong password", fixture: legacyFixture},
	}

	p := &StratumEncryptedParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.Parse(tt.fixture, "wrongpassword")
			if err == nil {
				t.Fatal("Parse() with wrong password returned nil error, want ErrWrongPassword")
			}
			if !errors.Is(err, ErrWrongPassword) {
				t.Errorf("Parse() error = %v, want ErrWrongPassword", err)
			}
		})
	}
}

// TestPkcs7Unpad verifies correct unpadding and error conditions for pkcs7Unpad.
func TestPkcs7Unpad(t *testing.T) {
	const blockSize = 16

	t.Run("valid single-byte padding", func(t *testing.T) {
		// 15 data bytes + 1 pad byte (0x01)
		input := make([]byte, 16)
		for i := 0; i < 15; i++ {
			input[i] = 0xAA
		}
		input[15] = 0x01

		got, err := pkcs7Unpad(input, blockSize)
		if err != nil {
			t.Fatalf("pkcs7Unpad() error = %v, want nil", err)
		}
		if len(got) != 15 {
			t.Errorf("len(got) = %d, want 15", len(got))
		}
	})

	t.Run("valid multi-byte padding (0x03 0x03 0x03)", func(t *testing.T) {
		// 13 data bytes + 3 pad bytes (0x03)
		input := make([]byte, 16)
		for i := 0; i < 13; i++ {
			input[i] = 0xBB
		}
		input[13] = 0x03
		input[14] = 0x03
		input[15] = 0x03

		got, err := pkcs7Unpad(input, blockSize)
		if err != nil {
			t.Fatalf("pkcs7Unpad() error = %v, want nil", err)
		}
		if len(got) != 13 {
			t.Errorf("len(got) = %d, want 13", len(got))
		}
	})

	t.Run("valid full-block padding (all 0x10)", func(t *testing.T) {
		// Full block of padding (16 bytes of 0x10)
		input := make([]byte, 32)
		for i := 0; i < 16; i++ {
			input[i] = 0xCC
		}
		for i := 16; i < 32; i++ {
			input[i] = 0x10 // 16 in decimal = 0x10
		}

		got, err := pkcs7Unpad(input, blockSize)
		if err != nil {
			t.Fatalf("pkcs7Unpad() error = %v, want nil", err)
		}
		if len(got) != 16 {
			t.Errorf("len(got) = %d, want 16", len(got))
		}
	})

	t.Run("error: empty input", func(t *testing.T) {
		_, err := pkcs7Unpad([]byte{}, blockSize)
		if err == nil {
			t.Fatal("pkcs7Unpad() returned nil error for empty input, want error")
		}
	})

	t.Run("error: non-block-aligned length", func(t *testing.T) {
		// 17 bytes is not a multiple of 16
		_, err := pkcs7Unpad(make([]byte, 17), blockSize)
		if err == nil {
			t.Fatal("pkcs7Unpad() returned nil error for non-aligned input, want error")
		}
	})

	t.Run("error: zero pad byte", func(t *testing.T) {
		input := make([]byte, 16) // all zeros — pad byte is 0x00
		_, err := pkcs7Unpad(input, blockSize)
		if err == nil {
			t.Fatal("pkcs7Unpad() returned nil error for zero pad byte, want error")
		}
	})

	t.Run("error: pad byte > blockSize", func(t *testing.T) {
		input := make([]byte, 16)
		input[15] = 0x11 // 17 > 16
		_, err := pkcs7Unpad(input, blockSize)
		if err == nil {
			t.Fatal("pkcs7Unpad() returned nil error for pad > blockSize, want error")
		}
	})

	t.Run("error: inconsistent pad bytes", func(t *testing.T) {
		// Claims 3 bytes of padding but last byte differs
		input := make([]byte, 16)
		input[13] = 0x03
		input[14] = 0x03
		input[15] = 0x02 // inconsistent — should all be 0x03
		_, err := pkcs7Unpad(input, blockSize)
		if err == nil {
			t.Fatal("pkcs7Unpad() returned nil error for inconsistent pad bytes, want error")
		}
	})
}
