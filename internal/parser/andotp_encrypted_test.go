// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	"golang.org/x/crypto/pbkdf2"
	"crypto/sha1"
)

// TestMain generates test fixture files if they don't already exist before running tests.
// This ensures the encrypted .bin fixtures are available for all test functions.
// Password used for fixtures: "testpassword"
// Entries: a subset of the andotp_plain.json fixture entries (TOTP, HOTP, STEAM types).
func TestMain(m *testing.M) {
	const fixturePassword = "testpassword"

	// Entries to encrypt — a representative subset of andotp_plain.json
	fixtureEntries := []andOTPEntry{
		// TOTP: Deno / Mason
		{
			Secret:    "4SJHB4GSD43FZBAI7C2HLRJGPQ======",
			Type:      "TOTP",
			Algorithm: "SHA1",
			Digits:    6,
			Period:    30,
			Label:     "Mason",
			Issuer:    "Deno",
		},
		// HOTP: Issuu / James
		{
			Secret:    "YOOMIXWS5GN6RTBPUFFWKTW5M4======",
			Type:      "HOTP",
			Algorithm: "SHA1",
			Digits:    6,
			Counter:   1,
			Label:     "James",
			Issuer:    "Issuu",
		},
		// STEAM: Boeing / Sophia
		{
			Secret:    "JRZCL47CMXVOQMNPZR2F7J4RGI======",
			Type:      "STEAM",
			Algorithm: "SHA1",
			Digits:    5,
			Period:    30,
			Label:     "Sophia",
			Issuer:    "Boeing",
		},
	}

	// Generate new-format fixture if it doesn't exist.
	newFixturePath := "testdata/andotp_encrypted_new.bin"
	if _, err := os.Stat(newFixturePath); os.IsNotExist(err) {
		data, err := generateAndOTPNewFormatFixture(fixturePassword, fixtureEntries)
		if err != nil {
			panic("TestMain: failed to generate new-format fixture: " + err.Error())
		}
		if err := os.WriteFile(newFixturePath, data, 0o644); err != nil {
			panic("TestMain: failed to write new-format fixture: " + err.Error())
		}
	}

	// Generate old-format fixture if it doesn't exist.
	oldFixturePath := "testdata/andotp_encrypted_old.bin"
	if _, err := os.Stat(oldFixturePath); os.IsNotExist(err) {
		data, err := generateAndOTPOldFormatFixture(fixturePassword, fixtureEntries)
		if err != nil {
			panic("TestMain: failed to generate old-format fixture: " + err.Error())
		}
		if err := os.WriteFile(oldFixturePath, data, 0o644); err != nil {
			panic("TestMain: failed to write old-format fixture: " + err.Error())
		}
	}

	// Generate 2FAS encrypted fixture if it doesn't exist.
	twoFASFixturePath := "testdata/twofas_encrypted.2fas"
	if _, err := os.Stat(twoFASFixturePath); os.IsNotExist(err) {
		data, err := generateTwoFASEncryptedFixture(fixturePassword, fixtureServices)
		if err != nil {
			panic("TestMain: failed to generate twofas_encrypted.2fas fixture: " + err.Error())
		}
		if err := os.WriteFile(twoFASFixturePath, data, 0o644); err != nil {
			panic("TestMain: failed to write twofas_encrypted.2fas fixture: " + err.Error())
		}
	}

	// Generate Stratum encrypted current-format fixture if it doesn't exist.
	stratumCurrentPath := "testdata/stratum_encrypted_current.bin"
	if _, err := os.Stat(stratumCurrentPath); os.IsNotExist(err) {
		data, err := generateStratumCurrentFixture(fixturePassword, fixtureStratumEntries)
		if err != nil {
			panic("TestMain: failed to generate stratum_encrypted_current.bin fixture: " + err.Error())
		}
		if err := os.WriteFile(stratumCurrentPath, data, 0o644); err != nil {
			panic("TestMain: failed to write stratum_encrypted_current.bin fixture: " + err.Error())
		}
	}

	// Generate Stratum encrypted legacy-format fixture if it doesn't exist.
	stratumLegacyPath := "testdata/stratum_encrypted_legacy.bin"
	if _, err := os.Stat(stratumLegacyPath); os.IsNotExist(err) {
		data, err := generateStratumLegacyFixture(fixturePassword, fixtureStratumEntries)
		if err != nil {
			panic("TestMain: failed to generate stratum_encrypted_legacy.bin fixture: " + err.Error())
		}
		if err := os.WriteFile(stratumLegacyPath, data, 0o644); err != nil {
			panic("TestMain: failed to write stratum_encrypted_legacy.bin fixture: " + err.Error())
		}
	}

	// Generate Authy encrypted fixture if it doesn't exist.
	authyEncryptedPath := "testdata/authy_encrypted.xml"
	if _, err := os.Stat(authyEncryptedPath); os.IsNotExist(err) {
		data, err := generateAuthyEncryptedFixture(fixturePassword, fixtureAuthyEncryptedTokens)
		if err != nil {
			panic("TestMain: failed to generate authy_encrypted.xml fixture: " + err.Error())
		}
		if err := os.WriteFile(authyEncryptedPath, data, 0o644); err != nil {
			panic("TestMain: failed to write authy_encrypted.xml fixture: " + err.Error())
		}
	}

	// Generate TOTP Authenticator encrypted fixture if it doesn't exist.
	// Uses the hardcoded password so cross-format matrix Import tests work without user password.
	totpAuthEncryptedPath := "testdata/totp_authenticator_encrypted.bin"
	if _, err := os.Stat(totpAuthEncryptedPath); os.IsNotExist(err) {
		data, err := generateTotpAuthEncryptedFixture(totpAuthHardcodedPassword, fixtureTotpAuthEntries)
		if err != nil {
			panic("TestMain: failed to generate totp_authenticator_encrypted.bin fixture: " + err.Error())
		}
		if err := os.WriteFile(totpAuthEncryptedPath, data, 0o644); err != nil {
			panic("TestMain: failed to write totp_authenticator_encrypted.bin fixture: " + err.Error())
		}
	}

	os.Exit(m.Run())
}

// generateAndOTPNewFormatFixture creates a new-format andOTP encrypted .bin file.
//
// Binary layout:
//
//	[0:4]   4-byte big-endian int32 — PBKDF2 iteration count (70000)
//	[4:16]  12 bytes — PBKDF2 salt
//	[16:28] 12 bytes — AES-GCM nonce
//	[28:]   remaining bytes — AES-GCM ciphertext + 16-byte GCM tag (appended by Seal)
//
// KDF: PBKDF2-SHA1, 70000 iterations, 32-byte key.
func generateAndOTPNewFormatFixture(password string, entries []andOTPEntry) ([]byte, error) {
	plainJSON, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}

	const iterations = 70000
	const saltSize = 12
	const nonceSize = 12

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	key := pbkdf2.Key([]byte(password), salt, iterations, 32, sha1.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// gcm.Seal appends the GCM tag to the ciphertext automatically.
	ciphertextWithTag := gcm.Seal(nil, nonce, plainJSON, nil)

	// Build binary: [4-byte big-endian iterations][12-byte salt][12-byte nonce][ciphertext+tag]
	buf := make([]byte, 4+saltSize+nonceSize+len(ciphertextWithTag))
	binary.BigEndian.PutUint32(buf[0:4], uint32(iterations))
	copy(buf[4:4+saltSize], salt)
	copy(buf[4+saltSize:4+saltSize+nonceSize], nonce)
	copy(buf[4+saltSize+nonceSize:], ciphertextWithTag)

	return buf, nil
}

// generateAndOTPOldFormatFixture creates an old-format andOTP encrypted .bin file.
//
// Binary layout:
//
//	[0:12]  12 bytes — AES-GCM nonce
//	[12:]   remaining bytes — AES-GCM ciphertext + 16-byte GCM tag (appended by Seal)
//
// KDF: single SHA-256 pass of password (NOT PBKDF2).
func generateAndOTPOldFormatFixture(password string, entries []andOTPEntry) ([]byte, error) {
	plainJSON, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}

	const nonceSize = 12

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	keyBytes := sha256.Sum256([]byte(password))

	block, err := aes.NewCipher(keyBytes[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertextWithTag := gcm.Seal(nil, nonce, plainJSON, nil)

	// Build binary: [12-byte nonce][ciphertext+tag]
	buf := make([]byte, nonceSize+len(ciphertextWithTag))
	copy(buf[0:nonceSize], nonce)
	copy(buf[nonceSize:], ciphertextWithTag)

	return buf, nil
}

// --- Tests ---

// TestAndOTPEncrypted_Name verifies the parser name.
func TestAndOTPEncrypted_Name(t *testing.T) {
	p := &AndOTPEncryptedParser{}
	if got := p.Name(); got != "andOTP (Encrypted)" {
		t.Errorf("Name() = %q, want %q", got, "andOTP (Encrypted)")
	}
}

// TestAndOTPEncrypted_CanParse verifies CanParse accepts binary (non-JSON-array) data
// and rejects JSON arrays and empty data.
//
// CanParse design: returns true for ANY non-empty non-JSON-array data. JSON objects
// (Aegis, Proton, etc.) also return true from this method alone — but in the registry,
// all JSON object parsers are registered BEFORE AndOTPEncryptedParser and claim those
// files before this parser is ever consulted. Only binary files reach this parser in practice.
//
// Tests verify the unit-level behavior, including that JSON arrays correctly return false.
func TestAndOTPEncrypted_CanParse(t *testing.T) {
	newFixture, err := os.ReadFile("testdata/andotp_encrypted_new.bin")
	if err != nil {
		t.Fatalf("failed to read new-format fixture: %v", err)
	}
	oldFixture, err := os.ReadFile("testdata/andotp_encrypted_old.bin")
	if err != nil {
		t.Fatalf("failed to read old-format fixture: %v", err)
	}
	andotpPlain, err := os.ReadFile("testdata/andotp_plain.json")
	if err != nil {
		t.Fatalf("failed to read andotp_plain.json: %v", err)
	}

	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "new-format binary fixture",
			input: newFixture,
			want:  true,
		},
		{
			name:  "old-format binary fixture",
			input: oldFixture,
			want:  true,
		},
		{
			// andOTP plain JSON is a JSON array — CanParse correctly returns false.
			// In the registry, AndOTPParser handles these; this parser never sees them.
			name:  "andOTP plain JSON (JSON array) returns false",
			input: andotpPlain,
			want:  false,
		},
		{
			name:  "empty data returns false",
			input: []byte{},
			want:  false,
		},
		{
			// JSON arrays are specifically rejected; JSON objects are not (registry handles ordering).
			name:  "valid JSON array returns false",
			input: []byte(`[{"type":"TOTP","secret":"AAAA"}]`),
			want:  false,
		},
		{
			name:  "empty JSON array returns false",
			input: []byte(`[]`),
			want:  false,
		},
	}

	p := &AndOTPEncryptedParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(tt.input)
			if got != tt.want {
				t.Errorf("CanParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAndOTPEncrypted_Parse_NewFormat verifies that a new-format .bin fixture
// decrypts correctly with the correct password and returns the expected entries.
func TestAndOTPEncrypted_Parse_NewFormat(t *testing.T) {
	data, err := os.ReadFile("testdata/andotp_encrypted_new.bin")
	if err != nil {
		t.Fatalf("failed to read new-format fixture: %v", err)
	}

	p := &AndOTPEncryptedParser{}
	entries, err := p.Parse(data, "testpassword")
	if err != nil {
		t.Fatalf("Parse() new-format returned unexpected error: %v", err)
	}

	// Fixture has 3 entries: TOTP (Deno/Mason), HOTP (Issuu/James), STEAM (Boeing/Sophia)
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
	if e0.Secret != "4SJHB4GSD43FZBAI7C2HLRJGPQ======" {
		t.Errorf("entries[0].Secret = %q, want %q", e0.Secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ======")
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
	if e1.Type != "hotp" {
		t.Errorf("entries[1].Type = %q, want %q", e1.Type, "hotp")
	}
	if e1.Counter != 1 {
		t.Errorf("entries[1].Counter = %d, want 1", e1.Counter)
	}
	if e1.Period != 0 {
		t.Errorf("entries[1].Period = %d, want 0 (HOTP has no period)", e1.Period)
	}

	// Verify STEAM entry: Boeing / Sophia
	e2 := entries[2]
	if e2.Issuer != "Boeing" {
		t.Errorf("entries[2].Issuer = %q, want %q", e2.Issuer, "Boeing")
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
		t.Errorf("entries[2].Period = %d, want 30 (Steam hardcodes 30s period)", e2.Period)
	}
}

// TestAndOTPEncrypted_Parse_OldFormat verifies that an old-format .bin fixture
// decrypts correctly with the correct password and returns the expected entries.
func TestAndOTPEncrypted_Parse_OldFormat(t *testing.T) {
	data, err := os.ReadFile("testdata/andotp_encrypted_old.bin")
	if err != nil {
		t.Fatalf("failed to read old-format fixture: %v", err)
	}

	p := &AndOTPEncryptedParser{}
	entries, err := p.Parse(data, "testpassword")
	if err != nil {
		t.Fatalf("Parse() old-format returned unexpected error: %v", err)
	}

	// Fixture has 3 entries: TOTP (Deno/Mason), HOTP (Issuu/James), STEAM (Boeing/Sophia)
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

	// Verify HOTP entry: Issuu / James
	e1 := entries[1]
	if e1.Issuer != "Issuu" {
		t.Errorf("entries[1].Issuer = %q, want %q", e1.Issuer, "Issuu")
	}
	if e1.Type != "hotp" {
		t.Errorf("entries[1].Type = %q, want %q", e1.Type, "hotp")
	}
	if e1.Counter != 1 {
		t.Errorf("entries[1].Counter = %d, want 1", e1.Counter)
	}

	// Verify STEAM entry: Boeing / Sophia
	e2 := entries[2]
	if e2.Issuer != "Boeing" {
		t.Errorf("entries[2].Issuer = %q, want %q", e2.Issuer, "Boeing")
	}
	if e2.Type != "steam" {
		t.Errorf("entries[2].Type = %q, want %q", e2.Type, "steam")
	}
}

// TestAndOTPEncrypted_Parse_EmptyPassword verifies that an empty password returns ErrPasswordRequired.
func TestAndOTPEncrypted_Parse_EmptyPassword(t *testing.T) {
	data, err := os.ReadFile("testdata/andotp_encrypted_new.bin")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	p := &AndOTPEncryptedParser{}
	_, err = p.Parse(data, "")
	if err == nil {
		t.Fatal("Parse() with empty password returned nil error, want ErrPasswordRequired")
	}
	if !errors.Is(err, ErrPasswordRequired) {
		t.Errorf("Parse() error = %v, want ErrPasswordRequired", err)
	}
}

// TestAndOTPEncrypted_Parse_WrongPassword verifies that a wrong password returns ErrWrongPassword
// after both new and old formats are tried and fail.
func TestAndOTPEncrypted_Parse_WrongPassword(t *testing.T) {
	data, err := os.ReadFile("testdata/andotp_encrypted_new.bin")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	p := &AndOTPEncryptedParser{}
	_, err = p.Parse(data, "wrongpassword")
	if err == nil {
		t.Fatal("Parse() with wrong password returned nil error, want ErrWrongPassword")
	}
	if !errors.Is(err, ErrWrongPassword) {
		t.Errorf("Parse() error = %v, want ErrWrongPassword", err)
	}
}

// TestAndOTPEncrypted_Parse_IterationGuard verifies that the PBKDF2 iteration count guard
// rejects values < 1 or > 10,000,000. When the new-format path rejects the data due to
// an invalid iteration count, the parser silently falls back to old-format. Since the data
// is also not a valid old-format file, the final result is ErrWrongPassword.
func TestAndOTPEncrypted_Parse_IterationGuard(t *testing.T) {
	tests := []struct {
		name       string
		iterations uint32
	}{
		{name: "zero iterations", iterations: 0},
		{name: "over-limit iterations (10_000_001)", iterations: 10_000_001},
		{name: "max uint32", iterations: 0xFFFFFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Craft a binary with the specified iteration count followed by
			// 12-byte salt, 12-byte nonce, and minimal ciphertext (all zeros).
			// This exercises the iteration guard in decryptAndOTPNewFormat.
			buf := make([]byte, 4+12+12+1) // 4+salt+nonce+1byte ciphertext
			binary.BigEndian.PutUint32(buf[0:4], tt.iterations)
			// Remaining bytes are zero-valued — invalid salt/nonce/ciphertext.
			// The iteration guard (or GCM decryption failure) will reject this in
			// new-format path; old-format also fails (invalid ciphertext) -> ErrWrongPassword.

			p := &AndOTPEncryptedParser{}
			_, err := p.Parse(buf, "testpassword")
			if err == nil {
				t.Fatalf("Parse() with iterations=%d returned nil error, want ErrWrongPassword", tt.iterations)
			}
			if !errors.Is(err, ErrWrongPassword) {
				t.Errorf("Parse() error = %v, want ErrWrongPassword", err)
			}
		})
	}
}
