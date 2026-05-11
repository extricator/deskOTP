// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// encryptAuthyEntry is the test-only inverse of decryptAuthyEntry.
// It PKCS7-pads the secret, derives a key via PBKDF2-SHA1, and AES-CBC-encrypts it
// with a fixed zero IV. Returns the base64-encoded ciphertext.
func encryptAuthyEntry(secret, salt, password string) (string, error) {
	key := pbkdf2.Key([]byte(password), []byte(salt), 1000, 32, sha1.New)
	iv := make([]byte, 16) // fixed zero IV — matches decryptAuthyEntry

	padded := pkcs7Pad([]byte(secret), aes.BlockSize)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("encryptAuthyEntry: cipher init: %w", err)
	}
	ct := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct, padded)

	return base64.StdEncoding.EncodeToString(ct), nil
}

// generateAuthyEncryptedFixture creates a synthetic Authy XML with per-entry encrypted secrets.
// It wraps the token slice as JSON inside the standard Authy Android XML structure.
// Tokens that have DecryptedSecret set will have their secrets encrypted using
// the provided password; tokens with only EncryptedSecret set are used directly
// (for injecting pre-encrypted entries or error-case entries).
func generateAuthyEncryptedFixture(password string, tokens []authyEncryptedToken) ([]byte, error) {
	// Encrypt any token that has DecryptedSecret but no EncryptedSecret yet.
	out := make([]authyEncryptedToken, len(tokens))
	for i, tok := range tokens {
		out[i] = tok
		if tok.DecryptedSecret != "" && tok.EncryptedSecret == "" && tok.SecretSeed == "" {
			enc, err := encryptAuthyEntry(tok.DecryptedSecret, tok.Salt, password)
			if err != nil {
				return nil, fmt.Errorf("generateAuthyEncryptedFixture: entry %d: %w", i, err)
			}
			out[i].EncryptedSecret = enc
			out[i].DecryptedSecret = "" // encrypted backup: no decryptedSecret field
		}
	}

	jsonBytes, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("generateAuthyEncryptedFixture: marshal: %w", err)
	}

	// XML-entity-encode the JSON so it embeds cleanly in XML attribute value context.
	// encoding/xml will decode entities on read, so we need to encode them on write.
	escaped := escapeForXMLAttr(string(jsonBytes))

	xml := fmt.Sprintf(
		"<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n    <string name=\"com.authy.storage.tokens.authenticator.key\">%s</string>\n</map>\n",
		escaped,
	)
	return []byte(xml), nil
}

// escapeForXMLAttr replaces characters that must be entity-encoded when embedding
// JSON inside an XML element's character data (not an attribute — chardata context).
// encoding/xml decodes &quot; -> " and &amp; -> & on read, so we encode in reverse.
func escapeForXMLAttr(s string) string {
	out := make([]byte, 0, len(s)+len(s)/4)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			out = append(out, []byte("&quot;")...)
		case '&':
			out = append(out, []byte("&amp;")...)
		case '<':
			out = append(out, []byte("&lt;")...)
		case '>':
			out = append(out, []byte("&gt;")...)
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}

// fixtureAuthyEncryptedTokens defines test entries covering all heuristic levels and skip logic.
//
// Level 1: originalIssuer set (Deno) — issuer=originalIssuer
// Level 2: originalName contains ":" (SPDX:James) — issuer=part before ":"
// Level 4: accountType set, no originalIssuer or colon (fallback to capitalize(accountType))
// SecretSeed-only: Authy-native entry — must be skipped
//
// All have Salt set (required for PBKDF2 key derivation).
var fixtureAuthyEncryptedTokens = []authyEncryptedToken{
	// Level 1: originalIssuer "Deno" → issuer=Deno, name=Mason
	{
		AccountType:     "authenticator",
		DecryptedSecret: "4SJHB4GSD43FZBAI7C2HLRJGPQ",
		Salt:            "saltfordeno12345",
		Digits:          6,
		OriginalIssuer:  "Deno",
		OriginalName:    "Deno:Mason",
		Name:            "Deno: Mason",
	},
	// Level 2: no originalIssuer, but originalName has ":" → issuer=SPDX, name=James
	{
		AccountType:     "authenticator",
		DecryptedSecret: "5OM4WOOGPLQEF6UGN3CPEOOLWU",
		Salt:            "saltforspx1234567",
		Digits:          7,
		OriginalIssuer:  "",
		OriginalName:    "SPDX:James",
		Name:            "SPDX: James",
	},
	// Level 4: no originalIssuer, no colon in originalName, no " - " in name → capitalize(accountType)
	{
		AccountType:     "authenticator",
		DecryptedSecret: "7ELGJSGXNCCTV3O6LKJWYFV2RA",
		Salt:            "saltforairbnb1234",
		Digits:          8,
		OriginalIssuer:  "",
		OriginalName:    "",
		Name:            "Elijah",
	},
	// SecretSeed-only entry — should be skipped (Authy-native, no TOTP equivalent)
	{
		AccountType: "authy",
		SecretSeed:  "someauthynativeseed",
		Digits:      7,
		Name:        "Authy Native",
	},
}

// TestAuthyEncrypted_Name verifies the parser name.
func TestAuthyEncrypted_Name(t *testing.T) {
	p := &AuthyEncryptedParser{}
	if got := p.Name(); got != "Authy (Encrypted)" {
		t.Errorf("Name() = %q, want %q", got, "Authy (Encrypted)")
	}
}

// TestAuthyEncrypted_CanParse verifies CanParse distinguishes encrypted from plain Authy XML,
// and rejects non-XML data.
func TestAuthyEncrypted_CanParse(t *testing.T) {
	encryptedFixture, err := generateAuthyEncryptedFixture("testpassword", fixtureAuthyEncryptedTokens)
	if err != nil {
		t.Fatalf("failed to generate encrypted Authy fixture: %v", err)
	}

	// Load the plain Authy XML fixture from testdata — must return false.
	plainAuthyXML := []byte(`<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="com.authy.storage.tokens.authenticator.key">[{"accountType":"authenticator","decryptedSecret":"4SJHB4GSD43FZBAI7C2HLRJGPQ","digits":6,"name":"Deno: Mason","originalIssuer":"Deno","originalName":"Deno:Mason"}]</string>
</map>`)

	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "encrypted Authy XML (has encryptedSecret) returns true",
			input: encryptedFixture,
			want:  true,
		},
		{
			name:  "plain Authy XML (decryptedSecret only) returns false",
			input: plainAuthyXML,
			want:  false,
		},
		{
			name:  "empty data returns false",
			input: []byte{},
			want:  false,
		},
		{
			name:  "JSON data returns false",
			input: []byte(`{"Authenticators":[]}`),
			want:  false,
		},
		{
			name:  "binary data returns false",
			input: []byte{0x00, 0x01, 0x02, 0x03},
			want:  false,
		},
	}

	p := &AuthyEncryptedParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(tt.input)
			if got != tt.want {
				t.Errorf("CanParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAuthyEncrypted_Parse_EmptyPassword verifies ErrPasswordRequired is returned
// before any decryption is attempted.
func TestAuthyEncrypted_Parse_EmptyPassword(t *testing.T) {
	encryptedFixture, err := generateAuthyEncryptedFixture("testpassword", fixtureAuthyEncryptedTokens)
	if err != nil {
		t.Fatalf("failed to generate fixture: %v", err)
	}

	p := &AuthyEncryptedParser{}
	_, err = p.Parse(encryptedFixture, "")
	if err == nil {
		t.Fatal("Parse() with empty password returned nil error, want ErrPasswordRequired")
	}
	if !errors.Is(err, ErrPasswordRequired) {
		t.Errorf("Parse() error = %v, want ErrPasswordRequired", err)
	}
}

// TestAuthyEncrypted_Parse_CorrectPassword verifies that a correct password decrypts
// all encrypted entries, resolves issuer/name via 4-level heuristic, and skips
// SecretSeed-only (Authy-native) entries.
func TestAuthyEncrypted_Parse_CorrectPassword(t *testing.T) {
	encryptedFixture, err := generateAuthyEncryptedFixture("testpassword", fixtureAuthyEncryptedTokens)
	if err != nil {
		t.Fatalf("failed to generate fixture: %v", err)
	}

	p := &AuthyEncryptedParser{}
	entries, err := p.Parse(encryptedFixture, "testpassword")
	if err != nil {
		t.Fatalf("Parse() with correct password returned unexpected error: %v", err)
	}

	// The fixture has 3 decryptable entries + 1 SecretSeed-only (skipped).
	// So we expect 3 entries.
	if len(entries) != 3 {
		t.Fatalf("Parse() returned %d entries, want 3", len(entries))
	}

	// Entry 0: Level-1 heuristic — originalIssuer="Deno" → issuer=Deno, name stripped
	e0 := entries[0]
	if e0.Issuer != "Deno" {
		t.Errorf("entries[0].Issuer = %q, want %q", e0.Issuer, "Deno")
	}
	// After resolveAuthyIssuerName with separator="" for level-1: name = "Deno: Mason" - "Deno" = ": Mason" → strip ": " → "Mason"
	if e0.Name != "Mason" {
		t.Errorf("entries[0].Name = %q, want %q", e0.Name, "Mason")
	}
	if e0.Secret != "4SJHB4GSD43FZBAI7C2HLRJGPQ" {
		t.Errorf("entries[0].Secret = %q, want %q", e0.Secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ")
	}
	if e0.Digits != 6 {
		t.Errorf("entries[0].Digits = %d, want 6", e0.Digits)
	}
	if e0.Algo != "SHA1" {
		t.Errorf("entries[0].Algo = %q, want %q", e0.Algo, "SHA1")
	}
	if e0.Period != 30 {
		t.Errorf("entries[0].Period = %d, want 30", e0.Period)
	}
	if e0.Type != "totp" {
		t.Errorf("entries[0].Type = %q, want %q", e0.Type, "totp")
	}
	if e0.UUID == "" {
		t.Error("entries[0].UUID is empty, want non-empty synthetic UUID")
	}

	// Entry 1: Level-2 heuristic — originalName="SPDX:James" → issuer=SPDX
	e1 := entries[1]
	if e1.Issuer != "SPDX" {
		t.Errorf("entries[1].Issuer = %q, want %q", e1.Issuer, "SPDX")
	}
	if e1.Secret != "5OM4WOOGPLQEF6UGN3CPEOOLWU" {
		t.Errorf("entries[1].Secret = %q, want %q", e1.Secret, "5OM4WOOGPLQEF6UGN3CPEOOLWU")
	}
	if e1.Digits != 7 {
		t.Errorf("entries[1].Digits = %d, want 7", e1.Digits)
	}

	// Entry 2: Level-4 heuristic — capitalize(accountType)="Authenticator"
	e2 := entries[2]
	if e2.Issuer != "Authenticator" {
		t.Errorf("entries[2].Issuer = %q, want %q", e2.Issuer, "Authenticator")
	}
	if e2.Secret != "7ELGJSGXNCCTV3O6LKJWYFV2RA" {
		t.Errorf("entries[2].Secret = %q, want %q", e2.Secret, "7ELGJSGXNCCTV3O6LKJWYFV2RA")
	}
	if e2.Digits != 8 {
		t.Errorf("entries[2].Digits = %d, want 8", e2.Digits)
	}
}

// TestAuthyEncrypted_Parse_WrongPassword verifies that a wrong password returns ErrWrongPassword
// when all entries fail PKCS7 unpadding.
func TestAuthyEncrypted_Parse_WrongPassword(t *testing.T) {
	encryptedFixture, err := generateAuthyEncryptedFixture("testpassword", fixtureAuthyEncryptedTokens)
	if err != nil {
		t.Fatalf("failed to generate fixture: %v", err)
	}

	p := &AuthyEncryptedParser{}
	_, err = p.Parse(encryptedFixture, "wrongpassword")
	if err == nil {
		t.Fatal("Parse() with wrong password returned nil error, want ErrWrongPassword")
	}
	if !errors.Is(err, ErrWrongPassword) {
		t.Errorf("Parse() error = %v, want ErrWrongPassword", err)
	}
}

// TestAuthyEncrypted_Parse_SkipsSecretSeedOnly verifies that Authy-native entries
// (secretSeed only, no decryptedSecret or encryptedSecret) are silently skipped.
func TestAuthyEncrypted_Parse_SkipsSecretSeedOnly(t *testing.T) {
	// Build a fixture with one encrypted entry and one secretSeed-only entry.
	tokens := []authyEncryptedToken{
		{
			AccountType:     "authenticator",
			DecryptedSecret: "4SJHB4GSD43FZBAI7C2HLRJGPQ",
			Salt:            "saltfordeno12345",
			Digits:          6,
			OriginalIssuer:  "Deno",
			OriginalName:    "Deno:Mason",
			Name:            "Deno: Mason",
		},
		{
			AccountType: "authy",
			SecretSeed:  "nativeseed",
			Name:        "Authy Native",
		},
	}

	fixture, err := generateAuthyEncryptedFixture("testpassword", tokens)
	if err != nil {
		t.Fatalf("failed to generate fixture: %v", err)
	}

	p := &AuthyEncryptedParser{}
	entries, err := p.Parse(fixture, "testpassword")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	// Only the encrypted entry should be returned; secretSeed entry is skipped.
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1 (secretSeed entry should be skipped)", len(entries))
	}
	if entries[0].Issuer != "Deno" {
		t.Errorf("entries[0].Issuer = %q, want %q", entries[0].Issuer, "Deno")
	}
}
