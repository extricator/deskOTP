// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"deskotp/internal/totp"
)

// Hardcoded passwords for TOTP Authenticator encrypted binary format.
// These are tried silently before prompting the user.
//
// totpAuthHardcodedPassword is from Aegis TotpAuthenticatorImporter.java (authoritative source).
// totpAuthHardcodedPasswordAlt is the lowercase variant from rhtenhove.nl blog; tried for compatibility.
const totpAuthHardcodedPassword = "TotpAuthenticator"    // capital T — Aegis source
const totpAuthHardcodedPasswordAlt = "totpauthenticator" // lowercase — blog variant

// TotpAuthenticatorEncryptedParser implements BackupParser for TOTP Authenticator
// encrypted binary backup files (`.encrypt` or `.bin`).
//
// The file is a base64-encoded AES-CBC ciphertext. Key derivation uses SHA-256 of
// the password. The IV is a fixed 16-byte zero vector.
//
// After decryption, the plaintext is a JSON object with a single key whose value
// is an array of entries with the same structure as the internal XML format (PRSR-14).
//
// Hardcoded passwords are tried silently first:
//  1. "TotpAuthenticator" (capital T — from Aegis TotpAuthenticatorImporter.java)
//  2. "totpauthenticator" (lowercase — from rhtenhove.nl blog, for compatibility)
//
// If both hardcoded passwords fail and no user password is provided, ErrPasswordRequired
// is returned. If a user password fails, ErrWrongPassword is returned.
type TotpAuthenticatorEncryptedParser struct{}

func (p *TotpAuthenticatorEncryptedParser) Name() string { return "TOTP Authenticator (Encrypted)" }

// CanParse returns true if data is a TOTP Authenticator encrypted binary file.
//
// Detection criteria:
//  1. Not empty.
//  2. Data (trimmed of whitespace) is valid base64-encoded content.
//  3. The decoded bytes are block-aligned (multiple of 16 — AES block size).
//  4. Not valid JSON (excludes JSON-only formats).
//  5. Not XML (excludes all Android SharedPreferences formats).
//
// This distinguishes the encrypted binary format from the plain XML format (PRSR-14),
// JSON formats, and raw binary formats like andOTP encrypted.
func (p *TotpAuthenticatorEncryptedParser) CanParse(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Reject valid JSON — JSON formats cannot be base64-encoded binary.
	if json.Valid(data) {
		return false
	}

	// Reject XML by checking for XML declaration or <map root element.
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<map")) {
		return false
	}

	// Attempt base64 decode (trimming whitespace to handle trailing newlines).
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return false
	}

	// Decoded bytes must be block-aligned (AES-CBC ciphertext is always a multiple of 16).
	if len(decoded)%aes.BlockSize != 0 {
		return false
	}

	return true
}

// Parse decrypts a TOTP Authenticator encrypted binary backup and returns OTP entries.
//
// Decryption order:
//  1. Try hardcoded "TotpAuthenticator" silently — return entries if successful.
//  2. Try alternate "totpauthenticator" silently — return entries if successful.
//  3. If both fail and password == "": return nil, ErrPasswordRequired.
//  4. Try user-supplied password — return entries if successful.
//  5. All attempts failed: return nil, ErrWrongPassword.
func (p *TotpAuthenticatorEncryptedParser) Parse(data []byte, password string) ([]totp.Entry, error) {
	// Step 1: Try primary hardcoded password silently.
	if entries, err := decryptTotpAuthBinary(data, totpAuthHardcodedPassword); err == nil {
		return entries, nil
	}

	// Step 2: Try alternate hardcoded password silently.
	if entries, err := decryptTotpAuthBinary(data, totpAuthHardcodedPasswordAlt); err == nil {
		return entries, nil
	}

	// Step 3: Both hardcoded passwords failed. Check if user provided a password.
	if password == "" {
		return nil, ErrPasswordRequired
	}

	// Step 4: Try user-supplied password.
	entries, err := decryptTotpAuthBinary(data, password)
	if err != nil {
		// Step 5: All attempts exhausted.
		return nil, ErrWrongPassword
	}
	return entries, nil
}

// decryptTotpAuthBinary decrypts a TOTP Authenticator encrypted file with the given password.
//
// Decryption:
//  1. Base64-decode the input (trim whitespace first).
//  2. Derive 32-byte key via SHA-256(password).
//  3. AES-256-CBC decrypt with fixed 16-byte zero IV.
//  4. PKCS7-unpad the plaintext.
//  5. Parse the resulting JSON via parseTotpAuthBinaryJSON.
func decryptTotpAuthBinary(data []byte, password string) ([]totp.Entry, error) {
	trimmed := strings.TrimSpace(string(data))
	ciphertext, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("totp authenticator encrypted: base64 decode: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("totp authenticator encrypted: ciphertext length %d not block-aligned", len(ciphertext))
	}

	keyBytes := sha256.Sum256([]byte(password))
	iv := make([]byte, 16) // fixed 16-byte zero IV — matches TotpAuthenticatorImporter.java

	block, err := aes.NewCipher(keyBytes[:])
	if err != nil {
		return nil, fmt.Errorf("totp authenticator encrypted: cipher init: %w", err)
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	unpadded, err := pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		// PKCS7 failure signals wrong password (CBC has no authentication tag).
		return nil, fmt.Errorf("totp authenticator encrypted: PKCS7 unpad: %w", err)
	}

	return parseTotpAuthBinaryJSON(unpadded)
}

// parseTotpAuthBinaryJSON parses the decrypted JSON payload from a TOTP Authenticator binary backup.
//
// The JSON is a dict with exactly one key whose value is the entries array.
// This matches Aegis TotpAuthenticatorImporter.java: obj.names().get(0).
//
// Example: {"STATIC_TOTP_CODES_LIST": [{...}, ...]}
//
// Returns an error if the outer dict does not have exactly one key.
// Individual entries that fail decodeTotpAuthSecret are silently skipped
// (partial import preferred over total failure — same robustness policy as
// TotpAuthenticatorParser).
func parseTotpAuthBinaryJSON(data []byte) ([]totp.Entry, error) {
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(data, &outer); err != nil {
		return nil, fmt.Errorf("totp authenticator encrypted: outer JSON unmarshal: %w", err)
	}

	if len(outer) != 1 {
		return nil, fmt.Errorf("totp authenticator encrypted: outer JSON dict has %d keys, expected 1", len(outer))
	}

	// Extract the single value (entries array) — key name is not hardcoded.
	var rawEntries json.RawMessage
	for _, v := range outer {
		rawEntries = v
	}

	var tokens []totpAuthEntry
	if err := json.Unmarshal(rawEntries, &tokens); err != nil {
		return nil, fmt.Errorf("totp authenticator encrypted: entries JSON unmarshal: %w", err)
	}

	entries := make([]totp.Entry, 0, len(tokens))
	for _, tok := range tokens {
		secret, err := decodeTotpAuthSecret(tok.Base, tok.Key)
		if err != nil {
			// Skip entries with decode errors — partial import preferred.
			continue
		}

		digits, err := strconv.Atoi(tok.Digits)
		if err != nil || digits == 0 {
			digits = 6
		}

		period, err := strconv.Atoi(tok.Period)
		if err != nil || period == 0 {
			period = 30
		}

		entries = append(entries, totp.Entry{
			UUID:   uuid.New().String(),
			Issuer: tok.Issuer,
			Name:   tok.Name,
			Secret: secret,
			Algo:   "SHA1",   // TOTP Authenticator does not expose algorithm
			Digits: digits,
			Period: uint(period),
			Type:   "totp", // TOTP only
		})
	}

	return entries, nil
}
