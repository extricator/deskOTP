// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"

	"deskotp/internal/totp"
)

// AuthyEncryptedParser implements BackupParser for Authy Android XML backups that
// use per-entry encryption. Each token has an encryptedSecret (base64-encoded
// AES-CBC ciphertext) and a salt (UTF-8 string for PBKDF2-SHA1 key derivation).
//
// Detection: same XML structure as AuthyParser, but at least one token has
// encryptedSecret set and decryptedSecret absent.
//
// Decryption: PBKDF2-SHA1 (1000 iterations, 256-bit key) + AES-CBC (16-byte zero IV).
// The plaintext is a base32 TOTP secret string.
//
// Wrong-password detection relies on PKCS7 unpad failure — AES-CBC has no
// authentication tag. If all entries fail unpadding, ErrWrongPassword is returned.
// If some succeed, a partial import is returned (robustness over completeness).
type AuthyEncryptedParser struct{}

// authyEncryptedToken extends the plain Authy token with per-entry encryption fields.
// The EncryptedSecret and Salt fields are present only in encrypted backups.
type authyEncryptedToken struct {
	AccountType     string `json:"accountType"`
	DecryptedSecret string `json:"decryptedSecret"` // present if already decrypted
	EncryptedSecret string `json:"encryptedSecret"` // base64-encoded AES-CBC ciphertext
	Salt            string `json:"salt"`             // UTF-8 salt for PBKDF2
	Digits          int    `json:"digits"`
	OriginalIssuer  string `json:"originalIssuer"`
	OriginalName    string `json:"originalName"`
	Name            string `json:"name"`
	SecretSeed      string `json:"secretSeed"` // Authy-native entries — skip
}

func (p *AuthyEncryptedParser) Name() string { return "Authy (Encrypted)" }

// CanParse returns true if data is an Authy XML backup with at least one encrypted entry.
//
// Detection logic:
//  1. Parse as Android SharedPreferences XML — reject if malformed.
//  2. Look for "com.authy.storage.tokens.authenticator.key" — reject if absent.
//  3. Parse the JSON token array.
//  4. Return true if at least one token has encryptedSecret set AND decryptedSecret absent.
//
// This distinguishes encrypted Authy backups from plain Authy backups, which only
// have decryptedSecret. Both formats share the same XML key.
func (p *AuthyEncryptedParser) CanParse(data []byte) bool {
	m, err := parseAndroidPrefsXML(data)
	if err != nil {
		return false
	}
	jsonStr, ok := m["com.authy.storage.tokens.authenticator.key"]
	if !ok {
		return false
	}

	var tokens []authyEncryptedToken
	if err := json.Unmarshal([]byte(jsonStr), &tokens); err != nil {
		return false
	}

	for _, tok := range tokens {
		if tok.EncryptedSecret != "" && tok.DecryptedSecret == "" {
			return true
		}
	}
	return false
}

// Parse decrypts an Authy encrypted XML backup and returns OTP entries.
//
// Parse flow:
//  1. Reject empty password with ErrPasswordRequired.
//  2. Parse XML and JSON token array.
//  3. For each token:
//     - SecretSeed-only (Authy-native, no encryptedSecret/decryptedSecret): skip.
//     - DecryptedSecret set: use directly (plain entry within an encrypted backup).
//     - EncryptedSecret set: decrypt via decryptAuthyEntry (PBKDF2-SHA1 + AES-CBC).
//     - Decryption failure: count as failed, continue.
//  4. If all encrypted entries failed: return nil, ErrWrongPassword.
//  5. Resolve issuer/name via resolveAuthyIssuerName (4-level heuristic).
//  6. Build totp.Entry with SHA1/30s/totp hardcoded (Authy format limitation).
func (p *AuthyEncryptedParser) Parse(data []byte, password string) ([]totp.Entry, error) {
	if password == "" {
		return nil, ErrPasswordRequired
	}

	m, err := parseAndroidPrefsXML(data)
	if err != nil {
		return nil, fmt.Errorf("authy encrypted: failed to parse XML: %w", err)
	}

	jsonStr, ok := m["com.authy.storage.tokens.authenticator.key"]
	if !ok {
		return nil, fmt.Errorf("authy encrypted: missing com.authy.storage.tokens.authenticator.key in XML")
	}

	var tokens []authyEncryptedToken
	if err := json.Unmarshal([]byte(jsonStr), &tokens); err != nil {
		return nil, fmt.Errorf("authy encrypted: failed to parse token JSON: %w", err)
	}

	entries := make([]totp.Entry, 0, len(tokens))
	encryptedTotal := 0
	encryptedFailed := 0

	for _, tok := range tokens {
		// Skip Authy-native entries that only have secretSeed (no TOTP equivalent).
		if tok.SecretSeed != "" && tok.DecryptedSecret == "" && tok.EncryptedSecret == "" {
			continue
		}

		var secret string
		if tok.DecryptedSecret != "" {
			// Already-decrypted entry within an encrypted backup — use directly.
			secret = tok.DecryptedSecret
		} else if tok.EncryptedSecret != "" {
			encryptedTotal++
			decrypted, err := decryptAuthyEntry(tok.EncryptedSecret, tok.Salt, password)
			if err != nil {
				encryptedFailed++
				continue
			}
			secret = decrypted
		} else {
			// No secret at all — skip.
			continue
		}

		issuer, name := resolveAuthyIssuerName(tok.OriginalIssuer, tok.OriginalName, tok.Name, tok.AccountType)

		digits := tok.Digits
		if digits == 0 {
			digits = 6
		}

		entries = append(entries, totp.Entry{
			UUID:   uuid.New().String(),
			Issuer: issuer,
			Name:   name,
			Secret: secret,
			Algo:   "SHA1", // Authy does not expose algorithm
			Digits: digits,
			Period: 30,     // Authy does not expose period
			Type:   "totp", // Authy does not support HOTP
		})
	}

	// If every encrypted entry failed to decrypt, the password is wrong.
	if encryptedTotal > 0 && encryptedFailed == encryptedTotal {
		return nil, ErrWrongPassword
	}

	return entries, nil
}

// decryptAuthyEntry decrypts a single Authy per-entry encrypted secret.
//
// Parameters:
//   - encryptedSecret: base64-encoded AES-CBC ciphertext
//   - salt: UTF-8 string used as PBKDF2 salt
//   - password: user-supplied vault password
//
// Decryption:
//  1. Base64-decode encryptedSecret → ciphertext bytes
//  2. Derive 32-byte key: PBKDF2-SHA1(password, salt, 1000 iterations)
//  3. Decrypt with AES-256-CBC using a fixed 16-byte zero IV
//  4. PKCS7-unpad the plaintext
//
// The unpadded result is the base32 TOTP secret string.
// PKCS7 unpad failure signals a wrong password (CBC has no authentication tag).
func decryptAuthyEntry(encryptedSecret, salt, password string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedSecret)
	if err != nil {
		return "", fmt.Errorf("authy encrypted: decode ciphertext: %w", err)
	}

	key := pbkdf2.Key([]byte(password), []byte(salt), 1000, 32, sha1.New)
	iv := make([]byte, 16) // fixed 16-byte zero IV (matches Aegis AuthyImporter.java)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("authy encrypted: create cipher: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("authy encrypted: ciphertext length %d not a multiple of block size", len(ciphertext))
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	unpadded, err := pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		// PKCS7 failure after decryption means wrong key → wrong password.
		return "", fmt.Errorf("authy encrypted: PKCS7 unpad: %w", err)
	}

	return string(unpadded), nil
}
