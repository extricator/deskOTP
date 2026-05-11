// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"

	"deskotp/internal/totp"
)

// AndOTPEncryptedParser implements BackupParser for the andOTP encrypted binary format (.bin).
//
// andOTP has two encrypted binary formats:
//   - New format: PBKDF2-SHA1 key derivation + AES-256-GCM encryption
//   - Old format: single SHA-256 pass key derivation + AES-256-GCM encryption
//
// The parser tries the new format first, then silently falls back to the old format.
// If both fail, ErrWrongPassword is returned. The user never sees format-version errors.
type AndOTPEncryptedParser struct{}

func (p *AndOTPEncryptedParser) Name() string { return "andOTP (Encrypted)" }

// CanParse returns true if data appears to be binary (non-text, non-JSON).
// andOTP encrypted .bin files are binary; they contain random nonce/ciphertext bytes
// that are not valid UTF-8 text and not valid JSON.
//
// Detection strategy (three-stage rejection):
//  1. Reject valid JSON (all JSON object/array parsers registered before this one
//     have already claimed their formats; this prevents andOTP encrypted from
//     double-claiming any JSON fixture in the cross-format matrix).
//  2. Reject Stratum encrypted files that begin with a 16-byte magic header
//     ("AUTHENTICATORPRO" or "AuthenticatorPro"). Stratum files start with ASCII,
//     making them partially valid UTF-8 — stage 3 alone cannot distinguish them.
//     StratumEncryptedParser is registered before this parser and claims these files
//     in the Import flow, but the cross-format matrix checks all parsers independently.
//  3. Reject valid UTF-8 text (text-based formats like CSV, URI lists are not binary).
//     andOTP .bin files contain random crypto bytes that fail UTF-8 validation.
//
// Empty data always returns false.
func (p *AndOTPEncryptedParser) CanParse(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// Reject valid JSON (both objects and arrays).
	var v json.RawMessage
	if json.Unmarshal(data, &v) == nil {
		return false
	}
	// Reject Stratum encrypted files (start with 16-byte magic headers).
	// These are binary files that share non-UTF-8 bytes with andOTP encrypted, but
	// the Stratum magic header probe is more specific and must win.
	if len(data) >= stratumHeaderSize {
		header := string(data[:stratumHeaderSize])
		if header == stratumMagicCurrent || header == stratumMagicLegacy {
			return false
		}
	}
	// Reject valid UTF-8 text (CSV, URI lists, etc. are text, not binary crypto data).
	return !utf8.Valid(data)
}

// Parse decrypts an andOTP encrypted .bin file and returns the parsed OTP entries.
//
// Decryption flow:
//  1. Reject empty password with ErrPasswordRequired.
//  2. Try new format (PBKDF2-SHA1 + AES-256-GCM). On success, return entries.
//  3. Silent fallback to old format (SHA-256 + AES-256-GCM). On success, return entries.
//  4. If both fail, return ErrWrongPassword.
//
// The dual-format fallback is transparent to the caller — the user sees one error on failure.
func (p *AndOTPEncryptedParser) Parse(data []byte, password string) ([]totp.Entry, error) {
	if password == "" {
		return nil, ErrPasswordRequired
	}

	// Try new format first (PBKDF2-SHA1).
	entries, err := decryptAndOTPNewFormat(data, password)
	if err == nil {
		return entries, nil
	}

	// Silent fallback to old format (SHA-256 key).
	entries, err = decryptAndOTPOldFormat(data, password)
	if err == nil {
		return entries, nil
	}

	// Both formats failed — wrong password (per locked decision: user sees one error).
	return nil, ErrWrongPassword
}

// decryptAndOTPNewFormat decrypts a new-format andOTP .bin file.
//
// Binary layout:
//
//	[0:4]   4-byte big-endian int32 — PBKDF2 iteration count
//	[4:16]  12 bytes — PBKDF2 salt
//	[16:28] 12 bytes — AES-GCM nonce
//	[28:]   remaining bytes — AES-GCM ciphertext + 16-byte GCM tag (appended by Seal)
//
// KDF: PBKDF2WithHmacSHA1, variable iterations, 256-bit (32-byte) key.
//
// Iteration count guard: rejects values < 1 or > 10,000,000 to prevent abuse.
func decryptAndOTPNewFormat(data []byte, password string) ([]totp.Entry, error) {
	const intSize = 4
	const saltSize = 12
	const nonceSize = 12
	const minLen = intSize + saltSize + nonceSize + 1 // at least 1 byte of ciphertext

	if len(data) < minLen {
		return nil, fmt.Errorf("andotp encrypted new: data too short (%d bytes)", len(data))
	}

	// Read and validate PBKDF2 iteration count.
	iterations := int(binary.BigEndian.Uint32(data[0:intSize]))
	if iterations < 1 || iterations > 10_000_000 {
		return nil, fmt.Errorf("andotp encrypted new: iteration count %d out of allowed range [1, 10000000]", iterations)
	}

	// Extract salt, nonce, and ciphertext (with GCM tag appended by Seal).
	salt := data[intSize : intSize+saltSize]
	nonce := data[intSize+saltSize : intSize+saltSize+nonceSize]
	ctWithTag := data[intSize+saltSize+nonceSize:]

	// Derive 32-byte AES key via PBKDF2-SHA1.
	key := pbkdf2.Key([]byte(password), salt, iterations, 32, sha1.New)

	// Decrypt via AES-256-GCM.
	plaintext, err := aesGCMDecrypt(key, nonce, ctWithTag)
	if err != nil {
		return nil, fmt.Errorf("andotp encrypted new: AES-GCM decryption failed: %w", err)
	}

	return parseAndOTPJSON(plaintext)
}

// decryptAndOTPOldFormat decrypts an old-format andOTP .bin file.
//
// Binary layout:
//
//	[0:12]  12 bytes — AES-GCM nonce
//	[12:]   remaining bytes — AES-GCM ciphertext + 16-byte GCM tag (appended by Seal)
//
// KDF: single SHA-256 digest of password (NOT PBKDF2).
func decryptAndOTPOldFormat(data []byte, password string) ([]totp.Entry, error) {
	const nonceSize = 12
	const minLen = nonceSize + 1 // at least 1 byte of ciphertext

	if len(data) < minLen {
		return nil, fmt.Errorf("andotp encrypted old: data too short (%d bytes)", len(data))
	}

	// Extract nonce and ciphertext (with GCM tag appended by Seal).
	nonce := data[0:nonceSize]
	ctWithTag := data[nonceSize:]

	// Derive 32-byte key via single SHA-256 pass (not PBKDF2).
	keyBytes := sha256.Sum256([]byte(password))

	// Decrypt via AES-256-GCM.
	plaintext, err := aesGCMDecrypt(keyBytes[:], nonce, ctWithTag)
	if err != nil {
		return nil, fmt.Errorf("andotp encrypted old: AES-GCM decryption failed: %w", err)
	}

	return parseAndOTPJSON(plaintext)
}

// aesGCMDecrypt performs AES-256-GCM decryption.
// key must be 32 bytes. ctWithTag is the ciphertext with the 16-byte GCM tag appended.
func aesGCMDecrypt(key, nonce, ctWithTag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ctWithTag, nil)
}

// parseAndOTPJSON unmarshals a JSON byte slice into []andOTPEntry and converts to []totp.Entry.
func parseAndOTPJSON(plaintext []byte) ([]totp.Entry, error) {
	var raw []andOTPEntry
	if err := json.Unmarshal(plaintext, &raw); err != nil {
		return nil, fmt.Errorf("andotp encrypted: malformed decrypted JSON: %w", err)
	}
	return convertAndOTPEntries(raw), nil
}

// convertAndOTPEntries converts []andOTPEntry to []totp.Entry using the same field mapping
// logic as AndOTPParser.Parse.
//
// Field mapping:
//   - Issuer resolution: uses "issuer" field if non-empty; falls back to splitting "label" on " - ".
//   - Type dispatch: TOTP (period default 30), HOTP (period=0, preserve counter), STEAM (SHA1/5/30).
//   - UUID: uuid.New().String() per entry (andOTP has no UUID field).
//   - Unknown types are silently skipped.
//
// Never returns nil slice.
func convertAndOTPEntries(raw []andOTPEntry) []totp.Entry {
	entries := make([]totp.Entry, 0, len(raw))

	for _, e := range raw {
		// Resolve issuer and name.
		var name, issuer string
		if e.Issuer != "" {
			name = e.Label
			issuer = e.Issuer
		} else {
			// Fallback: split label on " - " (space-dash-space).
			parts := strings.SplitN(e.Label, " - ", 2)
			if len(parts) > 1 {
				issuer = parts[0]
				name = parts[1]
			} else {
				name = parts[0]
				issuer = ""
			}
		}

		// andOTP uses UPPERCASE types; lowercase for internal consistency.
		switch strings.ToLower(e.Type) {
		case "totp":
			period := e.Period
			if period == 0 {
				period = 30
			}
			entries = append(entries, totp.Entry{
				UUID:   uuid.New().String(),
				Name:   name,
				Issuer: issuer,
				Secret: e.Secret,
				Algo:   e.Algorithm,
				Digits: e.Digits,
				Period: uint(period),
				Type:   "totp",
			})
		case "hotp":
			// HOTP is counter-based; Period must be 0.
			entries = append(entries, totp.Entry{
				UUID:    uuid.New().String(),
				Name:    name,
				Issuer:  issuer,
				Secret:  e.Secret,
				Algo:    e.Algorithm,
				Digits:  e.Digits,
				Period:  0,
				Type:    "hotp",
				Counter: uint64(e.Counter),
			})
		case "steam":
			// Steam Guard uses fixed parameters: SHA1, 5 digits, 30s period.
			entries = append(entries, totp.Entry{
				UUID:   uuid.New().String(),
				Name:   name,
				Issuer: issuer,
				Secret: e.Secret,
				Algo:   "SHA1",
				Digits: 5,
				Period: 30,
				Type:   "steam",
			})
		default:
			// Unknown types (motp, yandex, etc.) — silently skip.
			continue
		}
	}

	return entries
}
