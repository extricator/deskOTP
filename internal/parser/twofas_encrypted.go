// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"

	"deskotp/internal/totp"
)

// TwoFASEncryptedParser implements BackupParser for the encrypted 2FAS backup format.
// Encrypted 2FAS backups use PBKDF2-SHA256 as the key derivation function and
// AES-256-GCM for encryption. The encrypted payload is stored as a colon-separated
// base64 string: "ciphertext:salt:iv" in the servicesEncrypted JSON field.
type TwoFASEncryptedParser struct{}

func (p *TwoFASEncryptedParser) Name() string { return "2FAS (Encrypted)" }

// CanParse returns true if data is an encrypted 2FAS backup.
// Encrypted 2FAS files have a schemaVersion >= 1 and a non-empty servicesEncrypted string.
// This distinguishes them from plain 2FAS backups which have a "services" array instead.
func (p *TwoFASEncryptedParser) CanParse(data []byte) bool {
	var probe struct {
		SchemaVersion     int    `json:"schemaVersion"`
		ServicesEncrypted string `json:"servicesEncrypted"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.SchemaVersion >= 1 && probe.ServicesEncrypted != ""
}

// Parse decrypts an encrypted 2FAS backup and returns the OTP entries.
//
// Decryption flow:
//  1. Return ErrPasswordRequired immediately if password is empty
//  2. Unmarshal outer JSON to extract servicesEncrypted string
//  3. Split servicesEncrypted on ":" into ciphertext, salt, and IV (all base64-encoded)
//  4. Derive a 32-byte AES key using PBKDF2-SHA256 with 10000 iterations
//  5. Decrypt ciphertext with AES-256-GCM; wrong password causes gcm.Open to fail -> ErrWrongPassword
//  6. Unmarshal decrypted plaintext as a []twoFASEntry and convert to []totp.Entry
//
// Entry conversion follows the same rules as TwoFASParser.Parse:
//   - Issuer: outer "name" preferred; falls back to otp.issuer
//   - Name: otp.account preferred; falls back to otp.label
//   - Defaults when absent: Algo="SHA1", Digits=6, Period=30
//   - TokenType: nil defaults to TOTP; HOTP has Period=0; Steam has hardcoded SHA1/5/30
//   - UUID: synthetic UUID v4 generated per entry
func (p *TwoFASEncryptedParser) Parse(data []byte, password string) ([]totp.Entry, error) {
	if password == "" {
		return nil, ErrPasswordRequired
	}

	// Unmarshal outer structure.
	var outer struct {
		SchemaVersion     int    `json:"schemaVersion"`
		ServicesEncrypted string `json:"servicesEncrypted"`
	}
	if err := json.Unmarshal(data, &outer); err != nil {
		return nil, fmt.Errorf("2fas encrypted: malformed JSON: %w", err)
	}

	// Split servicesEncrypted into ciphertext, salt, and IV.
	parts := strings.SplitN(outer.ServicesEncrypted, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("2fas encrypted: servicesEncrypted has %d parts, want 3 (ciphertext:salt:iv)", len(parts))
	}

	ciphertext, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("2fas encrypted: decode ciphertext base64: %w", err)
	}
	salt, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("2fas encrypted: decode salt base64: %w", err)
	}
	iv, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("2fas encrypted: decode iv base64: %w", err)
	}

	// Derive 32-byte AES key via PBKDF2-SHA256.
	key := pbkdf2.Key([]byte(password), salt, 10000, 32, sha256.New)

	// Decrypt AES-256-GCM. ciphertext includes the 16-byte GCM tag appended at the end
	// (standard Go gcm.Seal output). gcm.Open expects ciphertext || tag.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("2fas encrypted: create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("2fas encrypted: create GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		// Authentication failure means wrong password (or corrupted data).
		return nil, ErrWrongPassword
	}

	// Unmarshal decrypted plaintext as a services array.
	var services []twoFASEntry
	if err := json.Unmarshal(plaintext, &services); err != nil {
		return nil, fmt.Errorf("2fas encrypted: malformed decrypted services JSON: %w", err)
	}

	// Convert twoFASEntry slice to totp.Entry slice using the same logic as TwoFASParser.
	entries := make([]totp.Entry, 0, len(services))
	for _, svc := range services {
		// Resolve issuer: outer "name" is the service display name and preferred issuer.
		issuer := svc.Name
		if issuer == "" {
			issuer = svc.OTP.Issuer
		}

		// Resolve account name: otp.account preferred over otp.label.
		name := svc.OTP.Account
		if name == "" {
			name = svc.OTP.Label
		}

		// Apply defaults for fields absent in older schema versions.
		algo := svc.OTP.Algorithm
		if algo == "" {
			algo = "SHA1"
		}
		digits := svc.OTP.Digits
		if digits == 0 {
			digits = 6
		}
		period := svc.OTP.Period
		if period == 0 {
			period = 30
		}

		// Dispatch on tokenType. nil pointer (absent in v1/v2) defaults to TOTP.
		tokenType := "TOTP"
		if svc.OTP.TokenType != nil {
			tokenType = strings.ToUpper(*svc.OTP.TokenType)
		}

		switch tokenType {
		case "TOTP":
			entries = append(entries, totp.Entry{
				UUID:   uuid.New().String(),
				Name:   name,
				Issuer: issuer,
				Secret: svc.Secret,
				Algo:   algo,
				Digits: digits,
				Period: uint(period),
				Type:   "totp",
			})
		case "HOTP":
			entries = append(entries, totp.Entry{
				UUID:    uuid.New().String(),
				Name:    name,
				Issuer:  issuer,
				Secret:  svc.Secret,
				Algo:    algo,
				Digits:  digits,
				Period:  0, // HOTP is counter-based; no time step
				Type:    "hotp",
				Counter: uint64(svc.OTP.Counter),
			})
		case "STEAM":
			// Steam Guard uses fixed parameters regardless of what the JSON contains.
			entries = append(entries, totp.Entry{
				UUID:   uuid.New().String(),
				Name:   name,
				Issuer: issuer,
				Secret: svc.Secret,
				Algo:   "SHA1",
				Digits: 5,
				Period: 30,
				Type:   "steam",
			})
		default:
			// Unknown tokenType — silently skip (forward compatibility).
			continue
		}
	}

	return entries, nil
}
