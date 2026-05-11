// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"deskotp/internal/totp"
)

// TotpAuthenticatorParser implements BackupParser for the "TOTP Authenticator"
// Android app internal XML format. Tokens are stored in Android SharedPreferences
// XML as a JSON array under the "STATIC_TOTP_CODES_LIST" key.
//
// Each entry may have secrets encoded as base-16 (hex), base-32, or base-64.
// All secrets are decoded to raw bytes then re-encoded as base32 (no padding)
// for the Secret field.
//
// Digits and period are JSON strings ("6", "30"), not integers. They are parsed
// with strconv.Atoi and default to 6 and 30 respectively if empty or invalid.
//
// All entries are hardcoded to SHA1/totp since the app does not expose algorithm.
type TotpAuthenticatorParser struct{}

// totpAuthEntry represents a single entry in the TOTP Authenticator JSON array.
// Digits and Period are strings in the actual JSON format (not integers).
type totpAuthEntry struct {
	Base   int    `json:"base"`
	Key    string `json:"key"`
	Name   string `json:"name"`
	Issuer string `json:"issuer"`
	Digits string `json:"digits"` // NOTE: string, not int
	Period string `json:"period"` // NOTE: string, not int
}

func (p *TotpAuthenticatorParser) Name() string { return "TOTP Authenticator" }

// CanParse returns true if data is a TOTP Authenticator Android XML export.
// TOTP Authenticator exports contain the "STATIC_TOTP_CODES_LIST" key.
func (p *TotpAuthenticatorParser) CanParse(data []byte) bool {
	m, err := parseAndroidPrefsXML(data)
	if err != nil {
		return false
	}
	_, ok := m["STATIC_TOTP_CODES_LIST"]
	return ok
}

// decodeTotpAuthSecret decodes a TOTP Authenticator secret from the specified base
// to raw bytes, then re-encodes it as base32 (no padding).
//
// Supported bases:
//   - 16: hex string decode -> raw bytes -> base32
//   - 32: base32 decode (no-padding first, then standard) -> raw bytes -> base32
//   - 64: base64 decode (standard first, then raw/no-padding) -> raw bytes -> base32
//
// Returns an error for unsupported bases or decode failures.
func decodeTotpAuthSecret(base int, key string) (string, error) {
	var raw []byte
	var err error

	switch base {
	case 16:
		raw, err = hex.DecodeString(key)
	case 32:
		// Try no-padding first, then with standard padding.
		raw, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(key))
		if err != nil {
			raw, err = base32.StdEncoding.DecodeString(strings.ToUpper(key))
		}
	case 64:
		// Try standard (padded) first, then raw (no padding).
		raw, err = base64.StdEncoding.DecodeString(key)
		if err != nil {
			raw, err = base64.RawStdEncoding.DecodeString(key)
		}
	default:
		return "", fmt.Errorf("totp_authenticator: unsupported secret base: %d", base)
	}

	if err != nil {
		return "", fmt.Errorf("totp_authenticator: base%d decode failed: %w", base, err)
	}

	// Re-encode as base32 without padding.
	return strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "="), nil
}

// Parse decodes a TOTP Authenticator Android XML export into OTP entries.
//
// Field mapping:
//   - issuer -> Issuer
//   - name -> Name (kept as-is from JSON, typically lowercase)
//   - key + base -> Secret via decodeTotpAuthSecret (hex/base32/base64 -> base32)
//   - digits (string) -> Digits via strconv.Atoi (default 6)
//   - period (string) -> Period via strconv.Atoi (default 30)
//   - Algo: hardcoded "SHA1" (app does not expose algorithm)
//   - Type: hardcoded "totp" (TOTP only)
//
// Entries with decode errors are silently skipped — partial import is preferred
// over total failure. password is accepted for interface compliance but ignored.
func (p *TotpAuthenticatorParser) Parse(data []byte, _ string) ([]totp.Entry, error) {
	m, err := parseAndroidPrefsXML(data)
	if err != nil {
		return nil, fmt.Errorf("totp_authenticator: failed to parse XML: %w", err)
	}

	jsonStr, ok := m["STATIC_TOTP_CODES_LIST"]
	if !ok {
		return nil, fmt.Errorf("totp_authenticator: missing STATIC_TOTP_CODES_LIST in XML")
	}

	var tokens []totpAuthEntry
	if err := json.Unmarshal([]byte(jsonStr), &tokens); err != nil {
		return nil, fmt.Errorf("totp_authenticator: failed to parse token JSON: %w", err)
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
			Name:   tok.Name, // kept as-is (typically lowercase)
			Secret: secret,
			Algo:   "SHA1",   // app does not expose algorithm
			Digits: digits,
			Period: uint(period),
			Type:   "totp", // TOTP only
		})
	}

	return entries, nil
}
