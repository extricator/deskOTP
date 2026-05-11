// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"deskotp/internal/totp"
)

// FreeOTPParser implements BackupParser for the FreeOTP v1 Android XML format.
// FreeOTP v1 stores OTP tokens in Android SharedPreferences XML: each token is
// a <string> element whose name is the composite key (issuer:label) and whose
// value is a JSON object containing the token fields.
//
// The "tokenOrder" key holds a JSON array of token names — it is not a token and
// must be skipped during parsing.
//
// Secret decoding reuses signedBytesToBase32 from freeotp_plus.go, since both
// FreeOTP v1 and FreeOTP+ use the same signed Java byte array encoding.
type FreeOTPParser struct{}

// freeOTPV1Token represents a single OTP token in FreeOTP v1 XML format.
// The secret field is a signed Java byte array (values in [-128, 127]).
type freeOTPV1Token struct {
	Algo      string `json:"algo"`
	Counter   int64  `json:"counter"`
	Digits    int    `json:"digits"`
	IssuerExt string `json:"issuerExt"`
	Label     string `json:"label"`
	Period    int    `json:"period"`
	Secret    []int  `json:"secret"` // signed byte array
	Type      string `json:"type"`   // "TOTP" or "HOTP"
}

func (p *FreeOTPParser) Name() string { return "FreeOTP" }

// CanParse returns true if data is a FreeOTP v1 Android SharedPreferences XML export.
// FreeOTP v1 files always contain a "tokenOrder" key which distinguishes them from
// other XML formats (TOTP Authenticator, Authy, Battle.net).
func (p *FreeOTPParser) CanParse(data []byte) bool {
	m, err := parseAndroidPrefsXML(data)
	if err != nil {
		return false
	}
	_, hasOrder := m["tokenOrder"]
	return hasOrder
}

// Parse decodes a FreeOTP v1 Android SharedPreferences XML export into OTP entries.
//
// Field mapping:
//   - issuerExt → Issuer
//   - label → Name
//   - secret (signed int array) → Secret via signedBytesToBase32
//   - algo → Algo (uppercased; defaults to "SHA1" if empty)
//   - type → Type (lowercased: "TOTP" → "totp", "HOTP" → "hotp")
//   - digits → Digits (defaults to 6 if 0)
//   - TOTP: period → Period (defaults to 30 if 0)
//   - HOTP: Period=0, counter → Counter (stored as-is, no adjustment)
//
// The "tokenOrder" entry is skipped — it is a JSON array of names, not a token.
// Unknown types are skipped silently.
// password is accepted for interface compliance but ignored — plain-only parser.
func (p *FreeOTPParser) Parse(data []byte, _ string) ([]totp.Entry, error) {
	m, err := parseAndroidPrefsXML(data)
	if err != nil {
		return nil, fmt.Errorf("freeotp: failed to parse XML: %w", err)
	}

	entries := make([]totp.Entry, 0, len(m)-1) // -1 for tokenOrder

	for key, value := range m {
		// Skip the tokenOrder key — it is a JSON array of names, not a token.
		if key == "tokenOrder" {
			continue
		}

		var tok freeOTPV1Token
		if err := json.Unmarshal([]byte(value), &tok); err != nil {
			// Malformed token JSON — skip rather than fail the whole import.
			continue
		}

		algo := strings.ToUpper(tok.Algo)
		if algo == "" {
			algo = "SHA1"
		}

		digits := tok.Digits
		if digits == 0 {
			digits = 6
		}

		entryType := strings.ToLower(tok.Type) // "TOTP" → "totp", "HOTP" → "hotp"

		entry := totp.Entry{
			UUID:   uuid.New().String(),
			Name:   tok.Label,
			Issuer: tok.IssuerExt,
			Secret: signedBytesToBase32(tok.Secret),
			Algo:   algo,
			Digits: digits,
			Type:   entryType,
		}

		switch entryType {
		case "hotp":
			// HOTP is counter-based; Period must be 0.
			// Counter is stored as-is from the JSON — no adjustment.
			entry.Period = 0
			entry.Counter = uint64(tok.Counter)
		case "totp":
			period := tok.Period
			if period == 0 {
				period = 30
			}
			entry.Period = uint(period)
		default:
			// Unknown type — skip entry.
			continue
		}

		entries = append(entries, entry)
	}

	return entries, nil
}
