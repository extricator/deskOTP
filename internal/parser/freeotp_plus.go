// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"deskotp/internal/totp"
)

// FreeOTPPlusParser implements BackupParser for the FreeOTP+ JSON export format.
// FreeOTP+ stores OTP secrets as signed Java int arrays (byte values in the range -128
// to 127) that must be converted to unsigned bytes and then Base32-encoded.
//
// The conversion: cast each int to byte using Java-style signed-to-unsigned conversion
// (add 256 if negative), then Base32-encode and strip padding for consistency.
type FreeOTPPlusParser struct{}

func (p *FreeOTPPlusParser) Name() string { return "FreeOTP+" }

// signedBytesToBase32 converts a FreeOTP+ signed int array to a Base32 string.
// Java int arrays in FreeOTP+ represent byte values in the range [-128, 127].
// Each int is treated as an unsigned byte (add 256 if negative, then cast to byte),
// which is equivalent to Java's signed-to-unsigned byte conversion.
// (e.g. -28 -> -28+256=228 -> 0xE4)
// Padding is stripped to match the convention of other parsers in this codebase.
func signedBytesToBase32(signed []int) string {
	if len(signed) == 0 {
		return ""
	}
	buf := make([]byte, len(signed))
	for i, v := range signed {
		if v < 0 {
			v += 256
		}
		buf[i] = byte(v)
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(buf), "=")
}

// freeOTPPlusBackup is the root JSON structure of a FreeOTP+ export.
type freeOTPPlusBackup struct {
	Tokens []freeOTPPlusToken `json:"tokens"`
}

// freeOTPPlusToken represents a single OTP entry in a FreeOTP+ JSON export.
// Fields not declared here (issuerInt, tokenOrder, etc.) are safely ignored by encoding/json.
type freeOTPPlusToken struct {
	Algo      string `json:"algo"`      // e.g. "SHA1", "SHA256", "SHA512"
	Counter   int64  `json:"counter"`   // HOTP only; 0 for TOTP
	Digits    int    `json:"digits"`
	IssuerExt string `json:"issuerExt"` // external issuer name -> maps to Issuer
	Label     string `json:"label"`     // account name -> maps to Name
	Period    int    `json:"period"`
	Secret    []int  `json:"secret"` // signed byte array -> converted to Base32
	Type      string `json:"type"`   // "TOTP" or "HOTP"
}

// CanParse returns true if data is a FreeOTP+ JSON export.
// FreeOTP+ exports are JSON objects with a root "tokens" key whose value is an array.
// This distinguishes FreeOTP+ from other supported formats:
// Stratum has "Authenticators" (capital-A), Aegis has "db", andOTP is a root array,
// 2FAS has "schemaVersion"/"services".
func (p *FreeOTPPlusParser) CanParse(data []byte) bool {
	var probe struct {
		Tokens []json.RawMessage `json:"tokens"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.Tokens != nil
}

// Parse decodes a FreeOTP+ JSON export into a slice of OTP entries.
//
// Field mapping:
//   - IssuerExt maps to Issuer; Label maps to Name.
//   - Secret (signed int array) is converted via signedBytesToBase32 (no padding).
//   - Algo is uppercased for normalization.
//   - Type "TOTP" -> "totp", "HOTP" -> "hotp" (lowercased for internal consistency).
//   - TOTP: Period defaults to 30 if absent or zero.
//   - HOTP: Period=0, Counter from the counter field.
//   - UUID: synthetic UUID v4 generated per entry.
//
// password is accepted for interface compliance but ignored — plain-only parser.
// Never returns a nil slice; returns an empty slice if no supported entries are found.
func (p *FreeOTPPlusParser) Parse(data []byte, _ string) ([]totp.Entry, error) {
	var backup freeOTPPlusBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		return nil, fmt.Errorf("freeotp+: malformed JSON: %w", err)
	}

	entries := make([]totp.Entry, 0, len(backup.Tokens))

	for _, tok := range backup.Tokens {
		secret := signedBytesToBase32(tok.Secret)
		algo := strings.ToUpper(tok.Algo)
		entryType := strings.ToLower(tok.Type) // "TOTP" -> "totp", "HOTP" -> "hotp"

		entry := totp.Entry{
			UUID:   uuid.New().String(),
			Name:   tok.Label,
			Issuer: tok.IssuerExt,
			Secret: secret,
			Algo:   algo,
			Digits: tok.Digits,
			Type:   entryType,
		}

		switch entryType {
		case "hotp":
			// HOTP is counter-based; Period must be 0.
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
