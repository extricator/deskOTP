// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"deskotp/internal/totp"
)

// DuoParser implements BackupParser for Duo Mobile JSON backup files.
// Duo Mobile exports a root JSON array of entry objects. Each entry has a "name" field
// and an "otpGenerator" object with "otpSecret" (already Base32) and an optional "counter".
//
// TOTP vs HOTP detection:
//   - No counter field (nil pointer): TOTP — Period=30, Digits=6, Algo=SHA1
//   - Counter field present (non-nil pointer): HOTP — Counter=value, Period=0
//
// Duo format has no issuer field. All entries will have Issuer="".
type DuoParser struct{}

func (p *DuoParser) Name() string { return "Duo" }

// duoEntry is a private struct for decoding a single Duo Mobile JSON entry.
// Fields not declared here (version, accountType, logoUri, pkey, etc.) are ignored.
type duoEntry struct {
	Name         string          `json:"name"`
	OTPGenerator duoOTPGenerator `json:"otpGenerator"`
}

// duoOTPGenerator holds the OTP secret and optional counter.
// Counter is a pointer: nil means TOTP, non-nil means HOTP.
type duoOTPGenerator struct {
	OTPSecret string `json:"otpSecret"` // Base32 encoded secret (no conversion needed)
	Counter   *int64 `json:"counter"`   // nil = TOTP, non-nil = HOTP
}

// canParseProbe is a minimal struct used only in CanParse to check for the
// otpGenerator field without decoding its full content.
type duoCanParseProbe struct {
	OTPGenerator *json.RawMessage `json:"otpGenerator"`
}

// CanParse returns true if data is a Duo Mobile JSON backup.
//
// Detection strategy: unmarshal as a JSON array; if non-empty and the first element
// has a non-nil "otpGenerator" field, accept. This distinguishes Duo from andOTP
// (which uses "type" and "secret" at root level without "otpGenerator").
//
// An empty array returns false (no evidence of Duo format).
func (p *DuoParser) CanParse(data []byte) bool {
	var probes []duoCanParseProbe
	if err := json.Unmarshal(data, &probes); err != nil {
		return false
	}
	if len(probes) == 0 {
		return false
	}
	// First element must have a non-nil otpGenerator to distinguish from andOTP.
	return probes[0].OTPGenerator != nil
}

// Parse decodes a Duo Mobile JSON backup into a slice of OTP entries.
//
// For each entry:
//   - If OTPGenerator.Counter is nil: Type="totp", Period=30, Digits=6, Algo="SHA1"
//   - If OTPGenerator.Counter is non-nil: Type="hotp", Counter=*counter, Period=0
//   - Name = entry.Name, Issuer = "" (Duo has no issuer field)
//   - Secret = OTPGenerator.OTPSecret (already Base32, no conversion needed)
//
// password is accepted for interface compliance but ignored — plain-only format.
// Returns a non-nil error for malformed JSON. Never returns a nil slice.
func (p *DuoParser) Parse(data []byte, _ string) ([]totp.Entry, error) {
	var raw []duoEntry
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("duo: malformed JSON: %w", err)
	}

	entries := make([]totp.Entry, 0, len(raw))

	for _, e := range raw {
		entry := totp.Entry{
			UUID:   uuid.New().String(),
			Name:   e.Name,
			Issuer: "", // Duo has no issuer field
			Secret: e.OTPGenerator.OTPSecret,
		}

		if e.OTPGenerator.Counter == nil {
			// No counter -> TOTP
			entry.Type = "totp"
			entry.Period = 30
			entry.Digits = 6
			entry.Algo = "SHA1"
		} else {
			// Counter present -> HOTP
			entry.Type = "hotp"
			entry.Counter = uint64(*e.OTPGenerator.Counter)
			entry.Period = 0
			entry.Digits = 6
			entry.Algo = "SHA1"
		}

		entries = append(entries, entry)
	}

	return entries, nil
}
