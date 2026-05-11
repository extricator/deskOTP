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

// AndOTPParser implements BackupParser for the andOTP plain JSON backup format.
// andOTP is a popular open-source authenticator app (now in maintenance mode).
// Plain backups are a root-level JSON array of entry objects.
// Encrypted backups (.bin files) are not supported by this parser.
type AndOTPParser struct{}

func (p *AndOTPParser) Name() string { return "andOTP" }

// andOTPProbe is a minimal struct used only in CanParse to distinguish andOTP from Duo.
// andOTP entries always have "type" and "secret" at root level; Duo entries have "otpGenerator".
type andOTPProbe struct {
	Type         *json.RawMessage `json:"type"`
	Secret       *json.RawMessage `json:"secret"`
	OTPGenerator *json.RawMessage `json:"otpGenerator"`
}

// CanParse returns true if data is an andOTP plain JSON backup (root-level JSON array
// whose first element has "type" and "secret" fields — andOTP's entry structure).
//
// Specificity vs Duo: Duo root arrays contain entries with "otpGenerator" and no "type"/"secret".
// DuoParser is registered before AndOTPParser; this extra check ensures andOTP does not
// false-positive on Duo fixtures when CanParse is probed independently (e.g., test matrix).
//
// Empty arrays return false (no evidence of andOTP format).
func (p *AndOTPParser) CanParse(data []byte) bool {
	var arr []andOTPProbe
	if err := json.Unmarshal(data, &arr); err != nil {
		return false
	}
	if len(arr) == 0 {
		return false
	}
	// First element must have "type" and "secret" (andOTP) and must NOT have "otpGenerator" (Duo).
	first := arr[0]
	return first.Type != nil && first.Secret != nil && first.OTPGenerator == nil
}

// Parse decodes an andOTP plain JSON array into a slice of OTP entries.
// Supports TOTP, HOTP, and STEAM entry types (case-insensitive). Unknown types are skipped.
//
// Field mapping:
//   - andOTP types are UPPERCASE ("TOTP", "HOTP", "STEAM"); lowercased in output.
//   - issuer: uses the "issuer" field when present; falls back to splitting "label" on " - ".
//     "Deno - Mason" -> issuer="Deno", name="Mason". "JustALabel" -> issuer="", name="JustALabel".
//   - secret: stored as-is with padding (e.g. "4SJHB4GSD43FZBAI7C2HLRJGPQ======").
//   - period: defaults to 30 if absent or zero.
//   - Steam: hardcoded SHA1/5 digits/30s period regardless of JSON values.
//   - HOTP: Period=0 (counter-based, no time step).
//   - UUID: synthetic UUID v4 generated per entry (andOTP has no UUID field;
//     synthetic UUIDs prevent copiedId="" collision in the frontend).
//
// password is accepted for interface compliance but ignored — plain-only parser.
// Never returns a nil slice; returns an empty slice if no supported entries are found.
func (p *AndOTPParser) Parse(data []byte, _ string) ([]totp.Entry, error) {
	var raw []andOTPEntry
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("andotp: malformed JSON: %w", err)
	}

	entries := make([]totp.Entry, 0, len(raw))

	for _, e := range raw {
		// Resolve issuer and name. andOTP's issuer field is optional.
		var name, issuer string
		if e.Issuer != "" {
			name = e.Label
			issuer = e.Issuer
		} else {
			// Fallback: split label on " - " (space-dash-space).
			// "GitHub - user@example.com" -> issuer="GitHub", name="user@example.com"
			// "JustALabel" -> issuer="", name="JustALabel"
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

	return entries, nil
}

// andOTPEntry is a private struct for decoding a single andOTP JSON entry.
// Fields not declared here (thumbnail, last_used, used_frequency, tags) are safely
// ignored by encoding/json.
type andOTPEntry struct {
	Secret    string `json:"secret"`
	Type      string `json:"type"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
	Counter   int64  `json:"counter"` // HOTP only; 0 for TOTP/STEAM
	Label     string `json:"label"`
	Issuer    string `json:"issuer"` // optional — may be absent
}
