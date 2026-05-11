// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"deskotp/internal/totp"
)

// StratumParser implements BackupParser for the Stratum (Authenticator Pro) plain JSON format.
// Stratum uses integer codes for OTP type and algorithm that must be mapped to strings.
//
// Type codes: 1=HOTP, 2=TOTP, 4=Steam
// Algorithm codes: 0=SHA1, 1=SHA256, 2=SHA512
//
// Steam entries are forced to Digits=5 and Algo="SHA1" regardless of JSON values.
// Entries with unknown Type or out-of-range Algorithm codes are silently skipped.
type StratumParser struct{}

func (p *StratumParser) Name() string { return "Stratum" }

// stratumAlgoNames maps integer Algorithm codes to canonical algorithm name strings.
// Index bounds must be checked before use: valid range is [0, len(stratumAlgoNames)).
var stratumAlgoNames = [3]string{"SHA1", "SHA256", "SHA512"}

// stratumBackup is the root JSON structure of a Stratum plain export.
type stratumBackup struct {
	Authenticators []stratumEntry `json:"Authenticators"`
}

// stratumEntry represents a single OTP entry in a Stratum JSON backup.
// Fields not declared here (Icon, Pin, Ranking, etc.) are safely ignored by encoding/json.
type stratumEntry struct {
	Type      int    `json:"Type"`      // 1=HOTP, 2=TOTP, 4=Steam
	Issuer    string `json:"Issuer"`
	Username  string `json:"Username"`  // maps to Name in totp.Entry
	Secret    string `json:"Secret"`    // Base32-encoded secret (no padding in Stratum exports)
	Algorithm int    `json:"Algorithm"` // 0=SHA1, 1=SHA256, 2=SHA512
	Digits    int    `json:"Digits"`
	Period    int    `json:"Period"`
	Counter   int    `json:"Counter"` // HOTP only
}

// CanParse returns true if data is a Stratum plain JSON backup.
// Stratum exports are JSON objects with a root "Authenticators" key (capital-A) whose
// value is an array. This distinguishes Stratum from all other supported formats:
// Aegis has "db", andOTP is a root array, 2FAS has "schemaVersion"/"services".
func (p *StratumParser) CanParse(data []byte) bool {
	var probe struct {
		Authenticators []json.RawMessage `json:"Authenticators"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.Authenticators != nil
}

// Parse decodes a Stratum plain JSON backup into a slice of OTP entries.
// Entries with unknown Type codes or out-of-range Algorithm codes are silently skipped.
//
// Field mapping:
//   - Type 1 -> "hotp", Type 2 -> "totp", Type 4 -> "steam"; unknown Type: skip.
//   - Algorithm 0 -> "SHA1", 1 -> "SHA256", 2 -> "SHA512"; out-of-range: skip.
//   - Username maps to Name; Issuer maps to Issuer.
//   - Secret is stored as-is (Stratum does not pad Base32 secrets).
//   - Steam entries: forced Digits=5, Algo="SHA1", Period=30.
//   - HOTP entries: Period=0 (counter-based).
//   - TOTP entries: Period defaults to 30 if absent or zero.
//   - UUID: synthetic UUID v4 generated per entry.
//
// password is accepted for interface compliance but ignored — plain-only parser.
// Never returns a nil slice; returns an empty slice if no supported entries are found.
func (p *StratumParser) Parse(data []byte, _ string) ([]totp.Entry, error) {
	var backup stratumBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		return nil, fmt.Errorf("stratum: malformed JSON: %w", err)
	}

	entries := make([]totp.Entry, 0, len(backup.Authenticators))

	for _, e := range backup.Authenticators {
		// Guard: skip entries with out-of-range Algorithm to prevent array bounds panic.
		if e.Algorithm < 0 || e.Algorithm >= len(stratumAlgoNames) {
			continue
		}
		algo := stratumAlgoNames[e.Algorithm]

		// Map integer Type code to canonical string.
		var entryType string
		switch e.Type {
		case 1:
			entryType = "hotp"
		case 2:
			entryType = "totp"
		case 4:
			entryType = "steam"
		default:
			// Unknown Type code — skip entry.
			continue
		}

		entry := totp.Entry{
			UUID:   uuid.New().String(),
			Name:   e.Username,
			Issuer: e.Issuer,
			Secret: e.Secret,
			Digits: e.Digits,
			Type:   entryType,
		}

		switch entryType {
		case "steam":
			// Steam Guard: forced parameters regardless of JSON values.
			entry.Algo = "SHA1"
			entry.Digits = 5
			entry.Period = 30
		case "hotp":
			// HOTP is counter-based; Period must be 0.
			entry.Algo = algo
			entry.Period = 0
			entry.Counter = uint64(e.Counter)
		case "totp":
			entry.Algo = algo
			period := e.Period
			if period == 0 {
				period = 30
			}
			entry.Period = uint(period)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}
