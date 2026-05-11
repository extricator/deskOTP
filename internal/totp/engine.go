// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

// internal/totp/engine.go
package totp

import (
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

// Entry holds all OTP parameters for a single authenticator account.
// Field names align with Aegis backup JSON structure to minimize adapter
// code in the parser and App struct.
type Entry struct {
	UUID    string // Unique identifier (from Aegis "uuid" field)
	Name    string // Account name (from Aegis "name" field)
	Issuer  string // Issuer/organization (from Aegis "issuer" field)
	Secret  string // Base32-encoded secret (from Aegis info."secret")
	Algo    string // Hash algorithm: "SHA1", "SHA256", or "SHA512"
	Digits  int    // Code length: 5, 6, or 8
	Period  uint   // Time step in seconds: 30 or 60 (TOTP/Steam only; 0 for HOTP)
	Type    string // "totp", "hotp", "steam"; empty string treated as "totp"
	Counter    uint64 // HOTP only — current counter value; persisted on each advance
	Group      string `json:",omitempty"` // User-assigned group
	Note       string `json:",omitempty"` // User-assigned note
	Icon       string `json:",omitempty"` // Icon slug for visual identification
	UsageCount int    `json:",omitempty"` // Copy count
}

// EffectiveType returns the entry's OTP type, treating empty string as "totp".
// Existing accounts.json files (from v1.0) have no Type field and decode to Type="".
// All code that dispatches on entry type MUST call EffectiveType(), not entry.Type,
// to ensure backward compatibility.
func (e Entry) EffectiveType() string {
	if e.Type == "" {
		return "totp"
	}
	return e.Type
}

// EffectiveAlgo returns the entry's algorithm, treating empty string as "SHA1".
// Mirrors EffectiveType() for backward compatibility with v1.0 entries.
func (e Entry) EffectiveAlgo() string {
	if e.Algo == "" {
		return "SHA1"
	}
	return e.Algo
}

// EffectivePeriod returns the entry's period, treating 0 as 30 seconds.
// HOTP entries store Period=0; when displayed or validated this defaults to 30.
func (e Entry) EffectivePeriod() uint {
	if e.Period == 0 {
		return 30
	}
	return e.Period
}

// EffectiveDigits returns the entry's digit count, treating 0 as 6.
// Legacy entries may store Digits=0; this defaults to the standard 6-digit code.
func (e Entry) EffectiveDigits() int {
	if e.Digits == 0 {
		return 6
	}
	return e.Digits
}

// GenerateCode computes the current OTP code for entry at time at.
// Dispatches to generateTOTP, generateHOTP, or generateSteam based on EffectiveType().
// For HOTP: returns (code, 0, nil) — remaining=0 signals no time expiry.
// For TOTP/Steam: returns (code, remainingSeconds, nil).
// Counter advancement for HOTP is the CALLER's responsibility — this function never
// mutates entry.Counter.
func GenerateCode(entry Entry, at time.Time) (code string, remaining int, err error) {
	switch entry.EffectiveType() {
	case "totp":
		return generateTOTP(entry, at)
	case "steam":
		return generateSteam(entry, at)
	case "hotp":
		return generateHOTP(entry)
	default:
		return "", 0, fmt.Errorf("unsupported OTP type: %q", entry.Type)
	}
}

// generateTOTP computes a standard TOTP code per RFC 6238.
// This is the existing GenerateCode body, extracted unchanged to preserve all TOTP behavior.
func generateTOTP(entry Entry, at time.Time) (string, int, error) {
	algo, err := parseAlgorithm(entry.Algo)
	if err != nil {
		return "", 0, err
	}

	digits := otp.Digits(entry.Digits)
	if digits == 0 {
		digits = otp.DigitsSix
	}

	period := entry.Period
	if period == 0 {
		period = 30
	}

	code, err := totp.GenerateCodeCustom(entry.Secret, at, totp.ValidateOpts{
		Period:    period,
		Digits:    digits,
		Algorithm: algo,
	})
	if err != nil {
		return "", 0, err
	}

	// Remaining seconds in the current period.
	// Formula: period - (unixTime % period)
	// At second 0 of a period: remaining = period (full period ahead, NOT 0)
	// At second 29 of a 30s period: remaining = 1
	remaining := int(period) - int(at.Unix()%int64(period))
	return code, remaining, nil
}

// generateHOTP computes an HOTP code per RFC 4226 for the given counter value.
// Returns (code, 0, nil) — HOTP has no time component; remaining is always 0.
// Do NOT increment entry.Counter here — counter advancement is the caller's responsibility.
func generateHOTP(entry Entry) (string, int, error) {
	algo, err := parseAlgorithm(entry.Algo)
	if err != nil {
		return "", 0, err
	}

	digits := otp.Digits(entry.Digits)
	if digits == 0 {
		digits = otp.DigitsSix
	}

	code, err := hotp.GenerateCodeCustom(entry.Secret, entry.Counter, hotp.ValidateOpts{
		Digits:    digits,
		Algorithm: algo,
	})
	if err != nil {
		return "", 0, err
	}

	return code, 0, nil // remaining=0 signals no time expiry; frontend hides countdown bar
}

// generateSteam computes a Steam Guard code using TOTP timing with Steam's base-26 alphabet.
// Steam codes are always: SHA1, 30s period, 5 characters from "23456789BCDFGHJKMNPQRTVWXY".
// The entry.Period field is respected if non-zero (defaults to 30).
func generateSteam(entry Entry, at time.Time) (string, int, error) {
	period := entry.Period
	if period == 0 {
		period = 30
	}

	code, err := totp.GenerateCodeCustom(entry.Secret, at, totp.ValidateOpts{
		Period:    period,
		Digits:    otp.Digits(5),
		Algorithm: otp.AlgorithmSHA1,
		Encoder:   otp.EncoderSteam,
	})
	if err != nil {
		return "", 0, err
	}

	remaining := int(period) - int(at.Unix()%int64(period))
	return code, remaining, nil
}

// parseAlgorithm maps Aegis/TOTP algorithm strings to pquerna/otp Algorithm constants.
// Only SHA1, SHA256, and SHA512 are supported per project requirements.
// Empty string defaults to SHA1 (matching Aegis convention).
func parseAlgorithm(algo string) (otp.Algorithm, error) {
	switch algo {
	case "SHA1", "":
		return otp.AlgorithmSHA1, nil
	case "SHA256":
		return otp.AlgorithmSHA256, nil
	case "SHA512":
		return otp.AlgorithmSHA512, nil
	default:
		return 0, fmt.Errorf("unsupported TOTP algorithm: %q (want SHA1, SHA256, or SHA512)", algo)
	}
}
