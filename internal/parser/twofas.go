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

// TwoFASParser implements BackupParser for the 2FAS backup format (schema versions 1-4).
// 2FAS is a popular open-source authenticator app for Android and iOS.
// Plain (unencrypted) backups are supported; encrypted backups (.2fas with password) are not.
type TwoFASParser struct{}

func (p *TwoFASParser) Name() string { return "2FAS" }

// CanParse returns true if data is a 2FAS plain backup (schemaVersion >= 1 and services array).
// 2FAS files have a top-level schemaVersion integer and a services JSON array.
// This probe rejects: Aegis vaults (no schemaVersion), andOTP arrays (JSON array at root),
// random JSON objects, non-JSON, and empty input.
func (p *TwoFASParser) CanParse(data []byte) bool {
	var probe struct {
		Services      json.RawMessage `json:"services"`
		SchemaVersion int             `json:"schemaVersion"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	if probe.SchemaVersion < 1 || probe.Services == nil {
		return false
	}
	// Confirm services is a JSON array (not an object or other type).
	var arr []json.RawMessage
	return json.Unmarshal(probe.Services, &arr) == nil
}

// Parse decodes a 2FAS plain backup JSON payload into a slice of OTP entries.
// Supports schema versions 1-4. Handles TOTP, HOTP, and Steam entry types.
//
// Field mapping:
//   - Issuer: outer "name" field (preferred); falls back to otp.issuer
//   - Name: otp.account (preferred); falls back to otp.label
//   - Defaults when fields absent: Algo="SHA1", Digits=6, Period=30
//   - tokenType absent (v1/v2): defaults to TOTP
//   - Steam: hardcoded SHA1/5 digits/30s period regardless of JSON values
//   - HOTP: Period=0 (counter-based, no time step)
//   - UUID: synthetic UUID v4 generated per entry (2FAS has no per-service UUID;
//     synthetic UUIDs prevent copiedId="" collision in the frontend)
//
// password is accepted for interface compliance but ignored — 2FAS plain vaults have no encryption.
// Never returns a nil slice; returns an empty slice if no supported entries are found.
func (p *TwoFASParser) Parse(data []byte, _ string) ([]totp.Entry, error) {
	var backup twoFASBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		return nil, fmt.Errorf("2fas: malformed JSON: %w", err)
	}

	entries := make([]totp.Entry, 0, len(backup.Services))
	for _, svc := range backup.Services {
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

		// Apply defaults for fields absent in schema v1/v2.
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
		// Use uppercase comparison for robustness (fixture uses "TOTP", "HOTP", "STEAM").
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

	// Never return nil slice (consistent with AegisParser convention).
	return entries, nil
}

// Private intermediate structs for 2FAS JSON decoding.
// These are NOT exported — only twofas.go uses them.

type twoFASBackup struct {
	SchemaVersion int           `json:"schemaVersion"`
	Services      []twoFASEntry `json:"services"`
}

type twoFASEntry struct {
	// Name is the service display name — used as Issuer (preferred over otp.issuer).
	Name   string    `json:"name"`
	Secret string    `json:"secret"`
	OTP    twoFASOTP `json:"otp"`
	// Note: The outer "type" field is a SERVICE ICON lookup ID (e.g. "Unknown"),
	// NOT the OTP type. Never read it for OTP type dispatch.
}

type twoFASOTP struct {
	Label     string  `json:"label"`
	Account   string  `json:"account"`
	Issuer    string  `json:"issuer"`
	Algorithm string  `json:"algorithm"`
	Digits    int     `json:"digits"`
	Period    int     `json:"period"`
	Counter   int64   `json:"counter"`
	// TokenType is a pointer so we can distinguish absent (nil) from empty string.
	// Absent in schema v1/v2 — defaults to TOTP. Present in v3/v4.
	TokenType *string `json:"tokenType"`
}
