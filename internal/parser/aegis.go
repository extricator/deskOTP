// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"encoding/json"
	"fmt"

	"deskotp/internal/totp"
)

// AegisParser implements BackupParser for the Aegis plain (unencrypted) vault format.
type AegisParser struct{}

func (p *AegisParser) Name() string { return "Aegis" }

// CanParse returns true if data is an Aegis plain (unencrypted) vault.
// Aegis plain vaults: version >= 1, header key present with null slots and null params.
// Encrypted vaults have a non-null slots array (scrypt/Argon2id key derivation slots).
// The header key must be present in the JSON to distinguish Aegis from Proton Authenticator
// (which also has "version" but no "header").
func (p *AegisParser) CanParse(data []byte) bool {
	// Use a map to detect key presence explicitly. An absent "header" key is different
	// from a null "header" value. json.Unmarshal into a struct cannot distinguish these.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return false
	}
	// Require "version" key with a positive integer value.
	rawVersion, ok := top["version"]
	if !ok {
		return false
	}
	var version int
	if err := json.Unmarshal(rawVersion, &version); err != nil || version < 1 {
		return false
	}
	// Require "header" key to be present (distinguishes Aegis from other versioned formats).
	rawHeader, ok := top["header"]
	if !ok {
		return false
	}
	// "header" must be a JSON object with null slots and null params.
	var header struct {
		Slots  any `json:"slots"`
		Params any `json:"params"`
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return false
	}
	if header.Slots != nil || header.Params != nil {
		return false
	}
	// Reject deskOTP plain backups — they have db.deskotp_version >= 1.
	// deskOTP plain files are structurally valid Aegis plain files, but must be claimed
	// by DeskOTPParser (registered before AegisParser) to preserve x-deskotp fields.
	// This check ensures mutual exclusion in the cross-format test matrix.
	rawDB, ok := top["db"]
	if ok {
		var db struct {
			DeskOTPVersion int `json:"deskotp_version"`
		}
		if err := json.Unmarshal(rawDB, &db); err == nil && db.DeskOTPVersion >= 1 {
			return false
		}
	}
	return true
}

// Parse decodes an Aegis plain vault JSON payload into a slice of OTP entries.
// Supports totp, hotp, and steam entry types. Unsupported types (motp, yandex) are silently skipped.
// Returns a non-nil error for malformed JSON or missing db.entries field.
// Never returns a nil slice; returns an empty slice if no supported entries are found.
// password is accepted for interface compliance but ignored — plain vaults have no encryption.
func (p *AegisParser) Parse(data []byte, password string) ([]totp.Entry, error) {
	var vault aegisVault
	if err := json.Unmarshal(data, &vault); err != nil {
		return nil, fmt.Errorf("aegis: malformed JSON: %w", err)
	}
	if vault.DB.Entries == nil {
		return nil, fmt.Errorf("aegis: missing db.entries field")
	}

	var entries []totp.Entry
	for _, e := range vault.DB.Entries {
		switch e.Type {
		case "totp":
			entries = append(entries, totp.Entry{
				UUID:   e.UUID,
				Name:   e.Name,
				Issuer: e.Issuer,
				Secret: e.Info.Secret,
				Algo:   e.Info.Algo,
				Digits: e.Info.Digits,
				Period: uint(e.Info.Period),
				Type:   "totp",
			})
		case "hotp":
			// HOTP entries have no period — counter-based, not time-based.
			entries = append(entries, totp.Entry{
				UUID:    e.UUID,
				Name:    e.Name,
				Issuer:  e.Issuer,
				Secret:  e.Info.Secret,
				Algo:    e.Info.Algo,
				Digits:  e.Info.Digits,
				Type:    "hotp",
				Counter: uint64(e.Info.Counter),
			})
		case "steam":
			// Steam entries use fixed values per Aegis spec: SHA1, 30s period, 5 digits.
			// Ignore whatever the JSON says for these fields — Steam is fixed-format.
			entries = append(entries, totp.Entry{
				UUID:   e.UUID,
				Name:   e.Name,
				Issuer: e.Issuer,
				Secret: e.Info.Secret,
				Algo:   "SHA1",
				Digits: 5,
				Period: 30,
				Type:   "steam",
			})
		default:
			continue // motp, yandex, etc. — silently skip unsupported types
		}
	}
	if entries == nil {
		entries = []totp.Entry{} // never return nil slice
	}
	return entries, nil
}

// Private intermediate structs for Aegis JSON decoding.
// These are NOT exported -- only aegis.go uses them.
// aegisInfo.Period and Counter are int/int64 because encoding/json decodes JSON numbers
// to these types naturally; cast to uint/uint64 only when building totp.Entry.

type aegisVault struct {
	Version int         `json:"version"`
	Header  aegisHeader `json:"header"`
	DB      aegisDB     `json:"db"`
}

type aegisHeader struct {
	Slots  any `json:"slots"`
	Params any `json:"params"`
}

type aegisDB struct {
	Version int          `json:"version"`
	Entries []aegisEntry `json:"entries"`
}

type aegisEntry struct {
	Type   string    `json:"type"`
	UUID   string    `json:"uuid"`
	Name   string    `json:"name"`
	Issuer string    `json:"issuer"`
	Info   aegisInfo `json:"info"`
}

type aegisInfo struct {
	Secret  string `json:"secret"`
	Algo    string `json:"algo"`
	Digits  int    `json:"digits"`
	Period  int    `json:"period"`
	Counter int64  `json:"counter"` // HOTP only; 0 for totp/steam
}
