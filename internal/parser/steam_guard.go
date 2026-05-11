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

// SteamGuardParser implements BackupParser for Steam Guard JSON backup files.
// Steam Guard has two JSON schema variants:
//   - New schema: root JSON object with "accounts" map (key = random token string, value = entry object)
//   - Old schema: single flat JSON object at root level
//
// Both schemas contain a "uri" field with an otpauth:// URI. The URI type is always
// "totp" (which ParseURI would produce), but Steam Guard entries MUST be type "steam"
// with 5 digits and SHA1 algorithm. The parser overrides these fields post-parse.
type SteamGuardParser struct{}

func (p *SteamGuardParser) Name() string { return "Steam Guard" }

// steamInnerEntry represents a single Steam Guard account in both schema variants.
// The "uri" field contains an otpauth:// URI; "account_name" is the Steam username.
type steamInnerEntry struct {
	URI         string `json:"uri"`
	AccountName string `json:"account_name"`
}

// steamNewSchema is the new Steam Guard export format with an "accounts" map.
type steamNewSchema struct {
	Accounts map[string]steamInnerEntry `json:"accounts"`
}

// CanParse returns true if data looks like a Steam Guard JSON backup.
//
// Detection strategy:
//  1. Try new schema: JSON object with "accounts" map — if at least one entry has a non-empty
//     uri containing "otpauth://", return true.
//  2. Try old schema: JSON object with top-level "uri" and "account_name" fields — if both
//     are non-empty and uri contains "otpauth://", return true.
//
// This correctly rejects Aegis vaults (has "version"/"header"/"db") and andOTP backups
// (root JSON array, not object).
func (p *SteamGuardParser) CanParse(data []byte) bool {
	// Try new schema (accounts map).
	var newSchema steamNewSchema
	if json.Unmarshal(data, &newSchema) == nil && len(newSchema.Accounts) > 0 {
		for _, entry := range newSchema.Accounts {
			if entry.URI != "" && strings.Contains(entry.URI, "otpauth://") {
				return true
			}
		}
	}

	// Try old schema (flat object with uri and account_name at root).
	var oldSchema steamInnerEntry
	if json.Unmarshal(data, &oldSchema) == nil &&
		oldSchema.URI != "" &&
		strings.Contains(oldSchema.URI, "otpauth://") &&
		oldSchema.AccountName != "" {
		return true
	}

	return false
}

// Parse decodes a Steam Guard JSON backup into a slice of OTP entries.
//
// Both new and old schema variants are handled. For each entry:
//  1. ParseURI extracts issuer, name, secret, and other fields from the otpauth:// URI.
//  2. Type, Digits, Algo, and Period are OVERRIDDEN to Steam Guard constants:
//     Type="steam", Digits=5, Algo="SHA1", Period=30.
//     This is REQUIRED because Steam Guard URIs say "otpauth://totp/" but must
//     produce Steam-type entries that use the Steam base-26 alphabet for codes.
//
// password is accepted for interface compliance but ignored — plain-only format.
func (p *SteamGuardParser) Parse(data []byte, _ string) ([]totp.Entry, error) {
	var entries []totp.Entry

	// Try new schema first (accounts map).
	var newSchema steamNewSchema
	if json.Unmarshal(data, &newSchema) == nil && len(newSchema.Accounts) > 0 {
		for _, e := range newSchema.Accounts {
			if e.URI == "" {
				continue
			}
			entry, err := parseSteamEntry(e.URI)
			if err != nil {
				return nil, fmt.Errorf("steam_guard: %w", err)
			}
			entries = append(entries, entry)
		}
		return entries, nil
	}

	// Fall back to old schema (flat object).
	var oldSchema steamInnerEntry
	if err := json.Unmarshal(data, &oldSchema); err != nil {
		return nil, fmt.Errorf("steam_guard: malformed JSON: %w", err)
	}
	if oldSchema.URI == "" {
		return nil, fmt.Errorf("steam_guard: no uri field found in old schema")
	}
	entry, err := parseSteamEntry(oldSchema.URI)
	if err != nil {
		return nil, fmt.Errorf("steam_guard: %w", err)
	}
	entries = append(entries, entry)

	return entries, nil
}

// parseSteamEntry parses one Steam Guard URI and applies the Steam-type overrides.
// The URI says "otpauth://totp/" but all fields are overridden to Steam constants.
func parseSteamEntry(uri string) (totp.Entry, error) {
	parsed, err := ParseURI(uri)
	if err != nil {
		return totp.Entry{}, fmt.Errorf("invalid uri: %w", err)
	}

	return totp.Entry{
		UUID:   uuid.New().String(),
		Name:   parsed.Name,
		Issuer: parsed.Issuer,
		Secret: parsed.Secret,
		// OVERRIDE: Steam Guard entries must use these constants regardless of URI values.
		Type:   "steam",
		Digits: 5,
		Algo:   "SHA1",
		Period: 30,
	}, nil
}
