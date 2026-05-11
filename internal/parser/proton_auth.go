// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"deskotp/internal/totp"
)

// ProtonAuthParser implements BackupParser for the Proton Authenticator JSON backup format.
// Proton Authenticator (by Proton AG) exports a simple JSON file with a "version" number
// and "entries" array. Each entry contains a "content" object with a "uri" field holding
// a standard otpauth:// URI.
type ProtonAuthParser struct{}

func (p *ProtonAuthParser) Name() string { return "Proton Authenticator" }

// CanParse returns true if data is a Proton Authenticator JSON backup.
// Proton backups have both a numeric "version" field and a non-null "entries" array.
// Both keys must be present to distinguish from Bitwarden (which uses "items") and
// other JSON formats.
func (p *ProtonAuthParser) CanParse(data []byte) bool {
	var probe struct {
		Version *int             `json:"version"`
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	// Both version (numeric, non-nil) and entries (non-nil array) must be present.
	return probe.Version != nil && probe.Entries != nil
}

// Parse decodes a Proton Authenticator JSON backup into a slice of OTP entries.
// Each entry's content.uri field is a standard otpauth:// URI, delegated to ParseURI.
// password is accepted for interface compliance but ignored — plain format.
func (p *ProtonAuthParser) Parse(data []byte, _ string) ([]totp.Entry, error) {
	var backup protonBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		return nil, fmt.Errorf("proton_auth: malformed JSON: %w", err)
	}

	var entries []totp.Entry
	for _, e := range backup.Entries {
		if e.Content.URI == "" {
			continue // skip entries without a URI
		}
		parsed, err := ParseURI(e.Content.URI)
		if err != nil {
			return nil, fmt.Errorf("proton_auth: entry %q: %w", e.Content.Name, err)
		}
		entries = append(entries, totp.Entry{
			UUID:    uuid.New().String(),
			Name:    parsed.Name,
			Issuer:  parsed.Issuer,
			Secret:  parsed.Secret,
			Algo:    parsed.Algo,
			Digits:  parsed.Digits,
			Period:  parsed.Period,
			Type:    parsed.Type,
			Counter: parsed.Counter,
		})
	}
	if entries == nil {
		entries = []totp.Entry{}
	}
	return entries, nil
}

// Private structs for decoding Proton Authenticator JSON.

type protonBackup struct {
	Version int            `json:"version"`
	Entries []protonEntry  `json:"entries"`
}

type protonEntry struct {
	ID      string        `json:"id"`
	Content protonContent `json:"content"`
	Note    *string       `json:"note"`
}

type protonContent struct {
	URI       string `json:"uri"`
	EntryType string `json:"entry_type"`
	Name      string `json:"name"`
}
