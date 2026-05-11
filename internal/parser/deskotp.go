// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"encoding/json"
	"fmt"

	"deskotp/internal/totp"
)

// DeskOTPParser implements BackupParser for the deskOTP plain (unencrypted) backup format.
// deskOTP plain backups are structurally identical to Aegis plain backups but include
// a "deskotp_version" field in the inner db object and per-entry "x-deskotp" extensions
// that carry icon_slug, usage_count, and group metadata.
//
// DeskOTPParser MUST be registered before AegisParser — deskOTP plain files satisfy
// AegisParser.CanParse (version + null slots), but AegisParser.Parse would lose all
// x-deskotp fields.
type DeskOTPParser struct{}

func (p *DeskOTPParser) Name() string { return "deskOTP Backup" }

// CanParse returns true if data is a deskOTP plain backup.
// Detection: version >= 1, header.slots == nil, AND db.deskotp_version >= 1.
// The deskotp_version field is the discriminator from plain Aegis (which has no such field).
func (p *DeskOTPParser) CanParse(data []byte) bool {
	var probe struct {
		Version int `json:"version"`
		Header  struct {
			Slots any `json:"slots"`
		} `json:"header"`
		DB struct {
			DeskOTPVersion int `json:"deskotp_version"`
		} `json:"db"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.Version >= 1 && probe.Header.Slots == nil && probe.DB.DeskOTPVersion >= 1
}

// Parse decodes a deskOTP plain backup JSON payload into a slice of OTP entries.
// Restores icon_slug, usage_count, and group from x-deskotp extension per entry.
// Note field is read from the standard BackupEntry.note top-level field.
// Supports totp, hotp, and steam entry types. Unsupported types are silently skipped.
// Returns a non-nil error for malformed JSON or missing db.entries field.
// Never returns a nil slice; returns an empty slice if no supported entries are found.
// password is accepted for interface compliance but ignored — plain vaults have no encryption.
func (p *DeskOTPParser) Parse(data []byte, password string) ([]totp.Entry, error) {
	var vault deskotpVault
	if err := json.Unmarshal(data, &vault); err != nil {
		return nil, fmt.Errorf("deskotp: malformed JSON: %w", err)
	}
	if vault.DB.Entries == nil {
		return nil, fmt.Errorf("deskotp: missing db.entries field")
	}

	var entries []totp.Entry
	for _, e := range vault.DB.Entries {
		switch e.Type {
		case "totp":
			entries = append(entries, totp.Entry{
				UUID:       e.UUID,
				Name:       e.Name,
				Issuer:     e.Issuer,
				Note:       e.Note,
				Secret:     e.Info.Secret,
				Algo:       e.Info.Algo,
				Digits:     e.Info.Digits,
				Period:     uint(e.Info.Period),
				Type:       "totp",
				Icon:       e.XDeskOTP.IconSlug,
				UsageCount: e.XDeskOTP.UsageCount,
				Group:      e.XDeskOTP.Group,
			})
		case "hotp":
			entries = append(entries, totp.Entry{
				UUID:       e.UUID,
				Name:       e.Name,
				Issuer:     e.Issuer,
				Note:       e.Note,
				Secret:     e.Info.Secret,
				Algo:       e.Info.Algo,
				Digits:     e.Info.Digits,
				Type:       "hotp",
				Counter:    uint64(e.Info.Counter),
				Icon:       e.XDeskOTP.IconSlug,
				UsageCount: e.XDeskOTP.UsageCount,
				Group:      e.XDeskOTP.Group,
			})
		case "steam":
			// Steam entries use fixed values per Aegis spec: SHA1, 30s period, 5 digits.
			entries = append(entries, totp.Entry{
				UUID:       e.UUID,
				Name:       e.Name,
				Issuer:     e.Issuer,
				Note:       e.Note,
				Secret:     e.Info.Secret,
				Algo:       "SHA1",
				Digits:     5,
				Period:     30,
				Type:       "steam",
				Icon:       e.XDeskOTP.IconSlug,
				UsageCount: e.XDeskOTP.UsageCount,
				Group:      e.XDeskOTP.Group,
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

// Private intermediate structs for deskOTP plain JSON decoding.
// These are NOT exported — only deskotp.go uses them.

type deskotpVault struct {
	Version int          `json:"version"`
	Header  deskotpHeader `json:"header"`
	DB      deskotpDB    `json:"db"`
}

type deskotpHeader struct {
	Slots  any `json:"slots"`
	Params any `json:"params"`
}

type deskotpDB struct {
	Version        int            `json:"version"`
	DeskOTPVersion int            `json:"deskotp_version"`
	Entries        []deskotpEntry `json:"entries"`
}

type deskotpEntry struct {
	Type     string       `json:"type"`
	UUID     string       `json:"uuid"`
	Name     string       `json:"name"`
	Issuer   string       `json:"issuer"`
	Note     string       `json:"note"`
	Info     deskotpInfo  `json:"info"`
	XDeskOTP deskotpExt   `json:"x-deskotp"`
}

type deskotpInfo struct {
	Secret  string `json:"secret"`
	Algo    string `json:"algo"`
	Digits  int    `json:"digits"`
	Period  int    `json:"period"`
	Counter int64  `json:"counter"` // HOTP only; 0 for totp/steam
}

type deskotpExt struct {
	IconSlug   string `json:"icon_slug"`
	UsageCount int    `json:"usage_count"`
	Group      string `json:"group"`
}
