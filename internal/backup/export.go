// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

// Package backup serializes totp.Entry slices into Aegis-compatible backup JSON.
// It handles both plain (unencrypted) and AES-256-GCM encrypted output paths.
// The encrypted path delegates to vault.EncryptBytes — the backup package never
// touches the key cache or creates new cryptographic slots.
package backup

import (
	"encoding/json"
	"fmt"

	"deskotp/internal/entries"
	"deskotp/internal/totp"
	"deskotp/internal/vault"
)

// BackupFile is the top-level Aegis backup structure.
// When plain: DB is a BackupDB value (marshals as a JSON object).
// When encrypted: vault.EncryptBytes produces the top-level VaultFile JSON directly.
type BackupFile struct {
	Version int          `json:"version"` // always 1
	Header  BackupHeader `json:"header"`
	DB      any          `json:"db"` // BackupDB (plain) or base64 string (encrypted)
}

// BackupHeader holds the encryption metadata. Both fields are null for plain exports.
type BackupHeader struct {
	Slots  any `json:"slots"`  // null for plain; []Slot for encrypted (not used here)
	Params any `json:"params"` // null for plain; GCMParams for encrypted (not used here)
}

// BackupGroupInfo holds group name and icon for backup round-trip preservation.
type BackupGroupInfo struct {
	Name string `json:"name"`
	Icon string `json:"icon,omitempty"`
}

// BackupDB is the inner database structure.
// db.version is 1 per STATE.md decision (matches existing deskOTP/Aegis fixtures;
// avoids Aegis group UUID semantics introduced in version 3).
type BackupDB struct {
	Version        int               `json:"version"`         // 1 (per STATE.md decision)
	DeskOTPVersion int               `json:"deskotp_version"` // 1
	Groups         []BackupGroupInfo `json:"groups,omitempty"`
	Entries        []BackupEntry     `json:"entries"`
}

// BackupEntry maps a totp.Entry to the Aegis entry format.
type BackupEntry struct {
	Type     string      `json:"type"`
	UUID     string      `json:"uuid"`
	Name     string      `json:"name"`
	Issuer   string      `json:"issuer"`
	Note     string      `json:"note"`
	Favorite bool        `json:"favorite"`  // always false
	Icon     any         `json:"icon"`      // always null (BFMT-05: icon_data field)
	IconMime any         `json:"icon_mime"` // always null (BFMT-05)
	Info     BackupInfo  `json:"info"`
	Groups   []string    `json:"groups"`    // always [] (Aegis UUID group refs — unused)
	XDeskOTP DeskOTPExt  `json:"x-deskotp"` // BFMT-02 deskOTP extension
}

// DeskOTPExt holds deskOTP-specific fields that Aegis ignores (unknown fields are
// preserved verbatim by Aegis's JSON parser, so this object survives round-trips).
type DeskOTPExt struct {
	IconSlug   string `json:"icon_slug,omitempty"`
	UsageCount int    `json:"usage_count,omitempty"`
	Group      string `json:"group,omitempty"`
}

// BackupInfo holds OTP parameters. Period is omitted for HOTP; Counter is omitted
// for TOTP and Steam.
type BackupInfo struct {
	Secret  string `json:"secret"`
	Algo    string `json:"algo"`
	Digits  int    `json:"digits"`
	Period  uint   `json:"period,omitempty"`  // TOTP + Steam only
	Counter uint64 `json:"counter,omitempty"` // HOTP only
}

// Export serializes entries into Aegis-compatible backup bytes.
//
// masterKey nil: produces plain JSON (db is a JSON object in the output).
// masterKey non-nil: produces AES-256-GCM encrypted output via vault.EncryptBytes
// (db becomes base64 ciphertext). existingVaultData is required when masterKey
// is non-nil — it provides the current slot structure for key wrapping.
//
// The caller is responsible for checking whether the vault is locked before
// calling Export with a non-nil masterKey (BFMT-04: doBackupWrite in app.go checks
// keyCache.Key() and skips backup entirely if the vault is locked).
func Export(ents []totp.Entry, groups []entries.GroupInfo, masterKey []byte, existingVaultData []byte) ([]byte, error) {
	db := buildDB(ents, groups)

	if masterKey == nil {
		return marshalPlainBackup(db)
	}

	// Encrypted path: marshal BackupDB to JSON bytes, then encrypt with cached key.
	dbBytes, err := json.Marshal(db)
	if err != nil {
		return nil, fmt.Errorf("backup: marshal db: %w", err)
	}
	return vault.EncryptBytes(dbBytes, masterKey, existingVaultData)
}

// buildDB converts a slice of totp.Entry values into a BackupDB.
func buildDB(ents []totp.Entry, groups []entries.GroupInfo) BackupDB {
	var backupGroups []BackupGroupInfo
	if len(groups) > 0 {
		backupGroups = make([]BackupGroupInfo, len(groups))
		for i, g := range groups {
			backupGroups[i] = BackupGroupInfo{Name: g.Name, Icon: g.Icon}
		}
	}

	db := BackupDB{
		Version:        1,
		DeskOTPVersion: 1,
		Groups:         backupGroups,
		Entries:        make([]BackupEntry, 0, len(ents)),
	}
	for _, e := range ents {
		db.Entries = append(db.Entries, buildBackupEntry(e))
	}
	return db
}

// buildBackupEntry maps a single totp.Entry to a BackupEntry.
func buildBackupEntry(e totp.Entry) BackupEntry {
	info := BackupInfo{
		Secret: e.Secret,
		Algo:   e.EffectiveAlgo(),
		Digits: e.Digits,
	}

	switch e.EffectiveType() {
	case "hotp":
		info.Counter = e.Counter
	default: // "totp", "steam"
		info.Period = e.Period
		if info.Period == 0 {
			info.Period = 30
		}
	}

	return BackupEntry{
		Type:     e.EffectiveType(),
		UUID:     e.UUID,
		Name:     e.Name,
		Issuer:   e.Issuer,
		Note:     e.Note,
		Favorite: false,
		Icon:     nil, // BFMT-05: must be explicitly null, not omitted
		IconMime: nil, // BFMT-05: must be explicitly null, not omitted
		Info:     info,
		Groups:   []string{}, // must be [] not null (Aegis UUID group refs — unused)
		XDeskOTP: DeskOTPExt{
			IconSlug:   e.Icon,
			UsageCount: e.UsageCount,
			Group:      e.Group,
		},
	}
}

// marshalPlainBackup wraps a BackupDB in a BackupFile and returns indented JSON.
func marshalPlainBackup(db BackupDB) ([]byte, error) {
	bf := BackupFile{
		Version: 1,
		Header: BackupHeader{
			Slots:  nil,
			Params: nil,
		},
		DB: db,
	}
	return json.MarshalIndent(bf, "", "  ")
}
