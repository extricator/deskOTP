// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"deskotp/internal/totp"
)

// DeskOTPEncryptedParser implements BackupParser for the deskOTP encrypted vault format.
//
// deskOTP encrypted backups are produced by backup.Export with a non-nil masterKey.
// They use the vault.VaultFile JSON structure with a "data" key (base64-encoded
// AES-GCM ciphertext of the inner deskOTP DB JSON). The slot structure is identical
// to Aegis encrypted vaults — scrypt KDF + AES-256-GCM — but the outer key is "data"
// not "db".
//
// DeskOTPEncryptedParser MUST be registered before AegisEncryptedParser. Both formats
// have version + non-null slots, but deskOTP encrypted uses "data" while Aegis uses
// "db" — this difference is the CanParse discriminator.
type DeskOTPEncryptedParser struct{}

func (p *DeskOTPEncryptedParser) Name() string { return "deskOTP Backup (Encrypted)" }

// CanParse returns true if data is a deskOTP encrypted backup.
// Detection uses mutual exclusion between "data" and "db" keys:
//   - "data" key present (deskOTP encrypted vault.VaultFile)
//   - "db" key absent (Aegis encrypted uses "db", mutually exclusive)
//   - "version" >= 1
//   - "header" with non-empty slots array
func (p *DeskOTPEncryptedParser) CanParse(data []byte) bool {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}

	// "db" key present means it's Aegis encrypted — not ours
	if _, hasDB := probe["db"]; hasDB {
		return false
	}

	// "data" key required
	if _, hasData := probe["data"]; !hasData {
		return false
	}

	// version >= 1
	var version int
	if err := json.Unmarshal(probe["version"], &version); err != nil || version < 1 {
		return false
	}

	// header with non-empty slots array
	var header struct {
		Slots json.RawMessage `json:"slots"`
	}
	if err := json.Unmarshal(probe["header"], &header); err != nil {
		return false
	}
	if header.Slots == nil {
		return false
	}
	var slots []json.RawMessage
	return json.Unmarshal(header.Slots, &slots) == nil && len(slots) > 0
}

// Parse decrypts a deskOTP encrypted backup using the supplied password and returns entries.
//
// Decryption flow:
//  1. Unmarshal the outer JSON (slots + encrypted data payload under "data" key)
//  2. Recover master key via decryptMasterKey (reused from aegis_encrypted.go — same package)
//  3. Base64-decode the "data" field, hex-decode nonce and tag from header.params
//  4. AES-256-GCM decrypt the ciphertext with masterKey + nonce + tag
//  5. Parse the decrypted plaintext as deskOTP DB JSON (same schema as DeskOTPParser)
//
// Returns ErrPasswordRequired if password is empty.
// Returns ErrWrongPassword if slot decryption fails with the given password.
func (p *DeskOTPEncryptedParser) Parse(data []byte, password string) ([]totp.Entry, error) {
	if password == "" {
		return nil, ErrPasswordRequired
	}

	var vault deskotpEncryptedVault
	if err := json.Unmarshal(data, &vault); err != nil {
		return nil, fmt.Errorf("deskotp encrypted: malformed JSON: %w", err)
	}

	// Step 1: recover master key from a password slot (reuses aegis_encrypted.go helper)
	masterKey, err := decryptMasterKey(vault.Header, password)
	if err != nil {
		return nil, err // includes ErrWrongPassword
	}

	// Step 2: base64-decode the encrypted data ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(vault.Data)
	if err != nil {
		return nil, fmt.Errorf("deskotp encrypted: decode data base64: %w", err)
	}

	// Step 3: hex-decode data nonce and tag
	dataNonce, err := hex.DecodeString(vault.Header.Params.Nonce)
	if err != nil {
		return nil, fmt.Errorf("deskotp encrypted: decode data nonce: %w", err)
	}
	dataTag, err := hex.DecodeString(vault.Header.Params.Tag)
	if err != nil {
		return nil, fmt.Errorf("deskotp encrypted: decode data tag: %w", err)
	}

	// Step 4: decrypt the data payload with master key using AES-256-GCM
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("deskotp encrypted: create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("deskotp encrypted: create GCM: %w", err)
	}
	// GCM expects ciphertext || tag as a single input slice
	plaintext, err := gcm.Open(nil, dataNonce, append(ciphertext, dataTag...), nil)
	if err != nil {
		return nil, fmt.Errorf("deskotp encrypted: decrypt data: %w", err)
	}

	// Step 5: parse decrypted plaintext as deskOTP DB JSON
	return parseDeskOTPDB(plaintext)
}

// parseDeskOTPDB parses the decrypted inner database JSON produced by AES-GCM decryption.
// The inner DB has the deskOTP backup DB structure:
//
//	{"version": 1, "deskotp_version": 1, "entries": [{...}, ...]}
//
// Reuses deskotpDB, deskotpEntry, and deskotpInfo types from deskotp.go (same package).
// Restores icon_slug, usage_count, and group from x-deskotp extension per entry.
// Note field is read from the standard BackupEntry.note top-level field.
func parseDeskOTPDB(data []byte) ([]totp.Entry, error) {
	var db deskotpDB
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("deskotp encrypted: malformed decrypted db JSON: %w", err)
	}
	if db.Entries == nil {
		return nil, fmt.Errorf("deskotp encrypted: missing entries field in decrypted db")
	}

	var entries []totp.Entry
	for _, e := range db.Entries {
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

// Private JSON struct for the deskOTP encrypted vault outer layer.
// The key difference from aegisEncryptedVault is "data" (not "db") for the payload.
// Header reuses aegisEncHeader from aegis_encrypted.go (same package — accessible directly).
type deskotpEncryptedVault struct {
	Version int           `json:"version"`
	Header  aegisEncHeader `json:"header"` // same slot structure as Aegis
	Data    string         `json:"data"`   // base64-encoded AES-GCM ciphertext (NOT "db")
}
