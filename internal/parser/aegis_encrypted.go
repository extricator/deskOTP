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

	"golang.org/x/crypto/scrypt"
)

// AegisEncryptedParser implements BackupParser for the Aegis encrypted vault format.
// Encrypted vaults use scrypt KDF + AES-256-GCM for the master key (per slot) and
// then AES-256-GCM for the database payload.
type AegisEncryptedParser struct{}

func (p *AegisEncryptedParser) Name() string { return "Aegis (Encrypted)" }

// CanParse returns true if data is an Aegis encrypted vault.
// Encrypted vaults have version >= 1, a non-empty header.slots JSON array,
// AND a "db" key (base64-encoded ciphertext). The "db" key is the discriminator
// from deskOTP encrypted vaults, which use a "data" key instead.
func (p *AegisEncryptedParser) CanParse(data []byte) bool {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}

	// "db" key required — Aegis encrypted uses "db", deskOTP encrypted uses "data"
	if _, hasDB := probe["db"]; !hasDB {
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

// Parse decrypts an Aegis encrypted vault using the supplied password and returns the entries.
//
// Decryption flow:
//  1. Unmarshal the outer JSON structure (slots + encrypted DB)
//  2. Iterate password slots (type=1), derive a slot key via scrypt, attempt AES-GCM decryption of master key
//  3. If no slot succeeds: return ErrWrongPassword
//  4. Base64-decode the encrypted DB, decrypt with master key + header.params nonce/tag
//  5. Delegate parsing of the decrypted plaintext to AegisParser
//
// Returns ErrWrongPassword only when slot decryption fails — db decryption failures
// after a successful slot open indicate a corrupted file, not a wrong password.
func (p *AegisEncryptedParser) Parse(data []byte, password string) ([]totp.Entry, error) {
	if password == "" {
		return nil, ErrPasswordRequired
	}
	var vault aegisEncryptedVault
	if err := json.Unmarshal(data, &vault); err != nil {
		return nil, fmt.Errorf("aegis encrypted: malformed JSON: %w", err)
	}

	// Step 1: recover master key from a password slot
	masterKey, err := decryptMasterKey(vault.Header, password)
	if err != nil {
		return nil, err // includes ErrWrongPassword
	}

	// Step 2: base64-decode the encrypted DB ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(vault.DB)
	if err != nil {
		return nil, fmt.Errorf("aegis encrypted: decode db base64: %w", err)
	}

	// Step 3: decode DB nonce and tag
	dbNonce, err := hex.DecodeString(vault.Header.Params.Nonce)
	if err != nil {
		return nil, fmt.Errorf("aegis encrypted: decode db nonce: %w", err)
	}
	dbTag, err := hex.DecodeString(vault.Header.Params.Tag)
	if err != nil {
		return nil, fmt.Errorf("aegis encrypted: decode db tag: %w", err)
	}

	// Step 4: decrypt the DB with master key
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("aegis encrypted: create db AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aegis encrypted: create db GCM: %w", err)
	}
	// GCM expects ciphertext || tag as a single input slice
	plaintext, err := gcm.Open(nil, dbNonce, append(ciphertext, dbTag...), nil)
	if err != nil {
		return nil, fmt.Errorf("aegis encrypted: decrypt db: %w", err)
	}

	// Step 5: parse the decrypted inner DB JSON.
	// The decrypted plaintext is the inner database JSON directly:
	//   {"version": 1, "entries": [{...}, ...]}
	// This is NOT the full outer vault JSON, so we parse it using aegisDB directly.
	return parseAegisDB(plaintext)
}

// parseAegisDB parses the decrypted inner database JSON produced by AES-GCM decryption.
// The inner DB has the structure: {"version": int, "entries": [{...}]}
// This is different from the outer vault JSON which wraps it in a "db" key.
// Reuses aegisDB, aegisEntry, aegisInfo types from aegis.go (same package).
func parseAegisDB(data []byte) ([]totp.Entry, error) {
	var db aegisDB
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("aegis encrypted: malformed decrypted db JSON: %w", err)
	}
	if db.Entries == nil {
		return nil, fmt.Errorf("aegis encrypted: missing entries field in decrypted db")
	}

	var entries []totp.Entry
	for _, e := range db.Entries {
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
			continue // motp, yandex, etc. -- silently skip unsupported types
		}
	}
	if entries == nil {
		entries = []totp.Entry{} // never return nil slice
	}
	return entries, nil
}

// decryptMasterKey iterates type=1 (password) slots and attempts scrypt KDF + AES-GCM
// decryption of the encrypted master key for each slot.
// Returns the 32-byte master key on first success, or ErrWrongPassword if all slots fail.
func decryptMasterKey(header aegisEncHeader, password string) ([]byte, error) {
	for _, slot := range header.Slots {
		if slot.Type != 1 { // only password slots; skip biometric or other slot types
			continue
		}

		// Decode slot hex fields
		salt, err := hex.DecodeString(slot.Salt)
		if err != nil {
			return nil, fmt.Errorf("aegis encrypted: decode slot salt: %w", err)
		}
		encKey, err := hex.DecodeString(slot.Key)
		if err != nil {
			return nil, fmt.Errorf("aegis encrypted: decode slot key: %w", err)
		}
		nonce, err := hex.DecodeString(slot.KeyParams.Nonce)
		if err != nil {
			return nil, fmt.Errorf("aegis encrypted: decode slot nonce: %w", err)
		}
		tag, err := hex.DecodeString(slot.KeyParams.Tag)
		if err != nil {
			return nil, fmt.Errorf("aegis encrypted: decode slot tag: %w", err)
		}

		// Derive slot key using scrypt parameters from the JSON slot
		// N, r, p are read from the slot -- never hardcoded.
		slotKey, err := scrypt.Key([]byte(password), salt, slot.N, slot.R, slot.P, 32)
		if err != nil {
			return nil, fmt.Errorf("aegis encrypted: scrypt: %w", err)
		}

		// Attempt AES-256-GCM decryption of the encrypted master key
		block, err := aes.NewCipher(slotKey)
		if err != nil {
			return nil, fmt.Errorf("aegis encrypted: create slot AES cipher: %w", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("aegis encrypted: create slot GCM: %w", err)
		}
		// GCM expects ciphertext || tag as a single input slice
		masterKey, err := gcm.Open(nil, nonce, append(encKey, tag...), nil)
		if err == nil {
			return masterKey, nil // correct password -- master key recovered
		}
		// Wrong password for this slot -- try next slot
	}
	return nil, ErrWrongPassword
}

// Private JSON structs for the Aegis encrypted vault format.
// These are NOT exported -- only aegis_encrypted.go uses them.

type aegisEncryptedVault struct {
	Version int           `json:"version"`
	Header  aegisEncHeader `json:"header"`
	DB      string         `json:"db"` // base64-encoded AES-GCM ciphertext of the JSON database
}

type aegisEncHeader struct {
	Slots  []aegisSlot   `json:"slots"`
	Params aegisEncParams `json:"params"` // nonce + tag for the DB ciphertext
}

type aegisSlot struct {
	Type      int            `json:"type"`       // 1 = password slot
	UUID      string         `json:"uuid"`
	Key       string         `json:"key"`        // hex-encoded AES-GCM ciphertext of master key
	KeyParams aegisEncParams `json:"key_params"` // nonce + tag for Key decryption
	N         int            `json:"n"`          // scrypt cost parameter N
	R         int            `json:"r"`          // scrypt block size parameter r
	P         int            `json:"p"`          // scrypt parallelisation parameter p
	Salt      string         `json:"salt"`       // hex-encoded 32-byte scrypt salt
}

type aegisEncParams struct {
	Nonce string `json:"nonce"` // hex-encoded 12-byte GCM nonce
	Tag   string `json:"tag"`   // hex-encoded 16-byte GCM authentication tag
}
