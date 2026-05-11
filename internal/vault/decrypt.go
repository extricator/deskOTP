// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"deskotp/internal/entries"
	"deskotp/internal/totp"

	"golang.org/x/crypto/scrypt"
)

// DecryptKey recovers the master key from a vault file using the provided password.
// This is used by app.go to extract the master key after Encrypt (for caching in KeyCache).
func DecryptKey(data []byte, password string) ([]byte, error) {
	masterKey, _, err := decryptMasterKey(data, password)
	if err != nil {
		return nil, err
	}
	return masterKey, nil
}

// DecryptFull unmarshals a vault file, recovers the master key, decrypts the data
// payload, and returns entries, groups, and the master key. This avoids running
// scrypt twice when the caller needs both (e.g. UnlockVault).
func DecryptFull(data []byte, password string) ([]totp.Entry, []entries.GroupInfo, []byte, error) {
	ents, groups, masterKey, err := decryptPayload(data, password)
	if err != nil {
		return nil, nil, nil, err
	}
	return ents, groups, masterKey, nil
}

// Decrypt unmarshals a vault file, recovers the master key from a password slot,
// decrypts the data payload, and returns the entries and groups.
func Decrypt(data []byte, password string) ([]totp.Entry, []entries.GroupInfo, error) {
	ents, groups, _, err := decryptPayload(data, password)
	return ents, groups, err
}

// decryptPayload is the shared implementation for Decrypt and DecryptFull.
// It derives the master key once via scrypt and returns entries, groups, and key.
// Supports both old format (bare []totp.Entry array) and new format (vaultPayload struct).
func decryptPayload(data []byte, password string) ([]totp.Entry, []entries.GroupInfo, []byte, error) {
	if password == "" {
		return nil, nil, nil, ErrPasswordRequired
	}

	masterKey, vault, err := decryptMasterKey(data, password)
	if err != nil {
		return nil, nil, nil, err
	}

	// Base64-decode the encrypted data payload
	ciphertext, err := base64.StdEncoding.DecodeString(vault.Data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vault: decode data base64: %w", err)
	}

	// Hex-decode data nonce and tag
	dataNonce, err := hex.DecodeString(vault.Header.Params.Nonce)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vault: decode data nonce: %w", err)
	}
	dataTag, err := hex.DecodeString(vault.Header.Params.Tag)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vault: decode data tag: %w", err)
	}

	// Decrypt data with master key
	plaintext, err := decryptGCM(masterKey, ciphertext, dataNonce, dataTag)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vault: decrypt data: %w", err)
	}

	// Detect format by first non-whitespace byte
	trimmed := bytes.TrimSpace(plaintext)
	if len(trimmed) == 0 {
		return []totp.Entry{}, []entries.GroupInfo{}, masterKey, nil
	}
	switch trimmed[0] {
	case '[':
		// Old format: bare entry array, no groups
		var ents []totp.Entry
		if err := json.Unmarshal(plaintext, &ents); err != nil {
			return nil, nil, nil, fmt.Errorf("vault: unmarshal entries: %w", err)
		}
		if ents == nil {
			ents = []totp.Entry{}
		}
		return ents, []entries.GroupInfo{}, masterKey, nil
	case '{':
		// New format: vaultPayload{entries, groups}
		// Use two-step unmarshal for backward-compatible groups deserialization
		// (supports both old []string and new []GroupInfo formats).
		type rawPayload struct {
			Entries []totp.Entry    `json:"entries"`
			Groups  json.RawMessage `json:"groups"`
		}
		var raw rawPayload
		if err := json.Unmarshal(plaintext, &raw); err != nil {
			return nil, nil, nil, fmt.Errorf("vault: unmarshal payload: %w", err)
		}
		if raw.Entries == nil {
			raw.Entries = []totp.Entry{}
		}
		groups, err := unmarshalGroups(raw.Groups)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("vault: unmarshal groups: %w", err)
		}
		return raw.Entries, groups, masterKey, nil
	default:
		return nil, nil, nil, fmt.Errorf("vault: unrecognized plaintext format")
	}
}

// unmarshalGroups deserializes a JSON groups field that may be either the old
// []string format or the new []GroupInfo format. This ensures backward compatibility
// when reading vaults written by older versions of the app.
func unmarshalGroups(data json.RawMessage) ([]entries.GroupInfo, error) {
	if len(data) == 0 || string(data) == "null" {
		return []entries.GroupInfo{}, nil
	}
	// Try new format first: []GroupInfo
	var groups []entries.GroupInfo
	if err := json.Unmarshal(data, &groups); err == nil {
		if groups == nil {
			groups = []entries.GroupInfo{}
		}
		return groups, nil
	}
	// Fall back to old format: []string
	var names []string
	if err := json.Unmarshal(data, &names); err != nil {
		return nil, fmt.Errorf("unrecognized format: %w", err)
	}
	result := make([]entries.GroupInfo, len(names))
	for i, name := range names {
		result[i] = entries.GroupInfo{Name: name}
	}
	return result, nil
}

// decryptMasterKey iterates password slots (Type==1) and attempts to recover the
// master key using the provided password. Returns the master key and parsed vault
// on success, or ErrWrongPassword if no slot succeeds.
func decryptMasterKey(data []byte, password string) ([]byte, VaultFile, error) {
	var vault VaultFile
	if err := json.Unmarshal(data, &vault); err != nil {
		return nil, VaultFile{}, fmt.Errorf("vault: malformed JSON: %w", err)
	}

	for _, slot := range vault.Header.Slots {
		if slot.Type != 1 { // only password slots
			continue
		}

		// Decode slot hex fields
		salt, err := hex.DecodeString(slot.Salt)
		if err != nil {
			return nil, VaultFile{}, fmt.Errorf("vault: decode slot salt: %w", err)
		}
		encKey, err := hex.DecodeString(slot.Key)
		if err != nil {
			return nil, VaultFile{}, fmt.Errorf("vault: decode slot key: %w", err)
		}
		nonce, err := hex.DecodeString(slot.KeyParams.Nonce)
		if err != nil {
			return nil, VaultFile{}, fmt.Errorf("vault: decode slot nonce: %w", err)
		}
		tag, err := hex.DecodeString(slot.KeyParams.Tag)
		if err != nil {
			return nil, VaultFile{}, fmt.Errorf("vault: decode slot tag: %w", err)
		}

		// Derive slot key via scrypt using params from the slot
		slotKey, err := scrypt.Key([]byte(password), salt, slot.N, slot.R, slot.P, keySize)
		if err != nil {
			return nil, VaultFile{}, fmt.Errorf("vault: scrypt: %w", err)
		}

		// Attempt AES-256-GCM decryption of the encrypted master key
		masterKey, err := decryptGCM(slotKey, encKey, nonce, tag)
		if err == nil {
			return masterKey, vault, nil // correct password
		}
		// Wrong password for this slot -- try next
	}

	return nil, VaultFile{}, ErrWrongPassword
}
