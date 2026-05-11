// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package vault

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"deskotp/internal/entries"
	"deskotp/internal/totp"
)

// Encrypt marshals entries and groups to JSON, encrypts with a random master key
// protected by a password slot, and returns the vault file as indented JSON.
func Encrypt(ents []totp.Entry, groups []entries.GroupInfo, password string) ([]byte, error) {
	if password == "" {
		return nil, ErrPasswordRequired
	}

	// Marshal entries and groups to JSON plaintext
	plaintext, err := marshalPayload(ents, groups)
	if err != nil {
		return nil, fmt.Errorf("vault: marshal payload: %w", err)
	}

	// Generate random 32-byte master key
	masterKey := make([]byte, keySize)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, fmt.Errorf("vault: generate master key: %w", err)
	}

	// Encrypt plaintext with master key using AES-256-GCM
	ciphertext, nonce, tag, err := encryptGCM(masterKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("vault: encrypt data: %w", err)
	}

	// Create password slot wrapping the master key
	slot, err := createSlot(masterKey, password)
	if err != nil {
		return nil, err
	}

	// Assemble vault file
	vault := VaultFile{
		Version: 1,
		Header: Header{
			Slots: []Slot{slot},
			Params: GCMParams{
				Nonce: hex.EncodeToString(nonce),
				Tag:   hex.EncodeToString(tag),
			},
		},
		Data: base64.StdEncoding.EncodeToString(ciphertext),
	}

	return json.MarshalIndent(vault, "", "  ")
}

// EncryptWithKey marshals entries and groups to JSON, encrypts with the provided
// master key using AES-256-GCM, and returns the vault file as indented JSON. The
// slot structure from existingVaultData is preserved verbatim -- only the Data
// field and Header.Params (nonce+tag) change. This avoids re-deriving scrypt on
// every save when the master key is already cached.
func EncryptWithKey(ents []totp.Entry, groups []entries.GroupInfo, masterKey, existingVaultData []byte) ([]byte, error) {
	if len(masterKey) != keySize {
		return nil, fmt.Errorf("vault: master key must be %d bytes, got %d", keySize, len(masterKey))
	}

	// Marshal entries and groups to JSON plaintext
	plaintext, err := marshalPayload(ents, groups)
	if err != nil {
		return nil, fmt.Errorf("vault: marshal payload: %w", err)
	}

	// Encrypt plaintext with cached master key (fresh nonce each call)
	ciphertext, nonce, tag, err := encryptGCM(masterKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("vault: encrypt data: %w", err)
	}

	// Parse existing vault to preserve slot structure
	var existing VaultFile
	if err := json.Unmarshal(existingVaultData, &existing); err != nil {
		return nil, fmt.Errorf("vault: parse existing vault: %w", err)
	}

	// Build new vault: same Version and Slots, updated Data and Params
	vault := VaultFile{
		Version: existing.Version,
		Header: Header{
			Slots: existing.Header.Slots,
			Params: GCMParams{
				Nonce: hex.EncodeToString(nonce),
				Tag:   hex.EncodeToString(tag),
			},
		},
		Data: base64.StdEncoding.EncodeToString(ciphertext),
	}

	return json.MarshalIndent(vault, "", "  ")
}

// EncryptBytes encrypts pre-marshaled plaintext bytes with the provided master key,
// preserving slot structure from existingVaultData. This is the backup export path:
// the caller has already marshaled its custom DB struct to JSON bytes and needs them
// encrypted with the cached master key.
func EncryptBytes(plaintext, masterKey, existingVaultData []byte) ([]byte, error) {
	if len(masterKey) != keySize {
		return nil, fmt.Errorf("vault: master key must be %d bytes, got %d", keySize, len(masterKey))
	}

	// Encrypt plaintext with cached master key (fresh nonce each call)
	ciphertext, nonce, tag, err := encryptGCM(masterKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("vault: encrypt data: %w", err)
	}

	// Parse existing vault to preserve slot structure
	var existing VaultFile
	if err := json.Unmarshal(existingVaultData, &existing); err != nil {
		return nil, fmt.Errorf("vault: parse existing vault: %w", err)
	}

	// Build new vault: same Version and Slots, updated Data and Params
	vf := VaultFile{
		Version: existing.Version,
		Header: Header{
			Slots: existing.Header.Slots,
			Params: GCMParams{
				Nonce: hex.EncodeToString(nonce),
				Tag:   hex.EncodeToString(tag),
			},
		},
		Data: base64.StdEncoding.EncodeToString(ciphertext),
	}

	return json.MarshalIndent(vf, "", "  ")
}

// ChangePassword recovers the master key using oldPassword, creates a new slot
// with newPassword wrapping the same master key, and returns updated vault JSON.
// The encrypted data payload is NOT re-encrypted -- only the slot changes.
func ChangePassword(vaultData []byte, oldPassword, newPassword string) ([]byte, error) {
	if oldPassword == "" || newPassword == "" {
		return nil, ErrPasswordRequired
	}

	// Recover master key and parsed vault using old password
	masterKey, vault, err := decryptMasterKey(vaultData, oldPassword)
	if err != nil {
		return nil, err
	}

	// Create new slot with new password wrapping the same master key
	slot, err := createSlot(masterKey, newPassword)
	if err != nil {
		return nil, err
	}

	// Replace slots but keep the same data payload and params
	vault.Header.Slots = []Slot{slot}

	return json.MarshalIndent(vault, "", "  ")
}
