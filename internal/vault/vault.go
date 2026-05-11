// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/scrypt"
)

// Sentinel errors for the vault package.
//
// ErrWrongPassword and ErrPasswordRequired intentionally duplicate the
// identically-named sentinels in the parser package. Vault sentinels scope to
// master-password operations (unlock, password change), while parser sentinels
// scope to import-file decryption. Keeping them separate avoids a cross-package
// dependency between vault and parser.
var (
	ErrWrongPassword    = errors.New("vault: incorrect password")
	ErrPasswordRequired = errors.New("vault: password required")
	ErrVaultLocked      = errors.New("vault: vault is locked")
)

// Internal crypto constants.
const (
	defaultN = 32768 // scrypt cost parameter (2^15)
	defaultR = 8     // scrypt block size
	defaultP = 1     // scrypt parallelisation
	saltSize = 32    // bytes
	keySize  = 32    // AES-256
)

// VaultFile is the top-level JSON structure of an encrypted vault.
type VaultFile struct {
	Version int    `json:"version"`
	Header  Header `json:"header"`
	Data    string `json:"data"` // base64-encoded AES-GCM ciphertext
}

// Header contains the encryption metadata.
type Header struct {
	Slots  []Slot    `json:"slots"`
	Params GCMParams `json:"params"` // nonce + tag for data ciphertext
}

// Slot holds a password-encrypted copy of the master key.
type Slot struct {
	UUID      string    `json:"uuid"`
	Type      int       `json:"type"`       // 1 = password
	Key       string    `json:"key"`        // hex: AES-GCM encrypted master key
	KeyParams GCMParams `json:"key_params"` // nonce + tag for slot key decryption
	N         int       `json:"n"`          // scrypt cost parameter
	R         int       `json:"r"`          // scrypt block size parameter
	P         int       `json:"p"`          // scrypt parallelisation parameter
	Salt      string    `json:"salt"`       // hex: 32-byte scrypt salt
}

// GCMParams holds the nonce and authentication tag for an AES-GCM operation.
type GCMParams struct {
	Nonce string `json:"nonce"` // hex: 12-byte GCM nonce
	Tag   string `json:"tag"`   // hex: 16-byte GCM auth tag
}

// encryptGCM encrypts plaintext with AES-256-GCM, returning ciphertext, nonce,
// and tag as separate byte slices. Mirrors the pattern in aegis_encrypted.go.
func encryptGCM(key, plaintext []byte) (ciphertext, nonce, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vault: create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vault: create GCM: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("vault: generate nonce: %w", err)
	}

	// Seal appends tag to ciphertext: result = ciphertext || tag (16 bytes)
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	tagOffset := len(sealed) - gcm.Overhead() // gcm.Overhead() == 16
	return sealed[:tagOffset], nonce, sealed[tagOffset:], nil
}

// decryptGCM decrypts ciphertext with AES-256-GCM using the provided nonce and tag.
// Mirrors the pattern in aegis_encrypted.go.
func decryptGCM(key, ciphertext, nonce, tag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vault: create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: create GCM: %w", err)
	}
	// GCM expects ciphertext || tag as a single input slice
	plaintext, err := gcm.Open(nil, nonce, append(ciphertext, tag...), nil)
	// Return the raw GCM error without a "vault:" prefix. Callers (UnlockVault,
	// ChangeVaultPassword) add their own context and use errors.Is against
	// specific sentinels to distinguish wrong-password from corruption. Wrapping
	// here would defeat those sentinel checks.
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// createSlot generates a password slot that encrypts the master key.
// It derives a slot key from the password via scrypt, then encrypts the master key
// with AES-256-GCM using that slot key.
func createSlot(masterKey []byte, password string) (Slot, error) {
	// Generate random salt
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return Slot{}, fmt.Errorf("vault: generate salt: %w", err)
	}

	// Derive slot key via scrypt
	slotKey, err := scrypt.Key([]byte(password), salt, defaultN, defaultR, defaultP, keySize)
	if err != nil {
		return Slot{}, fmt.Errorf("vault: scrypt key derivation: %w", err)
	}

	// Encrypt master key with slot key
	encKey, nonce, tag, err := encryptGCM(slotKey, masterKey)
	if err != nil {
		return Slot{}, fmt.Errorf("vault: encrypt master key: %w", err)
	}

	return Slot{
		UUID: uuid.New().String(),
		Type: 1, // password slot
		Key:  hex.EncodeToString(encKey),
		KeyParams: GCMParams{
			Nonce: hex.EncodeToString(nonce),
			Tag:   hex.EncodeToString(tag),
		},
		N:    defaultN,
		R:    defaultR,
		P:    defaultP,
		Salt: hex.EncodeToString(salt),
	}, nil
}
