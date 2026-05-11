// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package vault

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// TestEncryptBytes_RoundTrip verifies that EncryptBytes encrypts plaintext that
// can be recovered via DecryptKey + decryptGCM.
func TestEncryptBytes_RoundTrip(t *testing.T) {
	// Create a vault to get masterKey + existingVaultData
	masterKey, vaultData := helperEncryptAndExtractKey(t, testEntries, testPassword)

	plaintext := []byte(`{"version":1,"entries":[{"type":"totp","uuid":"abc"}]}`)

	encrypted, err := EncryptBytes(plaintext, masterKey, vaultData)
	if err != nil {
		t.Fatalf("EncryptBytes() error = %v", err)
	}

	// Recover the master key from the encrypted output via password
	recoveredKey, err := DecryptKey(encrypted, testPassword)
	if err != nil {
		t.Fatalf("DecryptKey() error = %v", err)
	}

	// Decrypt the data payload using recovered key
	var vf VaultFile
	if err := json.Unmarshal(encrypted, &vf); err != nil {
		t.Fatalf("unmarshal encrypted: %v", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(vf.Data)
	if err != nil {
		t.Fatalf("decode base64 data: %v", err)
	}
	nonce, err := hex.DecodeString(vf.Header.Params.Nonce)
	if err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	tag, err := hex.DecodeString(vf.Header.Params.Tag)
	if err != nil {
		t.Fatalf("decode tag: %v", err)
	}

	recovered, err := decryptGCM(recoveredKey, ciphertext, nonce, tag)
	if err != nil {
		t.Fatalf("decryptGCM() error = %v", err)
	}

	if string(recovered) != string(plaintext) {
		t.Errorf("round-trip mismatch\ngot:  %q\nwant: %q", recovered, plaintext)
	}
}

// TestEncryptBytes_InvalidKeyLength verifies that EncryptBytes returns an error
// for a master key that is not keySize (32) bytes.
func TestEncryptBytes_InvalidKeyLength(t *testing.T) {
	_, vaultData := helperEncryptAndExtractKey(t, testEntries, testPassword)

	plaintext := []byte("test plaintext")

	// Short key
	if _, err := EncryptBytes(plaintext, []byte("short"), vaultData); err == nil {
		t.Error("EncryptBytes with short key should return error")
	}

	// Empty key
	if _, err := EncryptBytes(plaintext, []byte{}, vaultData); err == nil {
		t.Error("EncryptBytes with empty key should return error")
	}

	// Nil key
	if _, err := EncryptBytes(plaintext, nil, vaultData); err == nil {
		t.Error("EncryptBytes with nil key should return error")
	}
}
