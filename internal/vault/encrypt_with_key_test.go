// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package vault

import (
	"encoding/json"
	"reflect"
	"testing"

	"deskotp/internal/entries"
	"deskotp/internal/totp"
)

// testEntries is a canonical set of entries for EncryptWithKey tests.
var testEntries = []totp.Entry{
	{
		UUID:   "ewk-uuid-001",
		Name:   "alice@example.com",
		Issuer: "ExampleCorp",
		Secret: "JBSWY3DPEHPK3PXP",
		Algo:   "SHA1",
		Digits: 6,
		Period: 30,
	},
}

const testPassword = "correct-horse-battery-staple"

// helperEncryptAndExtractKey creates a vault with Encrypt, then extracts the
// master key using the unexported decryptMasterKey (same package).
func helperEncryptAndExtractKey(t *testing.T, ents []totp.Entry, password string) (masterKey, vaultData []byte) {
	t.Helper()
	vaultData, err := Encrypt(ents, []entries.GroupInfo{}, password)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	masterKey, _, err = decryptMasterKey(vaultData, password)
	if err != nil {
		t.Fatalf("decryptMasterKey() error = %v", err)
	}
	return masterKey, vaultData
}

// TestEncryptWithKey_RoundTrip encrypts with password, re-encrypts with cached
// master key, then decrypts with original password -- entries must match.
func TestEncryptWithKey_RoundTrip(t *testing.T) {
	masterKey, vaultData := helperEncryptAndExtractKey(t, testEntries, testPassword)

	reEncrypted, err := EncryptWithKey(testEntries, []entries.GroupInfo{}, masterKey, vaultData)
	if err != nil {
		t.Fatalf("EncryptWithKey() error = %v", err)
	}

	got, _, err := Decrypt(reEncrypted, testPassword)
	if err != nil {
		t.Fatalf("Decrypt() after EncryptWithKey error = %v", err)
	}

	if !reflect.DeepEqual(got, testEntries) {
		t.Errorf("round-trip mismatch\ngot:  %+v\nwant: %+v", got, testEntries)
	}
}

// TestEncryptWithKey_PreservesSlots verifies that slot UUID, salt, and KDF params
// are preserved verbatim in the re-encrypted output.
func TestEncryptWithKey_PreservesSlots(t *testing.T) {
	masterKey, vaultData := helperEncryptAndExtractKey(t, testEntries, testPassword)

	reEncrypted, err := EncryptWithKey(testEntries, []entries.GroupInfo{}, masterKey, vaultData)
	if err != nil {
		t.Fatalf("EncryptWithKey() error = %v", err)
	}

	var original, updated VaultFile
	if err := json.Unmarshal(vaultData, &original); err != nil {
		t.Fatalf("unmarshal original: %v", err)
	}
	if err := json.Unmarshal(reEncrypted, &updated); err != nil {
		t.Fatalf("unmarshal updated: %v", err)
	}

	if len(updated.Header.Slots) != len(original.Header.Slots) {
		t.Fatalf("slot count changed: got %d, want %d", len(updated.Header.Slots), len(original.Header.Slots))
	}

	for i := range original.Header.Slots {
		orig := original.Header.Slots[i]
		upd := updated.Header.Slots[i]
		if upd.UUID != orig.UUID {
			t.Errorf("slot[%d] UUID changed: got %q, want %q", i, upd.UUID, orig.UUID)
		}
		if upd.Salt != orig.Salt {
			t.Errorf("slot[%d] Salt changed: got %q, want %q", i, upd.Salt, orig.Salt)
		}
		if upd.N != orig.N || upd.R != orig.R || upd.P != orig.P {
			t.Errorf("slot[%d] KDF params changed: got N=%d,R=%d,P=%d want N=%d,R=%d,P=%d",
				i, upd.N, upd.R, upd.P, orig.N, orig.R, orig.P)
		}
		if upd.Key != orig.Key {
			t.Errorf("slot[%d] Key changed", i)
		}
		if !reflect.DeepEqual(upd.KeyParams, orig.KeyParams) {
			t.Errorf("slot[%d] KeyParams changed", i)
		}
	}
}

// TestEncryptWithKey_FreshNonce verifies that two calls produce different Data
// fields (different nonces mean different ciphertext).
func TestEncryptWithKey_FreshNonce(t *testing.T) {
	masterKey, vaultData := helperEncryptAndExtractKey(t, testEntries, testPassword)

	enc1, err := EncryptWithKey(testEntries, []entries.GroupInfo{}, masterKey, vaultData)
	if err != nil {
		t.Fatalf("EncryptWithKey() #1 error = %v", err)
	}
	enc2, err := EncryptWithKey(testEntries, []entries.GroupInfo{}, masterKey, vaultData)
	if err != nil {
		t.Fatalf("EncryptWithKey() #2 error = %v", err)
	}

	var v1, v2 VaultFile
	json.Unmarshal(enc1, &v1)
	json.Unmarshal(enc2, &v2)

	if v1.Data == v2.Data {
		t.Error("two EncryptWithKey calls produced identical Data (nonce reuse)")
	}
	if v1.Header.Params.Nonce == v2.Header.Params.Nonce {
		t.Error("two EncryptWithKey calls produced identical nonce")
	}
}

// TestEncryptWithKey_NilMasterKey returns error when master key is nil or empty.
func TestEncryptWithKey_NilMasterKey(t *testing.T) {
	_, vaultData := helperEncryptAndExtractKey(t, testEntries, testPassword)

	emptyGroups := []entries.GroupInfo{}
	if _, err := EncryptWithKey(testEntries, emptyGroups, nil, vaultData); err == nil {
		t.Error("EncryptWithKey(nil key) should return error")
	}
	if _, err := EncryptWithKey(testEntries, emptyGroups, []byte{}, vaultData); err == nil {
		t.Error("EncryptWithKey(empty key) should return error")
	}
}

// TestEncryptWithKey_MalformedVault returns error for bad existingVaultData.
func TestEncryptWithKey_MalformedVault(t *testing.T) {
	masterKey := make([]byte, 32) // zeroed key, doesn't matter for this test
	emptyGroups := []entries.GroupInfo{}

	if _, err := EncryptWithKey(testEntries, emptyGroups, masterKey, []byte("not json")); err == nil {
		t.Error("EncryptWithKey(malformed vault) should return error")
	}
	if _, err := EncryptWithKey(testEntries, emptyGroups, masterKey, nil); err == nil {
		t.Error("EncryptWithKey(nil vault) should return error")
	}
}

func TestEncryptWithKey_RoundTrip_WithGroups(t *testing.T) {
	groups := []entries.GroupInfo{{Name: "Finance"}, {Name: "Social"}}
	masterKey, vaultData := helperEncryptAndExtractKey(t, testEntries, testPassword)
	reEncrypted, err := EncryptWithKey(testEntries, groups, masterKey, vaultData)
	if err != nil {
		t.Fatalf("EncryptWithKey() error = %v", err)
	}
	gotEntries, gotGroups, err := Decrypt(reEncrypted, testPassword)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !reflect.DeepEqual(gotEntries, testEntries) {
		t.Errorf("entries mismatch")
	}
	if len(gotGroups) != 2 || gotGroups[0].Name != "Finance" || gotGroups[1].Name != "Social" {
		t.Errorf("groups mismatch: got %v", gotGroups)
	}
}
