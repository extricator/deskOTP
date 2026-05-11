// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package vault

import (
	"encoding/json"
	"errors"
	"testing"

	"deskotp/internal/entries"
	"deskotp/internal/totp"
)

func sampleEntries() []totp.Entry {
	return []totp.Entry{
		{
			UUID:   "uuid-1",
			Name:   "alice@example.com",
			Issuer: "GitHub",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
		},
		{
			UUID:    "uuid-2",
			Name:    "bob@example.com",
			Issuer:  "Google",
			Secret:  "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
			Algo:    "SHA256",
			Digits:  8,
			Period:  60,
			Type:    "totp",
			Counter: 0,
		},
		{
			UUID:    "uuid-3",
			Name:    "carol@example.com",
			Issuer:  "Steam",
			Secret:  "ABCDEFGHIJKLMNOP",
			Algo:    "SHA1",
			Digits:  5,
			Period:  30,
			Type:    "steam",
			Counter: 0,
		},
	}
}

func TestRoundTrip(t *testing.T) {
	ents := sampleEntries()
	encrypted, err := Encrypt(ents, []entries.GroupInfo{}, "test123")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, _, err := Decrypt(encrypted, "test123")
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if len(decrypted) != len(ents) {
		t.Fatalf("got %d entries, want %d", len(decrypted), len(ents))
	}

	for i, got := range decrypted {
		want := ents[i]
		if got.UUID != want.UUID {
			t.Errorf("entry %d UUID: got %q, want %q", i, got.UUID, want.UUID)
		}
		if got.Name != want.Name {
			t.Errorf("entry %d Name: got %q, want %q", i, got.Name, want.Name)
		}
		if got.Issuer != want.Issuer {
			t.Errorf("entry %d Issuer: got %q, want %q", i, got.Issuer, want.Issuer)
		}
		if got.Secret != want.Secret {
			t.Errorf("entry %d Secret: got %q, want %q", i, got.Secret, want.Secret)
		}
		if got.Algo != want.Algo {
			t.Errorf("entry %d Algo: got %q, want %q", i, got.Algo, want.Algo)
		}
		if got.Digits != want.Digits {
			t.Errorf("entry %d Digits: got %d, want %d", i, got.Digits, want.Digits)
		}
		if got.Period != want.Period {
			t.Errorf("entry %d Period: got %d, want %d", i, got.Period, want.Period)
		}
		if got.Type != want.Type {
			t.Errorf("entry %d Type: got %q, want %q", i, got.Type, want.Type)
		}
	}
}

func TestRoundTripEmptyEntries(t *testing.T) {
	encrypted, err := Encrypt([]totp.Entry{}, []entries.GroupInfo{}, "test123")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, _, err := Decrypt(encrypted, "test123")
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if decrypted == nil {
		t.Fatal("Decrypt returned nil, want empty slice")
	}
	if len(decrypted) != 0 {
		t.Fatalf("got %d entries, want 0", len(decrypted))
	}
}

func TestWrongPassword(t *testing.T) {
	ents := sampleEntries()
	encrypted, err := Encrypt(ents, []entries.GroupInfo{}, "correct")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, _, err = Decrypt(encrypted, "wrong")
	if !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("got error %v, want ErrWrongPassword", err)
	}
}

func TestEmptyPassword(t *testing.T) {
	ents := sampleEntries()

	_, err := Encrypt(ents, []entries.GroupInfo{}, "")
	if !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("Encrypt with empty password: got %v, want ErrPasswordRequired", err)
	}

	// Create a valid vault first to test decrypt with empty password
	encrypted, err := Encrypt(ents, []entries.GroupInfo{}, "test123")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, _, err = Decrypt(encrypted, "")
	if !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("Decrypt with empty password: got %v, want ErrPasswordRequired", err)
	}
}

func TestHeaderFormat(t *testing.T) {
	ents := sampleEntries()
	encrypted, err := Encrypt(ents, []entries.GroupInfo{}, "test123")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	var vault VaultFile
	if err := json.Unmarshal(encrypted, &vault); err != nil {
		t.Fatalf("Unmarshal VaultFile failed: %v", err)
	}

	if vault.Version != 1 {
		t.Errorf("Version: got %d, want 1", vault.Version)
	}
	if len(vault.Header.Slots) != 1 {
		t.Fatalf("Slots count: got %d, want 1", len(vault.Header.Slots))
	}

	slot := vault.Header.Slots[0]
	if slot.UUID == "" {
		t.Error("Slot UUID is empty")
	}
	if slot.N == 0 {
		t.Error("Slot N is 0")
	}
	if slot.R == 0 {
		t.Error("Slot R is 0")
	}
	if slot.P == 0 {
		t.Error("Slot P is 0")
	}
	if slot.Salt == "" {
		t.Error("Slot Salt is empty")
	}
	if vault.Header.Params.Nonce == "" {
		t.Error("Header Params Nonce is empty")
	}
	if vault.Header.Params.Tag == "" {
		t.Error("Header Params Tag is empty")
	}
	if slot.Type != 1 {
		t.Errorf("Slot Type: got %d, want 1", slot.Type)
	}
}

func TestKDFParamsStored(t *testing.T) {
	ents := sampleEntries()
	encrypted, err := Encrypt(ents, []entries.GroupInfo{}, "test123")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	var vault VaultFile
	if err := json.Unmarshal(encrypted, &vault); err != nil {
		t.Fatalf("Unmarshal VaultFile failed: %v", err)
	}

	slot := vault.Header.Slots[0]
	if slot.N != 32768 {
		t.Errorf("Slot N: got %d, want 32768", slot.N)
	}
	if slot.R != 8 {
		t.Errorf("Slot R: got %d, want 8", slot.R)
	}
	if slot.P != 1 {
		t.Errorf("Slot P: got %d, want 1", slot.P)
	}
}

func TestChangePassword(t *testing.T) {
	ents := sampleEntries()
	encrypted, err := Encrypt(ents, []entries.GroupInfo{}, "old")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	changed, err := ChangePassword(encrypted, "old", "new")
	if err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	// Decrypt with new password should succeed
	decrypted, _, err := Decrypt(changed, "new")
	if err != nil {
		t.Fatalf("Decrypt with new password failed: %v", err)
	}

	if len(decrypted) != len(ents) {
		t.Fatalf("got %d entries, want %d", len(decrypted), len(ents))
	}
	for i, got := range decrypted {
		want := ents[i]
		if got.UUID != want.UUID || got.Name != want.Name || got.Secret != want.Secret {
			t.Errorf("entry %d mismatch after password change", i)
		}
	}

	// Decrypt with old password should fail
	_, _, err = Decrypt(changed, "old")
	if !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Decrypt with old password: got %v, want ErrWrongPassword", err)
	}
}

func TestChangePasswordWrongOld(t *testing.T) {
	ents := sampleEntries()
	encrypted, err := Encrypt(ents, []entries.GroupInfo{}, "correct")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = ChangePassword(encrypted, "wrongold", "new")
	if !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("ChangePassword with wrong old password: got %v, want ErrWrongPassword", err)
	}
}

func TestFreshNoncePerEncrypt(t *testing.T) {
	ents := sampleEntries()

	encrypted1, err := Encrypt(ents, []entries.GroupInfo{}, "test123")
	if err != nil {
		t.Fatalf("Encrypt 1 failed: %v", err)
	}

	encrypted2, err := Encrypt(ents, []entries.GroupInfo{}, "test123")
	if err != nil {
		t.Fatalf("Encrypt 2 failed: %v", err)
	}

	var vault1, vault2 VaultFile
	if err := json.Unmarshal(encrypted1, &vault1); err != nil {
		t.Fatalf("Unmarshal 1 failed: %v", err)
	}
	if err := json.Unmarshal(encrypted2, &vault2); err != nil {
		t.Fatalf("Unmarshal 2 failed: %v", err)
	}

	if vault1.Header.Params.Nonce == vault2.Header.Params.Nonce {
		t.Error("Two encryptions produced the same data nonce -- nonces must be unique")
	}
}

func TestRoundTrip_WithGroups(t *testing.T) {
	ents := sampleEntries()
	groups := []entries.GroupInfo{{Name: "Work"}, {Name: "Personal"}}
	encrypted, err := Encrypt(ents, groups, "test123")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	decEntries, decGroups, err := Decrypt(encrypted, "test123")
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if len(decEntries) != len(ents) {
		t.Fatalf("got %d entries, want %d", len(decEntries), len(ents))
	}
	if len(decGroups) != 2 || decGroups[0].Name != "Work" || decGroups[1].Name != "Personal" {
		t.Errorf("groups mismatch: got %v, want [{Work} {Personal}]", decGroups)
	}
}

func TestDecrypt_OldFormat_BackwardCompat(t *testing.T) {
	// Simulate old vault: encrypt entries WITHOUT groups using raw crypto
	// to produce a bare JSON array as plaintext (the old format).
	ents := sampleEntries()
	plaintext, err := json.Marshal(ents) // bare array, not vaultPayload
	if err != nil {
		t.Fatalf("marshal entries: %v", err)
	}
	// Use Encrypt to create a vault, then re-encrypt with the bare array plaintext
	// via EncryptBytes (which takes raw plaintext, preserving the old format).
	masterKey, vaultData := helperEncryptAndExtractKey(t, ents, "test123")
	oldFormatVault, err := EncryptBytes(plaintext, masterKey, vaultData)
	if err != nil {
		t.Fatalf("EncryptBytes failed: %v", err)
	}
	// Decrypt with new Decrypt function -- should handle old format gracefully
	decEntries, decGroups, err := Decrypt(oldFormatVault, "test123")
	if err != nil {
		t.Fatalf("Decrypt old format failed: %v", err)
	}
	if len(decEntries) != len(ents) {
		t.Fatalf("got %d entries, want %d", len(decEntries), len(ents))
	}
	// Old format should return empty groups, not nil
	if decGroups == nil {
		t.Fatal("groups is nil, want empty slice")
	}
	if len(decGroups) != 0 {
		t.Errorf("groups = %v, want empty []GroupInfo for old format", decGroups)
	}
}

// TestDecryptLegacyStringGroups verifies that vaults with old []string groups
// ("groups":["Work","Personal"]) are migrated to []GroupInfo with empty icons.
func TestDecryptLegacyStringGroups(t *testing.T) {
	// Build a raw vault payload with old-style string groups
	type legacyPayload struct {
		Entries []totp.Entry `json:"entries"`
		Groups  []string     `json:"groups"`
	}
	payload := legacyPayload{
		Entries: sampleEntries(),
		Groups:  []string{"Work", "Personal"},
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal legacy payload: %v", err)
	}

	// Encrypt using the raw bytes path to preserve the []string format
	masterKey, vaultData := helperEncryptAndExtractKey(t, sampleEntries(), "test123")
	legacyVault, err := EncryptBytes(plaintext, masterKey, vaultData)
	if err != nil {
		t.Fatalf("EncryptBytes failed: %v", err)
	}

	// Decrypt — the migration should transparently convert []string -> []GroupInfo
	_, decGroups, err := Decrypt(legacyVault, "test123")
	if err != nil {
		t.Fatalf("Decrypt legacy string groups failed: %v", err)
	}

	if len(decGroups) != 2 {
		t.Fatalf("len(decGroups) = %d, want 2", len(decGroups))
	}
	if decGroups[0].Name != "Work" || decGroups[0].Icon != "" {
		t.Errorf("decGroups[0] = %+v, want {Name:Work, Icon:}", decGroups[0])
	}
	if decGroups[1].Name != "Personal" || decGroups[1].Icon != "" {
		t.Errorf("decGroups[1] = %+v, want {Name:Personal, Icon:}", decGroups[1])
	}
}

// TestDecryptNewGroupInfoFormat verifies that vaults with new []GroupInfo groups
// preserve icon slugs through encrypt/decrypt.
func TestDecryptNewGroupInfoFormat(t *testing.T) {
	ents := sampleEntries()
	groups := []entries.GroupInfo{{Name: "Work", Icon: "briefcase"}}

	encrypted, err := Encrypt(ents, groups, "test123")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, decGroups, err := Decrypt(encrypted, "test123")
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if len(decGroups) != 1 {
		t.Fatalf("len(decGroups) = %d, want 1", len(decGroups))
	}
	if decGroups[0].Name != "Work" {
		t.Errorf("decGroups[0].Name = %q, want %q", decGroups[0].Name, "Work")
	}
	if decGroups[0].Icon != "briefcase" {
		t.Errorf("decGroups[0].Icon = %q, want %q", decGroups[0].Icon, "briefcase")
	}
}
