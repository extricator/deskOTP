// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

import (
	"reflect"
	"strings"
	"testing"

	"deskotp/internal/entries"
	"deskotp/internal/storage"
	"deskotp/internal/totp"
	"deskotp/internal/vault"
)

// testEntry is the canonical test entry for vault tests.
var testEntry = totp.Entry{
	UUID:   "vault-test-001",
	Name:   "alice@example.com",
	Issuer: "VaultCorp",
	Secret: "JBSWY3DPEHPK3PXP",
	Algo:   "SHA1",
	Digits: 6,
	Period: 30,
}

// --- Task 1 Tests: saveEntries helper and vault-aware startup ---

// TestSaveEntriesPlain verifies that when vault_enabled is not set,
// saveEntries writes plain JSON that storage.Load can read.
func TestSaveEntriesPlain(t *testing.T) {
	app := setupTestApp(t)

	ents := []totp.Entry{testEntry}
	if err := app.saveEntries(ents, []entries.GroupInfo{}); err != nil {
		t.Fatalf("saveEntries() error = %v", err)
	}

	got, _, err := storage.Load()
	if err != nil {
		t.Fatalf("storage.Load() error = %v", err)
	}

	if !reflect.DeepEqual(got, ents) {
		t.Errorf("saveEntries() plain mismatch\ngot:  %+v\nwant: %+v", got, ents)
	}
}

// TestSaveEntriesEncrypted verifies that when vault is active (vault_enabled=true,
// keyCache unlocked, vaultData cached), saveEntries writes encrypted bytes that
// vault.Decrypt can read.
func TestSaveEntriesEncrypted(t *testing.T) {
	app := setupTestApp(t)

	ents := []totp.Entry{testEntry}
	password := "test-password-123"

	// Set up vault state: encrypt entries, cache key, set flag
	vaultBytes, err := vault.Encrypt(ents, []entries.GroupInfo{}, password)
	if err != nil {
		t.Fatalf("vault.Encrypt() error = %v", err)
	}
	masterKey, err := vault.DecryptKey(vaultBytes, password)
	if err != nil {
		t.Fatalf("vault.DecryptKey() error = %v", err)
	}

	app.keyCache.Unlock(masterKey)
	app.vaultCtrl.SetVaultData(vaultBytes)
	if err := app.settings.Set("vault_enabled", "true"); err != nil {
		t.Fatalf("settings.Set() error = %v", err)
	}

	// Save via saveEntries
	if err := app.saveEntries(ents, []entries.GroupInfo{}); err != nil {
		t.Fatalf("saveEntries() error = %v", err)
	}

	// Verify: read raw and decrypt
	raw, err := storage.LoadRaw()
	if err != nil {
		t.Fatalf("storage.LoadRaw() error = %v", err)
	}

	got, _, err := vault.Decrypt(raw, password)
	if err != nil {
		t.Fatalf("vault.Decrypt() error = %v", err)
	}

	if !reflect.DeepEqual(got, ents) {
		t.Errorf("saveEntries() encrypted mismatch\ngot:  %+v\nwant: %+v", got, ents)
	}
}

// TestSaveEntriesLockedVault verifies that when vault_enabled=true but keyCache
// is locked, saveEntries returns an error (never silently falls back to plain JSON).
func TestSaveEntriesLockedVault(t *testing.T) {
	app := setupTestApp(t)

	if err := app.settings.Set("vault_enabled", "true"); err != nil {
		t.Fatalf("settings.Set() error = %v", err)
	}
	// keyCache is locked (default state)

	err := app.saveEntries([]totp.Entry{testEntry}, []entries.GroupInfo{})
	if err == nil {
		t.Fatal("saveEntries() with locked vault should return error, got nil")
	}
}

// TestStartupPlain verifies that when vault_enabled is not set,
// startup loads entries normally.
func TestStartupPlain(t *testing.T) {
	app := setupTestApp(t)

	// Pre-save some entries
	ents := []totp.Entry{testEntry}
	if err := storage.Save(ents, []entries.GroupInfo{}); err != nil {
		t.Fatalf("storage.Save() error = %v", err)
	}

	// Simulate startup (without full Wails context)
	if app.settings.Get("vault_enabled") == "true" {
		app.entryMgr.Set([]totp.Entry{})
	} else {
		loaded, _, err := storage.Load()
		if err != nil {
			t.Fatalf("storage.Load() error = %v", err)
		}
		app.entryMgr.Set(loaded)
	}

	snap := app.entryMgr.Snapshot()
	if !reflect.DeepEqual(snap, ents) {
		t.Errorf("startup plain entries mismatch\ngot:  %+v\nwant: %+v", snap, ents)
	}
}

// TestStartupEncrypted verifies that when vault_enabled=true,
// startup sets entries to empty slice (waits for UnlockVault).
func TestStartupEncrypted(t *testing.T) {
	app := setupTestApp(t)

	if err := app.settings.Set("vault_enabled", "true"); err != nil {
		t.Fatalf("settings.Set() error = %v", err)
	}

	// Simulate startup
	if app.settings.Get("vault_enabled") == "true" {
		app.entryMgr.Set([]totp.Entry{})
	} else {
		loaded, _, err := storage.Load()
		if err != nil {
			t.Fatalf("storage.Load() error = %v", err)
		}
		app.entryMgr.Set(loaded)
	}

	snap := app.entryMgr.Snapshot()
	if len(snap) != 0 {
		t.Errorf("startup with vault_enabled should set empty entries, got %d", len(snap))
	}
}

// --- Task 2 Tests: Wails-bound vault lifecycle methods ---

// TestSetPassword verifies that SetPassword creates an encrypted vault from plain
// entries, sets vault_enabled=true, caches the master key, and entries remain accessible.
func TestSetPassword(t *testing.T) {
	app := setupTestApp(t)
	password := "my-vault-password"

	// Pre-populate with plain entries
	app.entryMgr.Set([]totp.Entry{testEntry})
	if err := storage.Save([]totp.Entry{testEntry}, []entries.GroupInfo{}); err != nil {
		t.Fatalf("storage.Save() error = %v", err)
	}

	if err := app.SetPassword(password); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}

	// Verify vault_enabled is set
	if app.settings.Get("vault_enabled") != "true" {
		t.Error("vault_enabled should be 'true' after SetPassword")
	}

	// Verify keyCache is unlocked
	if !app.keyCache.IsUnlocked() {
		t.Error("keyCache should be unlocked after SetPassword")
	}

	// Verify entries are still accessible via entryMgr
	snap := app.entryMgr.Snapshot()
	if len(snap) != 1 || snap[0].UUID != testEntry.UUID {
		t.Errorf("entries should be preserved after SetPassword, got %+v", snap)
	}

	// Verify the file on disk is encrypted and can be decrypted
	raw, err := storage.LoadRaw()
	if err != nil {
		t.Fatalf("storage.LoadRaw() error = %v", err)
	}
	got, _, err := vault.Decrypt(raw, password)
	if err != nil {
		t.Fatalf("vault.Decrypt() error = %v", err)
	}
	if !reflect.DeepEqual(got, []totp.Entry{testEntry}) {
		t.Errorf("decrypted entries mismatch\ngot:  %+v\nwant: %+v", got, []totp.Entry{testEntry})
	}
}

// TestUnlockVaultCorrect verifies that UnlockVault with the correct password
// decrypts the vault, caches the key, and loads entries into the manager.
func TestUnlockVaultCorrect(t *testing.T) {
	app := setupTestApp(t)
	password := "unlock-test-pw"

	// Create an encrypted vault on disk
	ents := []totp.Entry{testEntry}
	vaultBytes, err := vault.Encrypt(ents, []entries.GroupInfo{}, password)
	if err != nil {
		t.Fatalf("vault.Encrypt() error = %v", err)
	}
	if err := storage.SaveRaw(vaultBytes); err != nil {
		t.Fatalf("storage.SaveRaw() error = %v", err)
	}
	if err := app.settings.Set("vault_enabled", "true"); err != nil {
		t.Fatalf("settings.Set() error = %v", err)
	}

	// Unlock
	if err := app.UnlockVault(password); err != nil {
		t.Fatalf("UnlockVault() error = %v", err)
	}

	// Verify keyCache unlocked
	if !app.keyCache.IsUnlocked() {
		t.Error("keyCache should be unlocked after UnlockVault")
	}

	// Verify entries loaded
	gotEntries := app.entryMgr.Snapshot()
	if !reflect.DeepEqual(gotEntries, ents) {
		t.Errorf("entries after UnlockVault mismatch\ngot:  %+v\nwant: %+v", gotEntries, ents)
	}
}

// TestUnlockVaultWrongPassword verifies that UnlockVault with the wrong password
// returns an error containing "incorrect password" and entries remain empty.
func TestUnlockVaultWrongPassword(t *testing.T) {
	app := setupTestApp(t)

	// Create encrypted vault
	ents := []totp.Entry{testEntry}
	vaultBytes, err := vault.Encrypt(ents, []entries.GroupInfo{}, "correct-password")
	if err != nil {
		t.Fatalf("vault.Encrypt() error = %v", err)
	}
	if err := storage.SaveRaw(vaultBytes); err != nil {
		t.Fatalf("storage.SaveRaw() error = %v", err)
	}
	if err := app.settings.Set("vault_enabled", "true"); err != nil {
		t.Fatalf("settings.Set() error = %v", err)
	}

	// Try wrong password
	err = app.UnlockVault("wrong-password")
	if err == nil {
		t.Fatal("UnlockVault() with wrong password should return error")
	}
	if !strings.Contains(err.Error(), "incorrect password") {
		t.Errorf("error should contain 'incorrect password', got: %v", err)
	}

	// Entries should remain empty
	if snap := app.entryMgr.Snapshot(); len(snap) != 0 {
		t.Errorf("entries should be empty after wrong password, got %d", len(snap))
	}
}

// TestChangeVaultPassword verifies that after changing the password, the old
// password fails and the new password succeeds for UnlockVault.
func TestChangeVaultPassword(t *testing.T) {
	app := setupTestApp(t)
	oldPw := "old-password"
	newPw := "new-password"

	// Set up vault
	ents := []totp.Entry{testEntry}
	app.entryMgr.Set(ents)
	if err := storage.Save(ents, []entries.GroupInfo{}); err != nil {
		t.Fatalf("storage.Save() error = %v", err)
	}
	if err := app.SetPassword(oldPw); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}

	// Change password
	if err := app.ChangeVaultPassword(oldPw, newPw); err != nil {
		t.Fatalf("ChangeVaultPassword() error = %v", err)
	}

	// Lock and try old password
	app.keyCache.Lock()
	app.entryMgr.Clear()

	err := app.UnlockVault(oldPw)
	if err == nil {
		t.Error("UnlockVault with old password should fail after ChangeVaultPassword")
	}

	// Try new password
	if err := app.UnlockVault(newPw); err != nil {
		t.Fatalf("UnlockVault with new password should succeed, got: %v", err)
	}

	gotEntries := app.entryMgr.Snapshot()
	if !reflect.DeepEqual(gotEntries, ents) {
		t.Errorf("entries after unlock with new password mismatch\ngot:  %+v\nwant: %+v", gotEntries, ents)
	}
}

// TestRemovePassword verifies that RemovePassword decrypts the vault back to
// plain JSON, clears vault_enabled, and locks the keyCache.
func TestRemovePassword(t *testing.T) {
	app := setupTestApp(t)
	password := "remove-test-pw"

	// Set up vault
	ents := []totp.Entry{testEntry}
	app.entryMgr.Set(ents)
	if err := storage.Save(ents, []entries.GroupInfo{}); err != nil {
		t.Fatalf("storage.Save() error = %v", err)
	}
	if err := app.SetPassword(password); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}

	// Remove password
	if err := app.RemovePassword(password); err != nil {
		t.Fatalf("RemovePassword() error = %v", err)
	}

	// Verify vault_enabled cleared
	if app.settings.Get("vault_enabled") == "true" {
		t.Error("vault_enabled should not be 'true' after RemovePassword")
	}

	// Verify keyCache locked
	if app.keyCache.IsUnlocked() {
		t.Error("keyCache should be locked after RemovePassword")
	}

	// Verify plain JSON on disk
	got, _, err := storage.Load()
	if err != nil {
		t.Fatalf("storage.Load() should work after RemovePassword, got error: %v", err)
	}
	if !reflect.DeepEqual(got, ents) {
		t.Errorf("plain entries mismatch after RemovePassword\ngot:  %+v\nwant: %+v", got, ents)
	}
}

// TestGetVaultStatus verifies that GetVaultStatus returns the correct
// enabled/unlocked state in each scenario.
func TestGetVaultStatus(t *testing.T) {
	app := setupTestApp(t)

	// Initial: not enabled, not unlocked
	status := app.GetVaultStatus()
	if status.Enabled || status.Unlocked {
		t.Errorf("initial status: want {false, false}, got %+v", status)
	}

	// Set password: enabled and unlocked
	app.entryMgr.Set([]totp.Entry{testEntry})
	if err := storage.Save([]totp.Entry{testEntry}, []entries.GroupInfo{}); err != nil {
		t.Fatalf("storage.Save() error = %v", err)
	}
	if err := app.SetPassword("status-test-pw"); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}

	status = app.GetVaultStatus()
	if !status.Enabled || !status.Unlocked {
		t.Errorf("after SetPassword: want {true, true}, got %+v", status)
	}

	// Lock: enabled but not unlocked
	app.keyCache.Lock()
	status = app.GetVaultStatus()
	if !status.Enabled || status.Unlocked {
		t.Errorf("after Lock: want {true, false}, got %+v", status)
	}
}

// TestVaultLifecycle tests the full lifecycle: set password -> save entries via
// saveEntries -> lock -> unlock -> entries match.
func TestVaultLifecycle(t *testing.T) {
	app := setupTestApp(t)
	password := "lifecycle-pw"

	// Start with plain entries
	ents := []totp.Entry{testEntry}
	app.entryMgr.Set(ents)
	if err := storage.Save(ents, []entries.GroupInfo{}); err != nil {
		t.Fatalf("storage.Save() error = %v", err)
	}

	// Step 1: Set password
	if err := app.SetPassword(password); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}

	// Step 2: Save entries via saveEntries (simulates adding a new account)
	newEntry := totp.Entry{
		UUID:   "vault-test-002",
		Name:   "bob@example.com",
		Issuer: "BobCorp",
		Secret: "JBSWY3DPEHPK3PXP",
		Algo:   "SHA1",
		Digits: 6,
		Period: 30,
	}
	updatedEntries := append(ents, newEntry)
	app.entryMgr.Set(updatedEntries)
	if err := app.saveEntries(updatedEntries, []entries.GroupInfo{}); err != nil {
		t.Fatalf("saveEntries() error = %v", err)
	}

	// Step 3: Lock (simulate app restart)
	app.keyCache.Lock()
	app.entryMgr.Clear()

	// Step 4: Unlock
	if err := app.UnlockVault(password); err != nil {
		t.Fatalf("UnlockVault() error = %v", err)
	}

	// Step 5: Verify entries match (should have both entries)
	got := app.entryMgr.Snapshot()

	if len(got) != 2 {
		t.Fatalf("expected 2 entries after lifecycle, got %d", len(got))
	}
	if !reflect.DeepEqual(got, updatedEntries) {
		t.Errorf("lifecycle entries mismatch\ngot:  %+v\nwant: %+v", got, updatedEntries)
	}
}
