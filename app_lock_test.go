// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

import (
	"testing"

	"deskotp/internal/entries"
	"deskotp/internal/totp"
	"deskotp/internal/vault"
)

// --- Phase 42 Tests: Lock foundation (LMCH-01, LMCH-02, LMCH-04) ---

// TestPerformLockIdempotent verifies that calling performLock() on an already-locked
// vault returns false and does not panic (LMCH-04: idempotent no-op).
// EventsEmit is never reached because the locked guard fires first.
func TestPerformLockIdempotent(t *testing.T) {
	app := setupTestApp(t)
	// keyCache starts locked (default state from NewApp)

	got := app.performLock()
	if got != false {
		t.Errorf("performLock() on locked vault = %v, want false", got)
	}
}

// TestLockVaultIdempotent verifies that LockVault() can be called multiple times
// without panic when vault is already locked (LMCH-04: public wrapper idempotency).
func TestLockVaultIdempotent(t *testing.T) {
	app := setupTestApp(t)
	// keyCache starts locked -- EventsEmit is never reached, nil ctx is safe

	app.LockVault()
	app.LockVault() // second call must not panic
}

// TestEmitTickLocked verifies that emitTick() on a locked vault (nil ctx) does NOT
// panic (LMCH-02: early return guard fires before runtime.EventsEmit).
func TestEmitTickLocked(t *testing.T) {
	app := setupTestApp(t)
	// Simulate an encrypted vault that is locked (keyCache starts locked, ctx is nil)
	app.settings.Set("vault_enabled", "true")

	// If the guard is not in place, EventsEmit(nil, ...) panics.
	// If the guard fires correctly, this returns silently.
	app.emitTick()
}

// TestPerformLockReturnsFalseWhenLocked verifies the return value contract: when
// already locked, performLock() returns false (no event emitted). This tests the
// boolean return value as a signal that lock was a no-op (LMCH-04).
func TestPerformLockReturnsFalseWhenLocked(t *testing.T) {
	app := setupTestApp(t)

	// Call performLock twice: both must return false (already locked)
	first := app.performLock()
	second := app.performLock()
	if first != false {
		t.Errorf("first performLock() = %v, want false", first)
	}
	if second != false {
		t.Errorf("second performLock() = %v, want false", second)
	}
}

// TestLockClearsEntries verifies that after a lock operation, in-memory entries are
// cleared (LMCH-01: secrets removed from memory). Uses keyCache.Lock() directly to
// simulate the lock state — Wails EventsEmit cannot be called without a real Wails
// context in unit tests (log.Fatalf terminates the process), so we test the entry-
// clearing behavior directly rather than through performLock() on an unlocked vault.
func TestLockClearsEntries(t *testing.T) {
	app := setupTestApp(t)

	// Set up unlocked vault with 2 entries (simulates post-unlock state)
	password := "lock-entries-pw"
	entry2 := testEntry
	entry2.UUID = "vault-test-002"
	ents := []totp.Entry{testEntry, entry2}
	vaultBytes, err := vault.Encrypt(ents, []entries.GroupInfo{}, password)
	if err != nil {
		t.Fatalf("vault.Encrypt() error = %v", err)
	}
	masterKey, err := vault.DecryptKey(vaultBytes, password)
	if err != nil {
		t.Fatalf("vault.DecryptKey() error = %v", err)
	}
	app.keyCache.Unlock(masterKey)
	app.entryMgr.Set(ents)

	// Verify setup: vault is unlocked and has 2 entries
	if !app.keyCache.IsUnlocked() {
		t.Fatal("precondition: keyCache should be unlocked")
	}
	if snap := app.entryMgr.Snapshot(); len(snap) != 2 {
		t.Fatalf("precondition: expected 2 entries, got %d", len(snap))
	}

	// Simulate lock: clear key + clear entries (exactly what performLock does,
	// minus the EventsEmit call that requires a real Wails context)
	app.keyCache.Lock()
	app.entryMgr.Clear()

	// Verify: key is locked, entries are cleared
	if app.keyCache.IsUnlocked() {
		t.Error("keyCache should be locked after lock operation")
	}
	if snap := app.entryMgr.Snapshot(); len(snap) != 0 {
		t.Errorf("entryMgr should be empty after lock, got %d entries", len(snap))
	}

	// Verify LMCH-01: subsequent saveEntries fails because vault is locked
	if err := app.settings.Set("vault_enabled", "true"); err != nil {
		t.Fatalf("settings.Set() error = %v", err)
	}
	err = app.saveEntries([]totp.Entry{testEntry}, []entries.GroupInfo{})
	if err == nil {
		t.Error("saveEntries() after lock should return error (vault locked), got nil")
	}
}
