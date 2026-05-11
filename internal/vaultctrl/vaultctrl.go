// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package vaultctrl

import (
	"errors"
	"fmt"
	"sync"

	"deskotp/internal/entries"
	"deskotp/internal/settings"
	"deskotp/internal/storage"
	"deskotp/internal/totp"
	"deskotp/internal/vault"
)

// VaultStatus reports whether the vault is enabled and unlocked.
// Used by the frontend to decide what to show (token list vs unlock screen).
type VaultStatus struct {
	Enabled  bool `json:"enabled"`
	Unlocked bool `json:"unlocked"`
}

// Controller owns vault state (vaultData and its mutex) and orchestrates all
// vault password operations. App vault methods are thin delegates to Controller.
type Controller struct {
	mu              sync.RWMutex
	vaultData       []byte
	keyCache        *vault.KeyCache
	settings        *settings.Store
	snapshotFn      func() []totp.Entry          // snapshot current entries (entryMgr.Snapshot)
	groupSnapshotFn func() []entries.GroupInfo    // snapshot current groups (entryMgr.GetGroups)
	reloadFn        func([]totp.Entry)            // set entries after unlock/remove (entryMgr.Set)
	setGroupsFn     func([]entries.GroupInfo)     // set groups after unlock/remove (entryMgr.SetGroups)
}

// New creates a Controller with the provided dependencies.
// snapshotFn is called by SetPassword to get the current entry list before encryption.
// groupSnapshotFn is called by SetPassword to get the current group list before encryption.
// reloadFn is called by UnlockVault and RemovePassword to update in-memory entries.
// setGroupsFn is called by UnlockVault and RemovePassword to update in-memory groups.
func New(
	keyCache *vault.KeyCache,
	st *settings.Store,
	snapshotFn func() []totp.Entry,
	groupSnapshotFn func() []entries.GroupInfo,
	reloadFn func([]totp.Entry),
	setGroupsFn func([]entries.GroupInfo),
) *Controller {
	return &Controller{
		keyCache:        keyCache,
		settings:        st,
		snapshotFn:      snapshotFn,
		groupSnapshotFn: groupSnapshotFn,
		reloadFn:        reloadFn,
		setGroupsFn:     setGroupsFn,
	}
}

// SetPassword encrypts existing plain entries into vault format and sets
// the vault_enabled flag. After this call the vault is unlocked (master key cached)
// and entries remain accessible.
func (c *Controller) SetPassword(password string) error {
	ents := c.snapshotFn()
	grps := c.groupSnapshotFn()

	// Encrypt with new password (scrypt runs here, OUTSIDE mutex)
	vaultBytes, err := vault.Encrypt(ents, grps, password)
	if err != nil {
		return fmt.Errorf("set password: encrypt: %w", err)
	}

	// Persist encrypted vault
	if err := storage.SaveRaw(vaultBytes); err != nil {
		return fmt.Errorf("set password: save: %w", err)
	}

	// Extract master key (scrypt runs again -- acceptable for one-time setup)
	masterKey, err := vault.DecryptKey(vaultBytes, password)
	if err != nil {
		return fmt.Errorf("set password: extract key: %w", err)
	}

	// Cache key and vault bytes
	c.keyCache.Unlock(masterKey)
	c.mu.Lock()
	c.vaultData = vaultBytes
	c.mu.Unlock()

	// Set vault_enabled flag
	if err := c.settings.Set("vault_enabled", "true"); err != nil {
		return fmt.Errorf("set password: update settings: %w", err)
	}

	return nil
}

// UnlockVault decrypts the vault with the provided password, caches the master
// key, and loads entries into memory via reloadFn. Returns "incorrect password" on
// wrong password.
func (c *Controller) UnlockVault(password string) error {
	// Read encrypted vault from disk
	rawData, err := storage.LoadRaw()
	if err != nil {
		return fmt.Errorf("unlock: read vault: %w", err)
	}
	if rawData == nil {
		return fmt.Errorf("unlock: no vault file found")
	}

	// Decrypt entries and extract master key in a single scrypt derivation
	ents, groups, masterKey, err := vault.DecryptFull(rawData, password)
	if err != nil {
		if errors.Is(err, vault.ErrWrongPassword) {
			return fmt.Errorf("incorrect password")
		}
		return fmt.Errorf("unlock: decrypt: %w", err)
	}

	// Cache key and vault bytes
	c.keyCache.Unlock(masterKey)
	c.mu.Lock()
	c.vaultData = rawData
	c.mu.Unlock()

	c.reloadFn(ents)
	c.setGroupsFn(groups)
	return nil
}

// ChangeVaultPassword re-wraps the master key slot with a new password.
// The encrypted data payload is NOT re-encrypted -- only the slot changes.
// The master key in keyCache remains valid (unchanged).
func (c *Controller) ChangeVaultPassword(currentPassword, newPassword string) error {
	// Re-wrap slot (scrypt runs here for both old and new password, OUTSIDE mutex)
	c.mu.RLock()
	vd := c.vaultData
	c.mu.RUnlock()

	newVaultBytes, err := vault.ChangePassword(vd, currentPassword, newPassword)
	if err != nil {
		if errors.Is(err, vault.ErrWrongPassword) {
			return fmt.Errorf("incorrect password")
		}
		return fmt.Errorf("change password: %w", err)
	}

	// Persist updated vault
	if err := storage.SaveRaw(newVaultBytes); err != nil {
		return fmt.Errorf("change password: save: %w", err)
	}

	// Update cached vault bytes (master key is unchanged)
	c.mu.Lock()
	c.vaultData = newVaultBytes
	c.mu.Unlock()

	return nil
}

// RemovePassword decrypts the vault back to plain JSON, clears the vault_enabled
// flag, and locks the key cache. After this call entries are stored as plain JSON.
func (c *Controller) RemovePassword(password string) error {
	// Decrypt vault to get plain entries and groups (scrypt runs here)
	c.mu.RLock()
	vd := c.vaultData
	c.mu.RUnlock()

	ents, groups, err := vault.Decrypt(vd, password)
	if err != nil {
		if errors.Is(err, vault.ErrWrongPassword) {
			return fmt.Errorf("incorrect password")
		}
		return fmt.Errorf("remove password: decrypt: %w", err)
	}

	// Write plain JSON preserving groups from the vault payload
	if err := storage.Save(ents, groups); err != nil {
		return fmt.Errorf("remove password: save: %w", err)
	}

	// Clear vault state
	if err := c.settings.Set("vault_enabled", "false"); err != nil {
		return fmt.Errorf("remove password: update settings: %w", err)
	}
	c.keyCache.Lock()
	c.mu.Lock()
	c.vaultData = nil
	c.mu.Unlock()

	c.reloadFn(ents)
	c.setGroupsFn(groups)
	return nil
}

// Status returns the current vault enabled/unlocked state.
func (c *Controller) Status() VaultStatus {
	return VaultStatus{
		Enabled:  c.settings.Get("vault_enabled") == "true",
		Unlocked: c.keyCache.IsUnlocked(),
	}
}

// VaultDataSnapshot returns a defensive copy of the cached vault bytes.
// Returns nil if no vault data is cached (vault disabled or not yet unlocked).
func (c *Controller) VaultDataSnapshot() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.vaultData == nil {
		return nil
	}
	out := make([]byte, len(c.vaultData))
	copy(out, c.vaultData)
	return out
}

// SetVaultData replaces the cached vault bytes. Called by saveEntries after
// re-encrypting entries with a fresh nonce.
func (c *Controller) SetVaultData(data []byte) {
	c.mu.Lock()
	c.vaultData = data
	c.mu.Unlock()
}
