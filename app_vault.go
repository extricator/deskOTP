// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

import (
	"fmt"

	"deskotp/internal/entries"
	"deskotp/internal/storage"
	"deskotp/internal/totp"
	"deskotp/internal/vault"
	"deskotp/internal/vaultctrl"
)

// GetVaultStatus returns whether vault encryption is enabled and whether
// the vault is currently unlocked (master key cached).
func (a *App) GetVaultStatus() vaultctrl.VaultStatus {
	return a.vaultCtrl.Status()
}

// SetPassword encrypts existing plain entries into vault format and sets
// the vault_enabled flag. After this call, the vault is unlocked (master key cached)
// and entries remain accessible.
func (a *App) SetPassword(password string) error {
	if err := a.vaultCtrl.SetPassword(password); err != nil {
		return err
	}
	a.notifyBackupChanged()
	return nil
}

// UnlockVault decrypts the vault with the provided password, caches the master
// key, and loads entries into memory. Returns "incorrect password" on wrong password.
func (a *App) UnlockVault(password string) error {
	if err := a.vaultCtrl.UnlockVault(password); err != nil {
		return err
	}
	a.emitTick()
	a.emitMetadata()
	return nil
}

// ChangeVaultPassword re-wraps the master key slot with a new password.
// The encrypted data payload is NOT re-encrypted -- only the slot changes.
// The master key in keyCache remains valid (unchanged).
func (a *App) ChangeVaultPassword(currentPassword, newPassword string) error {
	if err := a.vaultCtrl.ChangeVaultPassword(currentPassword, newPassword); err != nil {
		return err
	}
	a.notifyBackupChanged()
	return nil
}

// RemovePassword decrypts the vault back to plain JSON, clears the vault_enabled
// flag, and locks the key cache. After this call, entries are stored as plain JSON.
func (a *App) RemovePassword(password string) error {
	if err := a.vaultCtrl.RemovePassword(password); err != nil {
		return err
	}
	a.notifyBackupChanged()
	return nil
}

// saveEntries persists entries to disk, encrypting if vault is active.
// The caller is responsible for not holding entryMgr's mutex — saveEntries must NOT hold
// the mutex during file I/O.
func (a *App) saveEntries(ents []totp.Entry, groups []entries.GroupInfo) error {
	if a.settings.Get("vault_enabled") == "true" {
		masterKey, err := a.keyCache.Key()
		if err != nil {
			return fmt.Errorf("save: vault locked: %w", err)
		}
		vd := a.vaultCtrl.VaultDataSnapshot()
		data, err := vault.EncryptWithKey(ents, groups, masterKey, vd)
		if err != nil {
			return fmt.Errorf("save: encrypt: %w", err)
		}
		a.vaultCtrl.SetVaultData(data)
		return storage.SaveRaw(data)
	}
	return storage.Save(ents, groups)
}
