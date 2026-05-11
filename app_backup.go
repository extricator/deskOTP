// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"deskotp/internal/backup"
	"deskotp/internal/vault"
)

// BackupSettings is the typed return struct for GetBackupSettings.
// It aggregates all backup configuration and status in a single IPC call.
// Phase 64 frontend receives this as a Wails auto-generated TypeScript binding.
type BackupSettings struct {
	Dir        string `json:"dir"`
	Schedule   string `json:"schedule"`
	Retention  string `json:"retention"`
	LastBackup string `json:"lastBackup"`
	LastError  string `json:"lastError"`
}

// formatBackupTimestamp parses a Unix timestamp string and returns a formatted
// human-readable date/time string. Returns empty string if s is empty or invalid.
func formatBackupTimestamp(s string) string {
	if s == "" {
		return ""
	}
	ts, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return ""
	}
	return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04:05")
}

// GetBackupSettings returns aggregate backup configuration and status in one call.
// Fields: Dir (backup directory path), Schedule ("off"/"daily"/"weekly"),
// Retention ("3"/"5"/"10"), LastBackup (human-readable timestamp or ""),
// LastError (last write error message or "").
func (a *App) GetBackupSettings() BackupSettings {
	return BackupSettings{
		Dir:        a.settings.Get("backup_dir"),
		Schedule:   a.settings.Get("backup_schedule"),
		Retention:  a.settings.Get("backup_retention"),
		LastBackup: formatBackupTimestamp(a.settings.Get("backup_last_backup")),
		LastError:  a.settings.Get("backup_last_error"),
	}
}

// SetBackupSettings persists schedule and retention to the settings store.
// Manager reads these live from settings.Store on each check cycle — no explicit
// Manager notification is required (per Phase 61 architecture).
// Returns the first error encountered.
func (a *App) SetBackupSettings(schedule, retention string) error {
	if err := a.settings.Set("backup_schedule", schedule); err != nil {
		return fmt.Errorf("set backup settings: schedule: %w", err)
	}
	if err := a.settings.Set("backup_retention", retention); err != nil {
		return fmt.Errorf("set backup settings: retention: %w", err)
	}
	return nil
}

// notifyBackupChanged calls manager.NotifyChanged() if the manager is initialized.
// Guard against nil for tests that construct App without a manager.
func (a *App) notifyBackupChanged() {
	if a.manager != nil {
		a.manager.NotifyChanged()
	}
}

// doBackupWriteAt is the core backup write logic shared by doBackupWrite (auto)
// and ExportNow (manual). It snapshots entries, checks vault lock, exports, writes
// atomically, and rotates old backups.
func (a *App) doBackupWriteAt(outPath string) error {
	// Build payloads snapshot — use BuildPayloads for read access under manager lock
	// We need []totp.Entry not []CodePayload — use a snapshot approach via Set/Get.
	// Actually we need the raw entries for backup. We expose them via entryMgr snapshot.
	entrySnapshot := a.entryMgr.Snapshot()
	groupSnapshot := a.entryMgr.GetGroups()
	vaultData := a.vaultCtrl.VaultDataSnapshot()

	// Vault-locked guard (BFMT-04): silent skip for auto path
	var masterKey []byte
	if a.settings.Get("vault_enabled") == "true" {
		key, err := a.keyCache.Key()
		if errors.Is(err, vault.ErrVaultLocked) {
			return nil // silent skip — vault is locked
		}
		if err != nil {
			return fmt.Errorf("backup: key: %w", err)
		}
		masterKey = key
	}

	data, err := backup.Export(entrySnapshot, groupSnapshot, masterKey, vaultData)
	if err != nil {
		return fmt.Errorf("backup: export: %w", err)
	}

	if err := backup.WriteFile(outPath, data); err != nil {
		return err
	}

	// Rotate old backups; log warning on error but don't fail the write
	retention := 5
	if r, err := strconv.Atoi(a.settings.Get("backup_retention")); err == nil && r > 0 {
		retention = r
	}
	if err := backup.Rotate(filepath.Dir(outPath), retention); err != nil {
		if a.ctx != nil {
			runtime.LogWarning(a.ctx, "backup: rotate: "+err.Error())
		}
	}

	return nil
}

// doBackupWrite is the writeFn passed to backup.New. It generates a timestamped
// path from the configured backup_dir and delegates to doBackupWriteAt.
func (a *App) doBackupWrite() error {
	dir := a.settings.Get("backup_dir")
	if dir == "" {
		return nil // no backup dir configured — skip silently
	}
	ts := time.Now().Format("20060102-150405")
	outPath := filepath.Join(dir, "deskotp-backup-"+ts+".json")
	return a.doBackupWriteAt(outPath)
}

// ExportNow immediately writes a backup file, bypassing the 30s debounce.
// Returns the absolute path to the written file on success.
// Returns a plain error string if vault is locked (BFMT-04).
// CRITICAL: ExportNow must NOT call a.manager.NotifyChanged() — it must not
// reset the debounce timer.
func (a *App) ExportNow() (string, error) {
	// Vault-locked guard: explicit error for user-initiated export
	if a.settings.Get("vault_enabled") == "true" && !a.keyCache.IsUnlocked() {
		return "", fmt.Errorf("export: vault is locked")
	}
	dir := a.settings.Get("backup_dir")
	if dir == "" {
		return "", fmt.Errorf("export: no backup directory configured")
	}
	ts := time.Now().Format("20060102-150405")
	outPath := filepath.Join(dir, "deskotp-backup-"+ts+".json")
	if err := a.doBackupWriteAt(outPath); err != nil {
		return "", err
	}
	// Update last-backup timestamp so the UI reflects the manual export.
	nowTS := strconv.FormatInt(time.Now().Unix(), 10)
	_ = a.settings.Set("backup_last_backup", nowTS)
	_ = a.settings.Set("backup_last_error", "")
	return outPath, nil
}
