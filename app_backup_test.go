// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

import (
	"testing"

	"deskotp/internal/settings"
	"deskotp/internal/vault"
)

// newBackupSettingsApp creates a minimal App for backup settings tests.
// Uses a fresh in-memory settings.Store (no disk I/O).
func newBackupSettingsApp() *App {
	return &App{
		settings: settings.New(),
		keyCache: vault.NewKeyCache(),
	}
}

// TestGetBackupSettings_AllFields verifies that GetBackupSettings reads all five
// backup_* keys and returns them in the struct fields.
func TestGetBackupSettings_AllFields(t *testing.T) {
	app := newBackupSettingsApp()
	_ = app.settings.Set("backup_dir", "/home/user/backups")
	_ = app.settings.Set("backup_schedule", "daily")
	_ = app.settings.Set("backup_retention", "10")
	_ = app.settings.Set("backup_last_backup", "1741824000")
	_ = app.settings.Set("backup_last_error", "write failed")

	got := app.GetBackupSettings()
	if got.Dir != "/home/user/backups" {
		t.Errorf("Dir = %q, want %q", got.Dir, "/home/user/backups")
	}
	if got.Schedule != "daily" {
		t.Errorf("Schedule = %q, want %q", got.Schedule, "daily")
	}
	if got.Retention != "10" {
		t.Errorf("Retention = %q, want %q", got.Retention, "10")
	}
	if got.LastBackup == "" {
		t.Errorf("LastBackup should not be empty for timestamp 1741824000")
	}
	if got.LastError != "write failed" {
		t.Errorf("LastError = %q, want %q", got.LastError, "write failed")
	}
}

// TestGetBackupSettings_EmptyStore verifies that GetBackupSettings returns empty
// strings for all fields on a fresh store (no panic, no defaults).
func TestGetBackupSettings_EmptyStore(t *testing.T) {
	app := newBackupSettingsApp()
	got := app.GetBackupSettings()
	if got.Dir != "" {
		t.Errorf("Dir = %q, want empty", got.Dir)
	}
	if got.Schedule != "" {
		t.Errorf("Schedule = %q, want empty", got.Schedule)
	}
	if got.Retention != "" {
		t.Errorf("Retention = %q, want empty", got.Retention)
	}
	if got.LastBackup != "" {
		t.Errorf("LastBackup = %q, want empty", got.LastBackup)
	}
	if got.LastError != "" {
		t.Errorf("LastError = %q, want empty", got.LastError)
	}
}

// TestGetBackupSettings_FormatsTimestamp verifies that Unix timestamp 1741824000
// is formatted as "2025-03-13 04:00:00".
func TestGetBackupSettings_FormatsTimestamp(t *testing.T) {
	app := newBackupSettingsApp()
	_ = app.settings.Set("backup_last_backup", "1741824000")

	got := app.GetBackupSettings()
	want := "2025-03-13 00:00:00"
	if got.LastBackup != want {
		t.Errorf("LastBackup = %q, want %q", got.LastBackup, want)
	}
}

// TestGetBackupSettings_NeverBackedUp verifies that empty backup_last_backup
// results in an empty LastBackup field.
func TestGetBackupSettings_NeverBackedUp(t *testing.T) {
	app := newBackupSettingsApp()
	_ = app.settings.Set("backup_last_backup", "")

	got := app.GetBackupSettings()
	if got.LastBackup != "" {
		t.Errorf("LastBackup = %q, want empty string", got.LastBackup)
	}
}

// TestGetBackupSettings_InvalidTimestamp verifies that an unparseable backup_last_backup
// results in an empty LastBackup field (graceful fallback, no panic).
func TestGetBackupSettings_InvalidTimestamp(t *testing.T) {
	app := newBackupSettingsApp()
	_ = app.settings.Set("backup_last_backup", "not-a-number")

	got := app.GetBackupSettings()
	if got.LastBackup != "" {
		t.Errorf("LastBackup = %q, want empty string for invalid timestamp", got.LastBackup)
	}
}

// TestSetBackupSettings_PersistsScheduleAndRetention verifies that SetBackupSettings
// writes schedule and retention to the underlying settings store.
func TestSetBackupSettings_PersistsScheduleAndRetention(t *testing.T) {
	app := newBackupSettingsApp()
	if err := app.SetBackupSettings("daily", "10"); err != nil {
		t.Fatalf("SetBackupSettings() error = %v", err)
	}
	if got := app.settings.Get("backup_schedule"); got != "daily" {
		t.Errorf("backup_schedule = %q, want %q", got, "daily")
	}
	if got := app.settings.Get("backup_retention"); got != "10" {
		t.Errorf("backup_retention = %q, want %q", got, "10")
	}
}

// TestSetBackupSettings_GetRoundTrip verifies that values written by SetBackupSettings
// are readable back via GetBackupSettings.
func TestSetBackupSettings_GetRoundTrip(t *testing.T) {
	app := newBackupSettingsApp()
	if err := app.SetBackupSettings("weekly", "5"); err != nil {
		t.Fatalf("SetBackupSettings() error = %v", err)
	}
	got := app.GetBackupSettings()
	if got.Schedule != "weekly" {
		t.Errorf("Schedule = %q, want %q", got.Schedule, "weekly")
	}
	if got.Retention != "5" {
		t.Errorf("Retention = %q, want %q", got.Retention, "5")
	}
}

