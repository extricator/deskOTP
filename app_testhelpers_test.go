// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

import (
	"testing"

	"deskotp/internal/entries"
	"deskotp/internal/settings"
	"deskotp/internal/storage"
	"deskotp/internal/vaultctrl"
)

// newTestEntryMgr creates an entries.Manager wired to the given App's save/notify/emit callbacks.
// Used by tests that manually construct App without calling startup().
func newTestEntryMgr(app *App) *entries.Manager {
	return entries.New(app.saveEntries, app.notifyBackupChanged, app.emitTick, app.emitMetadata)
}

// setupTestApp creates an App with isolated temp directories for storage and settings.
// Both packages write to the same temp dir (separate subdirectories are created internally).
// The entryMgr is initialized so tests can call entry-related methods.
func setupTestApp(t *testing.T) *App {
	t.Helper()
	tmp := t.TempDir()
	cleanStorage := storage.SetConfigDirOverride(tmp)
	t.Cleanup(cleanStorage)
	cleanSettings := settings.SetConfigDirOverride(tmp)
	t.Cleanup(cleanSettings)
	app := NewApp()
	if err := app.settings.Load(); err != nil {
		t.Fatalf("settings.Load() error = %v", err)
	}
	app.entryMgr = newTestEntryMgr(app)
	app.vaultCtrl = vaultctrl.New(
		app.keyCache,
		app.settings,
		app.entryMgr.Snapshot,
		app.entryMgr.GetGroups,
		app.entryMgr.Set,
		app.entryMgr.SetGroups,
	)
	return app
}
