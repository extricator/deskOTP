// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

import (
	"context"
	"sync/atomic"

	"deskotp/internal/backup"
	"deskotp/internal/clipboard"
	"deskotp/internal/entries"
	"deskotp/internal/iconmatch"
	"deskotp/internal/settings"
	"deskotp/internal/vault"
	"deskotp/internal/vaultctrl"
)

// App is the Wails application struct. All exported methods are bound to the frontend.
type App struct {
	ctx       context.Context
	entryMgr  *entries.Manager
	settings  *settings.Store
	keyCache  *vault.KeyCache      // holds master key after unlock
	vaultCtrl *vaultctrl.Controller // owns vaultData and vaultDataMu
	clipMgr   *clipboard.Manager

	manager       *backup.Manager    // debounced backup writer
	managerCancel context.CancelFunc // stops the manager's context on shutdown
	pickerActive  atomic.Bool        // prevents concurrent portal file dialogs
}

// NewApp creates a new App application struct.
func NewApp() *App {
	return &App{settings: settings.New(), keyCache: vault.NewKeyCache()}
}

// GetSetting returns the value of a setting by key.
// Returns an empty string if the key has not been set.
func (a *App) GetSetting(key string) string {
	return a.settings.Get(key)
}

// SetSetting updates a setting key-value pair and persists to disk.
func (a *App) SetSetting(key, value string) error {
	return a.settings.Set(key, value)
}

// GetIconSuggestion returns the icon slug for the given issuer, or empty string
// if no match is found. Delegates to iconmatch.Match.
func (a *App) GetIconSuggestion(issuer string) string {
	return iconmatch.Match(issuer)
}

