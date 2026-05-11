// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

import (
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"deskotp/internal/clipboard"
	"deskotp/internal/entries"
)

// AddEntry appends a new OTP entry with a fresh UUID to the in-memory list and
// persists it to storage. Delegates to entryMgr.Add.
func (a *App) AddEntry(name, issuer, secret, entryType, algo string, period, digits int, counter uint64, icon, group string, force bool) error {
	return a.entryMgr.Add(name, issuer, secret, entryType, algo, period, digits, counter, icon, group, force)
}

// UpdateEntry modifies an existing entry identified by id (UUID). Delegates to entryMgr.Update.
func (a *App) UpdateEntry(id, name, issuer, group, note, entryType, algo string, period, digits int, newSecret, icon string) error {
	return a.entryMgr.Update(id, name, issuer, group, note, entryType, algo, period, digits, newSecret, icon)
}

// DeleteEntry removes an account by UUID. Delegates to entryMgr.Delete.
func (a *App) DeleteEntry(id string) error {
	return a.entryMgr.Delete(id)
}

// UndoDelete restores the most recently deleted entry. Delegates to entryMgr.UndoDelete.
func (a *App) UndoDelete() error {
	return a.entryMgr.UndoDelete()
}

// GetEntryDetails returns full entry details for the edit dialog.
// The secret is masked server-side — it never reaches JavaScript in usable form.
func (a *App) GetEntryDetails(id string) (entries.EntryDetails, error) {
	return a.entryMgr.GetDetails(id)
}

// GetEntryGroups returns the ordered group list.
// Used by the edit dialog to populate the group combo input.
// Returns an empty slice (not nil) when no groups exist.
func (a *App) GetEntryGroups() []entries.GroupInfo {
	return a.entryMgr.GetGroups()
}

// GetCodes returns the current TOTP code payloads for all entries.
// Called by the frontend on mount to get codes immediately without waiting for
// the first codes:tick event (which may be missed due to WebView load timing).
func (a *App) GetCodes() []entries.CodePayload {
	if a.settings.Get("vault_enabled") == "true" && !a.keyCache.IsUnlocked() {
		return []entries.CodePayload{}
	}
	return a.entryMgr.BuildPayloads(time.Now())
}

// GetEntries returns entry metadata for all entries (no TOTP codes).
// Called by the frontend on mount alongside GetCodes() to seed the metadata map,
// since GetCodes() only returns code-rotating fields after the CodePayload shrink.
func (a *App) GetEntries() []entries.EntryMetadata {
	if a.settings.Get("vault_enabled") == "true" && !a.keyCache.IsUnlocked() {
		return []entries.EntryMetadata{}
	}
	return a.entryMgr.BuildMetadataPayloads()
}

// CopyCode computes the current OTP code for the account identified by id (UUID)
// and writes it to the system clipboard.
// For HOTP accounts: increments the counter in-memory and persists it to storage
// before writing to the clipboard (counter-first ordering ensures no replay risk).
// Returns an error if id is not found or code generation fails.
func (a *App) CopyCode(id string) error {
	code, err := a.entryMgr.GenerateAndAdvance(id, time.Now())
	if err != nil {
		return err
	}
	if err := runtime.ClipboardSetText(a.ctx, code); err != nil {
		return err
	}
	timeout := a.settings.Get("clipboard_clear_timeout")
	dur, skip := clipboard.ParseTimeout(timeout)
	if !skip {
		a.clipMgr.Start(code, dur)
	}
	return nil
}
