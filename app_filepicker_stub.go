// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

//go:build !linux

package main

import (
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// PickFile opens a native file dialog and returns the selected file path.
// Returns an empty string (not an error) if the user cancels.
// The frontend holds this path in state and passes it to ImportFile(path, password).
// This enables the two-round-trip flow for encrypted backups:
//  1. PickFile() -> frontend gets path
//  2. ImportFile(path, "") -> returns "password required" if encrypted
//  3. Frontend shows PasswordModal
//  4. ImportFile(path, realPassword) -> decrypts and imports
func (a *App) PickFile() (string, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select Backup File",
		Filters: []runtime.FileFilter{
			{DisplayName: "Authenticator Backups (*.json;*.txt;*.csv;*.2fas;*.bin;*.xml;*.zip)", Pattern: "*.json;*.txt;*.csv;*.2fas;*.bin;*.xml;*.zip"},
			{DisplayName: "All Files (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return "", fmt.Errorf("pick file: %w", err)
	}
	return path, nil
}

// PickAndScanQRFile opens a native file dialog filtered to image files, then
// decodes the QR code in the selected image and returns a URIPreview.
// If the user cancels the dialog, returns an empty URIPreview with nil error.
func (a *App) PickAndScanQRFile() (URIPreview, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select QR Code Image",
		Filters: []runtime.FileFilter{
			{DisplayName: "Images (*.png;*.jpg;*.jpeg;*.gif)", Pattern: "*.png;*.jpg;*.jpeg;*.gif"},
			{DisplayName: "All Files (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return URIPreview{}, fmt.Errorf("pick qr file: %w", err)
	}
	if path == "" {
		return URIPreview{}, nil // user cancelled
	}
	return a.ScanQRFile(path)
}

// PickBackupDir opens a native directory picker dialog, persists the chosen path
// to the backup_dir setting, and returns the path.
// Returns empty string and nil error if the user cancels (same pattern as PickFile).
// SAFETY: Wails validates DefaultDirectory with os.Lstat (not os.Stat), so symlinks
// and stale paths can cause it to reject. If the first attempt fails, we retry
// without DefaultDirectory so the dialog always opens.
func (a *App) PickBackupDir() (string, error) {
	opts := runtime.OpenDialogOptions{
		Title:                "Select Backup Directory",
		CanCreateDirectories: true,
	}

	// Only set DefaultDirectory if the stored path actually exists.
	if stored := a.settings.Get("backup_dir"); stored != "" {
		if _, err := os.Stat(stored); err == nil {
			opts.DefaultDirectory = stored
		}
	}

	dir, err := runtime.OpenDirectoryDialog(a.ctx, opts)
	if err != nil && opts.DefaultDirectory != "" {
		// Wails validates DefaultDirectory with os.Lstat which rejects symlinks
		// and some edge-case paths. Retry without it so the dialog still opens.
		opts.DefaultDirectory = ""
		dir, err = runtime.OpenDirectoryDialog(a.ctx, opts)
	}
	if err != nil {
		return "", fmt.Errorf("pick backup dir: %w", err)
	}
	if dir == "" {
		return "", nil // user cancelled — not an error
	}
	if err := a.settings.Set("backup_dir", dir); err != nil {
		return "", fmt.Errorf("pick backup dir: persist: %w", err)
	}
	return dir, nil
}
