// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

//go:build linux

package main

import (
	"fmt"
	"net/url"

	"github.com/rymdport/portal/filechooser"
)

// uriToPath converts a file:// URI returned by the xdg-desktop-portal to a
// filesystem path. It handles percent-encoded characters (e.g., spaces as %20,
// Unicode as %C3%A9) correctly via url.Parse().Path. Returns an error if the
// URI cannot be parsed or does not have the "file" scheme.
func uriToPath(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("parse file URI: %w", err)
	}
	if u.Scheme != "file" {
		return "", fmt.Errorf("expected file:// URI, got scheme %q", u.Scheme)
	}
	return u.Path, nil
}

// pickFileFilters returns portal filter rules for backup file pickers.
// Each Rule is one pattern — portal does not use semicolon-separated strings.
// Both glob and MIME rules are provided for maximum compatibility across KDE
// (prefers glob) and GNOME (prefers MIME) portal backends.
func pickFileFilters() []*filechooser.Filter {
	return []*filechooser.Filter{
		{
			Name: "Authenticator Backups",
			Rules: []filechooser.Rule{
				{Type: filechooser.GlobPattern, Pattern: "*.json"},
				{Type: filechooser.GlobPattern, Pattern: "*.txt"},
				{Type: filechooser.GlobPattern, Pattern: "*.csv"},
				{Type: filechooser.GlobPattern, Pattern: "*.2fas"},
				{Type: filechooser.GlobPattern, Pattern: "*.bin"},
				{Type: filechooser.GlobPattern, Pattern: "*.xml"},
				{Type: filechooser.GlobPattern, Pattern: "*.zip"},
				{Type: filechooser.MIMEType, Pattern: "application/json"},
				{Type: filechooser.MIMEType, Pattern: "text/plain"},
				{Type: filechooser.MIMEType, Pattern: "text/csv"},
				{Type: filechooser.MIMEType, Pattern: "application/xml"},
				{Type: filechooser.MIMEType, Pattern: "application/zip"},
				{Type: filechooser.MIMEType, Pattern: "application/octet-stream"},
			},
		},
		{
			Name:  "All Files",
			Rules: []filechooser.Rule{{Type: filechooser.GlobPattern, Pattern: "*"}},
		},
	}
}

// pickQRFileFilters returns portal filter rules for QR image file pickers.
func pickQRFileFilters() []*filechooser.Filter {
	return []*filechooser.Filter{
		{
			Name: "Images",
			Rules: []filechooser.Rule{
				{Type: filechooser.GlobPattern, Pattern: "*.png"},
				{Type: filechooser.GlobPattern, Pattern: "*.jpg"},
				{Type: filechooser.GlobPattern, Pattern: "*.jpeg"},
				{Type: filechooser.GlobPattern, Pattern: "*.gif"},
				{Type: filechooser.MIMEType, Pattern: "image/png"},
				{Type: filechooser.MIMEType, Pattern: "image/jpeg"},
				{Type: filechooser.MIMEType, Pattern: "image/gif"},
			},
		},
		{
			Name:  "All Files",
			Rules: []filechooser.Rule{{Type: filechooser.GlobPattern, Pattern: "*"}},
		},
	}
}

// PickFile opens a native file dialog via xdg-desktop-portal and returns the
// selected file path. Returns an empty string with nil error if the user cancels.
// The frontend holds this path in state and passes it to ImportFile(path, password).
// This enables the two-round-trip flow for encrypted backups:
//  1. PickFile() -> frontend gets path
//  2. ImportFile(path, "") -> returns "password required" if encrypted
//  3. Frontend shows PasswordModal
//  4. ImportFile(path, realPassword) -> decrypts and imports
//
// IMPORTANT: The portal file chooser call blocks synchronously on the D-Bus
// Response signal. It MUST run in a goroutine to avoid deadlocking the Wails
// IPC bridge. The goroutine+channel pattern preserves synchronous semantics.
func (a *App) PickFile() (string, error) {
	if !a.pickerActive.CompareAndSwap(false, true) {
		return "", fmt.Errorf("file picker already open")
	}
	defer a.pickerActive.Store(false)

	type result struct {
		path string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		uris, err := filechooser.OpenFile("", "Select Backup File", &filechooser.OpenFileOptions{
			Filters: pickFileFilters(),
		})
		if err != nil {
			ch <- result{err: fmt.Errorf("pick file: xdg-desktop-portal unavailable: %w", err)}
			return
		}
		// Context guard: if app is shutting down, return silently.
		if a.ctx.Err() != nil {
			ch <- result{}
			return
		}
		// Cancel guard: empty slice with nil error means user cancelled.
		if len(uris) == 0 {
			ch <- result{} // user cancelled — nil error
			return
		}
		path, err := uriToPath(uris[0])
		if err != nil {
			ch <- result{err: fmt.Errorf("pick file: %w", err)}
			return
		}
		ch <- result{path: path}
	}()
	r := <-ch
	return r.path, r.err
}

// PickAndScanQRFile opens a native file dialog via xdg-desktop-portal filtered
// to image files, decodes the QR code in the selected image, and returns a
// URIPreview. Returns an empty URIPreview with nil error if the user cancels.
func (a *App) PickAndScanQRFile() (URIPreview, error) {
	if !a.pickerActive.CompareAndSwap(false, true) {
		return URIPreview{}, fmt.Errorf("file picker already open")
	}
	defer a.pickerActive.Store(false)

	type result struct {
		preview URIPreview
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		uris, err := filechooser.OpenFile("", "Select QR Code Image", &filechooser.OpenFileOptions{
			Filters: pickQRFileFilters(),
		})
		if err != nil {
			ch <- result{err: fmt.Errorf("pick qr file: xdg-desktop-portal unavailable: %w", err)}
			return
		}
		// Context guard: if app is shutting down, return silently.
		if a.ctx.Err() != nil {
			ch <- result{}
			return
		}
		// Cancel guard: empty slice with nil error means user cancelled.
		if len(uris) == 0 {
			ch <- result{} // user cancelled — nil error
			return
		}
		path, err := uriToPath(uris[0])
		if err != nil {
			ch <- result{err: fmt.Errorf("pick qr file: %w", err)}
			return
		}
		preview, err := a.ScanQRFile(path)
		if err != nil {
			ch <- result{err: fmt.Errorf("pick qr file: %w", err)}
			return
		}
		ch <- result{preview: preview}
	}()
	r := <-ch
	return r.preview, r.err
}

// PickBackupDir opens a native directory picker via xdg-desktop-portal,
// persists the chosen path to the backup_dir setting, and returns the path.
// Returns empty string and nil error if the user cancels.
// CurrentFolder is passed from stored backup_dir; portal ignores invalid or
// empty values gracefully (no retry needed, unlike the Wails DefaultDirectory).
func (a *App) PickBackupDir() (string, error) {
	if !a.pickerActive.CompareAndSwap(false, true) {
		return "", fmt.Errorf("file picker already open")
	}
	defer a.pickerActive.Store(false)

	type result struct {
		dir string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		uris, err := filechooser.OpenFile("", "Select Backup Directory", &filechooser.OpenFileOptions{
			Directory:     true,
			CurrentFolder: a.settings.Get("backup_dir"),
		})
		if err != nil {
			ch <- result{err: fmt.Errorf("pick backup dir: xdg-desktop-portal unavailable: %w", err)}
			return
		}
		// Context guard: if app is shutting down, return silently.
		if a.ctx.Err() != nil {
			ch <- result{}
			return
		}
		// Cancel guard: empty slice with nil error means user cancelled.
		if len(uris) == 0 {
			ch <- result{} // user cancelled — nil error
			return
		}
		dir, err := uriToPath(uris[0])
		if err != nil {
			ch <- result{err: fmt.Errorf("pick backup dir: %w", err)}
			return
		}
		if err := a.settings.Set("backup_dir", dir); err != nil {
			ch <- result{err: fmt.Errorf("pick backup dir: persist: %w", err)}
			return
		}
		ch <- result{dir: dir}
	}()
	r := <-ch
	return r.dir, r.err
}
