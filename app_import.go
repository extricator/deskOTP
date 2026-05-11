// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

import (
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"strings"

	"deskotp/internal/importer"
	"deskotp/internal/parser"
	"deskotp/internal/qr"
)

// URIPreview holds the parsed fields from an otpauth:// URI, returned to the
// frontend for user review before the entry is committed via AddEntry.
// Secret is NOT masked — the review-before-save flow requires the plain secret.
type URIPreview struct {
	Type    string `json:"type"`
	Issuer  string `json:"issuer"`
	Name    string `json:"name"`
	Secret  string `json:"secret"`
	Algo    string `json:"algo"`
	Digits  int    `json:"digits"`
	Period  uint   `json:"period"`
	Counter uint64 `json:"counter"`
}

// ImportFile parses a backup file at the given path and merges it with the current entries.
// password is the vault decryption password; pass empty string for plain (unencrypted) vaults.
// Returns an ImportResult with counts and a human-readable summary on success.
// If path is empty (user cancelled file picker on frontend), returns zero ImportResult and nil error.
//
// Error string contract (frontend checks exact equality):
//   - "password required" -- frontend shows PasswordModal; file is encrypted, no password given
//   - "incorrect password" -- frontend shows error in PasswordModal; bad password for scrypt slot
//   - All other errors are displayed as generic import errors
func (a *App) ImportFile(path, password string) (importer.ImportResult, error) {
	if path == "" {
		return importer.ImportResult{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return importer.ImportResult{}, fmt.Errorf("import: read file: %w", err)
	}
	result, err := importer.Import(data, password, a.entryMgr.Snapshot())
	if err != nil {
		return importer.ImportResult{}, err
	}
	a.entryMgr.Set(result.Merged)
	a.entryMgr.SyncGroupsFromEntries()
	if err := a.saveEntries(result.Merged, a.entryMgr.GetGroups()); err != nil {
		return importer.ImportResult{}, fmt.Errorf("import: save: %w", err)
	}
	a.emitMetadata()
	a.notifyBackupChanged()
	return result, nil
}

// ParseAndPreviewURI parses an otpauth:// URI and returns a URIPreview for the
// frontend to display before the user confirms the add. Trims whitespace from
// the raw URI before parsing. Does not persist any state.
func (a *App) ParseAndPreviewURI(raw string) (URIPreview, error) {
	parsed, err := parser.ParseURI(strings.TrimSpace(raw))
	if err != nil {
		return URIPreview{}, err
	}
	return URIPreview{
		Type:    parsed.Type,
		Issuer:  parsed.Issuer,
		Name:    parsed.Name,
		Secret:  parsed.Secret,
		Algo:    parsed.Algo,
		Digits:  parsed.Digits,
		Period:  parsed.Period,
		Counter: parsed.Counter,
	}, nil
}

// ScanQRFile opens the image file at path, decodes its QR code, and returns a
// URIPreview of the embedded otpauth:// URI. Returns an error if the file
// cannot be opened, is not a valid image, or contains no QR code.
func (a *App) ScanQRFile(path string) (URIPreview, error) {
	f, err := os.Open(path)
	if err != nil {
		return URIPreview{}, fmt.Errorf("scan qr: open: %w", err)
	}
	defer f.Close()

	img, _, err := image.Decode(f)
	if err != nil {
		return URIPreview{}, fmt.Errorf("scan qr: decode image: %w", err)
	}

	uri, err := qr.Decode(img)
	if err != nil {
		return URIPreview{}, fmt.Errorf("scan qr: %w", err)
	}

	return a.ParseAndPreviewURI(uri)
}

