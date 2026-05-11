// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

// Package importer provides stateless import orchestration for OTP backup files.
package importer

import (
	"bytes"
	"errors"
	"fmt"

	"deskotp/internal/iconmatch"
	"deskotp/internal/parser"
	"deskotp/internal/totp"
)

// ImportResult carries the outcome of a successful import operation.
// All four fields are always set on success; zero value is returned on error.
type ImportResult struct {
	Added   int        `json:"added"`
	Skipped int        `json:"skipped"`
	Summary string     `json:"summary"`
	Format  string     `json:"format"`
	Merged  []totp.Entry `json:"-"`
}

// summaryText computes the human-readable import result summary from counts.
func summaryText(added, skipped int) string {
	switch {
	case added > 0 && skipped > 0:
		return fmt.Sprintf("%d added, %d already existed", added, skipped)
	case added > 0:
		return fmt.Sprintf("%d added", added)
	case skipped > 0:
		return fmt.Sprintf("All %d already existed", skipped)
	default:
		return "No accounts found in file"
	}
}

// maxImportBytes is the maximum file size accepted by ImportFile.
// Files larger than this are rejected before any parser runs.
const maxImportBytes = 50 * 1024 * 1024 // 50 MiB

// magicSignature pairs a human-readable label with the leading byte sequence
// that identifies a known non-backup binary format.
type magicSignature struct {
	label string
	sig   []byte
}

// magicSignatures lists binary file formats that are never valid backup files.
// Any file whose first bytes match one of these signatures is rejected by screenFile.
var magicSignatures = []magicSignature{
	{"ZIP", []byte{0x50, 0x4B, 0x03, 0x04}},
	{"PNG", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A}},
	{"JPEG", []byte{0xFF, 0xD8, 0xFF}},
	{"PDF", []byte{0x25, 0x50, 0x44, 0x46, 0x2D}},
	{"GIF", []byte{0x47, 0x49, 0x46, 0x38}},
	{"GZIP", []byte{0x1F, 0x8B}},
}

// screenFile inspects raw file bytes before any parser runs.
// It rejects three categories of unimportable input:
//  1. Empty files (zero bytes)
//  2. Oversized files (> maxImportBytes)
//  3. Files whose leading bytes match a known non-backup binary signature
//
// Valid backup files (JSON, XML, CSV, plain text, andOTP binary, Stratum binary, etc.)
// do not match any of the magic signatures and pass through with a nil error.
func screenFile(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("file is empty")
	}
	if len(data) > maxImportBytes {
		return fmt.Errorf("file too large (%d bytes; max %d)", len(data), maxImportBytes)
	}
	for _, m := range magicSignatures {
		if bytes.HasPrefix(data, m.sig) {
			return fmt.Errorf("not a backup file (detected %s signature)", m.label)
		}
	}
	return nil
}

// Import parses backup file data and merges it with the current entries.
// password is the vault decryption password; pass empty string for plain (unencrypted) vaults.
// Returns an ImportResult with counts, human-readable summary, format name, and merged entries on success.
//
// Error string contract (frontend checks exact equality):
//   - "password required" -- frontend shows PasswordModal; file is encrypted, no password given
//   - "incorrect password" -- frontend shows error in PasswordModal; bad password for scrypt slot
//   - All other errors are displayed as generic import errors
func Import(data []byte, password string, current []totp.Entry) (ImportResult, error) {
	if err := screenFile(data); err != nil {
		return ImportResult{}, err
	}

	incoming, formatName, err := parser.Import(data, password)
	if err != nil {
		switch {
		case errors.Is(err, parser.ErrNoParserFound):
			return ImportResult{}, fmt.Errorf("no supported backup format found")
		case errors.Is(err, parser.ErrPasswordRequired):
			return ImportResult{}, fmt.Errorf("password required")
		case errors.Is(err, parser.ErrWrongPassword):
			return ImportResult{}, fmt.Errorf("incorrect password")
		default:
			return ImportResult{}, fmt.Errorf("import: parse: %w", err)
		}
	}

	// Auto-assign icons to incoming entries (AMTCH-01, AMTCH-03)
	for i := range incoming {
		if incoming[i].Icon == "" {
			incoming[i].Icon = iconmatch.Match(incoming[i].Issuer)
		}
	}

	merged, counts := totp.Merge(current, incoming)

	return ImportResult{
		Added:   counts.Added,
		Skipped: counts.Skipped,
		Summary: summaryText(counts.Added, counts.Skipped),
		Format:  formatName,
		Merged:  merged,
	}, nil
}
