// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"deskotp/internal/totp"
)

// WinAuthParser parses WinAuth URI text backup files.
// WinAuth uses the same otpauth:// URI text format as Google Auth (one URI per line),
// but applies a name swap per the Aegis WinAuthImporter behavior:
//
//   - entry.Issuer = original entry.Name  (the label's account name becomes the issuer)
//   - entry.Name   = "WinAuth"            (all entries get a fixed name)
//
// This swap reflects how WinAuth stores entries without a separate issuer field.
type WinAuthParser struct{}

// Name returns the human-readable label for this parser.
func (p *WinAuthParser) Name() string {
	return "WinAuth"
}

// CanParse always returns false. WinAuth uses the same otpauth:// URI text format as
// Google Authenticator, so it cannot be distinguished from Google Auth by content alone.
// GoogleAuthParser is registered first and handles all URI text files in auto-detection.
// WinAuthParser is registered for completeness only — its Parse method is callable
// directly when the user explicitly selects the WinAuth format.
func (p *WinAuthParser) CanParse(_ []byte) bool {
	return false
}

// Parse decodes a WinAuth URI text file and applies the Aegis WinAuthImporter name swap.
// The shared parseURITextFile helper (from google_auth.go) handles URI parsing and UUID
// generation. After parsing, each entry has:
//   - Issuer set to the original Name (label's account component)
//   - Name set to "WinAuth"
//
// password is ignored (plain format requires no decryption).
func (p *WinAuthParser) Parse(data []byte, password string) ([]totp.Entry, error) {
	entries, err := parseURITextFile(data)
	if err != nil {
		return nil, err
	}

	// Apply WinAuth name swap: original Name -> Issuer, Name -> "WinAuth"
	for i := range entries {
		entries[i].Issuer = entries[i].Name
		entries[i].Name = "WinAuth"
	}

	return entries, nil
}
