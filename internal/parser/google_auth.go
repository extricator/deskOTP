// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"deskotp/internal/totp"
)

// GoogleAuthParser parses Google Authenticator URI text files (one otpauth:// URI per line).
// Also handles Ente Auth exports, which use the same format with an additional codeDisplay
// query parameter that ParseURI ignores.
type GoogleAuthParser struct{}

// Name returns the human-readable label for this parser.
func (p *GoogleAuthParser) Name() string {
	return "Google Authenticator"
}

// CanParse returns true if data looks like a URI text file: the first non-blank line
// must start with "otpauth://". Uses a bufio.Scanner to avoid loading the full file.
func (p *GoogleAuthParser) CanParse(data []byte) bool {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		return strings.HasPrefix(line, "otpauth://")
	}
	return false
}

// Parse decodes a URI text file into a slice of totp.Entry.
// The password parameter is ignored (plain format requires no decryption).
// Blank lines are silently skipped. Each valid URI generates a new UUID.
func (p *GoogleAuthParser) Parse(data []byte, password string) ([]totp.Entry, error) {
	return parseURITextFile(data)
}

// parseURITextFile is a shared package-level helper used by GoogleAuthParser and
// WinAuthParser. It scans data line-by-line, calls ParseURI on each non-blank line,
// and generates a UUID per entry. Returns an error if any line fails to parse.
func parseURITextFile(data []byte) ([]totp.Entry, error) {
	var entries []totp.Entry
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parsed, err := ParseURI(line)
		if err != nil {
			return nil, fmt.Errorf("google_auth: line %d: %w", lineNum, err)
		}
		entries = append(entries, totp.Entry{
			UUID:    uuid.New().String(),
			Name:    parsed.Name,
			Issuer:  parsed.Issuer,
			Secret:  parsed.Secret,
			Algo:    parsed.Algo,
			Digits:  parsed.Digits,
			Period:  parsed.Period,
			Type:    parsed.Type,
			Counter: parsed.Counter,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("google_auth: scanner error: %w", err)
	}
	return entries, nil
}
