// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"deskotp/internal/totp"
)

// BitwardenParser implements BackupParser for Bitwarden JSON and CSV export formats.
// Bitwarden is a popular password manager that stores TOTP secrets in the login.totp field.
// Both JSON and CSV exports are detected and parsed by this single parser.
// steam:// URI entries are supported and produce Type="steam" entries with Digits=5.
type BitwardenParser struct{}

func (p *BitwardenParser) Name() string { return "Bitwarden" }

// CanParse returns true if data is a Bitwarden JSON export (has root "items" array)
// or a Bitwarden CSV export (header row contains "login_totp" column).
func (p *BitwardenParser) CanParse(data []byte) bool {
	// Try JSON first: Bitwarden JSON exports have a root {"items":[...]} structure.
	var probe struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(data, &probe); err == nil && probe.Items != nil {
		return true
	}

	// Try CSV: Bitwarden CSV exports have a header row containing "login_totp".
	// Use only the first line to keep this probe fast.
	line := strings.SplitN(string(data), "\n", 2)[0]
	fields := strings.Split(line, ",")
	for _, f := range fields {
		if strings.TrimSpace(f) == "login_totp" {
			return true
		}
	}
	return false
}

// Parse decodes a Bitwarden JSON or CSV backup into a slice of OTP entries.
// Items without a login.totp field (null or empty) are silently skipped.
// password is accepted for interface compliance but ignored — Bitwarden plain exports
// are not encrypted by this parser.
func (p *BitwardenParser) Parse(data []byte, _ string) ([]totp.Entry, error) {
	// Detect format: attempt JSON first.
	var jProbe struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(data, &jProbe); err == nil && jProbe.Items != nil {
		return p.parseJSON(data)
	}
	return p.parseCSV(data)
}

// parseJSON decodes a Bitwarden JSON export.
func (p *BitwardenParser) parseJSON(data []byte) ([]totp.Entry, error) {
	var vault struct {
		Items []struct {
			Name  string `json:"name"`
			Login struct {
				TOTP string `json:"totp"`
			} `json:"login"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &vault); err != nil {
		return nil, fmt.Errorf("bitwarden: malformed JSON: %w", err)
	}

	var entries []totp.Entry
	for _, item := range vault.Items {
		if item.Login.TOTP == "" {
			continue // silently skip items without TOTP
		}
		entry, err := parseTotpField(item.Login.TOTP)
		if err != nil {
			return nil, fmt.Errorf("bitwarden: item %q: %w", item.Name, err)
		}
		// Use item name as fallback Name if URI parsing returns empty name.
		if entry.Name == "" {
			entry.Name = item.Name
		}
		entry.UUID = uuid.New().String()
		entries = append(entries, entry)
	}
	if entries == nil {
		entries = []totp.Entry{}
	}
	return entries, nil
}

// parseCSV decodes a Bitwarden CSV export.
func (p *BitwardenParser) parseCSV(data []byte) ([]totp.Entry, error) {
	r := csv.NewReader(strings.NewReader(string(data)))
	r.LazyQuotes = true

	// Read header row.
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("bitwarden: CSV header read: %w", err)
	}

	// Find column indices.
	totpIdx := -1
	nameIdx := -1
	for i, col := range header {
		switch strings.TrimSpace(col) {
		case "login_totp":
			totpIdx = i
		case "name":
			nameIdx = i
		}
	}
	if totpIdx < 0 {
		return nil, fmt.Errorf("bitwarden: CSV missing login_totp column")
	}

	var entries []totp.Entry
	for {
		row, err := r.Read()
		if err != nil {
			break // EOF or error — stop reading
		}
		if totpIdx >= len(row) {
			continue
		}
		totpVal := strings.TrimSpace(row[totpIdx])
		if totpVal == "" {
			continue // silently skip rows without TOTP
		}

		entry, err := parseTotpField(totpVal)
		if err != nil {
			return nil, fmt.Errorf("bitwarden: CSV row: %w", err)
		}

		// Use name column as fallback if URI parsing returned empty name.
		if entry.Name == "" && nameIdx >= 0 && nameIdx < len(row) {
			entry.Name = strings.TrimSpace(row[nameIdx])
		}
		entry.UUID = uuid.New().String()
		entries = append(entries, entry)
	}
	if entries == nil {
		entries = []totp.Entry{}
	}
	return entries, nil
}

// parseTotpField handles the two URI schemes found in Bitwarden TOTP fields:
//   - "steam://BASE32SECRET": returns Entry with Type="steam", Digits=5, Period=30, Algo="SHA1"
//   - "otpauth://...": delegates to ParseURI, converts ParsedURI to totp.Entry
//
// UUID is NOT set here — callers are responsible for generating UUIDs.
func parseTotpField(s string) (totp.Entry, error) {
	const steamPrefix = "steam://"
	if secret, ok := strings.CutPrefix(s, steamPrefix); ok {
		if secret == "" {
			return totp.Entry{}, fmt.Errorf("bitwarden: steam:// URI has empty secret")
		}
		return totp.Entry{
			Type:   "steam",
			Issuer: "Steam",
			Name:   "Steam",
			Secret: secret,
			Algo:   "SHA1",
			Digits: 5,
			Period: 30,
		}, nil
	}

	parsed, err := ParseURI(s)
	if err != nil {
		return totp.Entry{}, fmt.Errorf("bitwarden: %w", err)
	}
	return totp.Entry{
		Name:    parsed.Name,
		Issuer:  parsed.Issuer,
		Secret:  parsed.Secret,
		Algo:    parsed.Algo,
		Digits:  parsed.Digits,
		Period:  parsed.Period,
		Type:    parsed.Type,
		Counter: parsed.Counter,
	}, nil
}
