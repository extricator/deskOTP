// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"os"
	"testing"
)

// TestBitwardenParser_Name verifies the parser's human-readable name.
func TestBitwardenParser_Name(t *testing.T) {
	p := &BitwardenParser{}
	if got := p.Name(); got != "Bitwarden" {
		t.Errorf("Name() = %q, want %q", got, "Bitwarden")
	}
}

// TestBitwardenParser_CanParse verifies CanParse accepts Bitwarden JSON and CSV,
// and rejects other formats.
func TestBitwardenParser_CanParse(t *testing.T) {
	bwJSON, err := os.ReadFile("testdata/bitwarden.json")
	if err != nil {
		t.Fatalf("failed to read bitwarden.json fixture: %v", err)
	}
	bwCSV, err := os.ReadFile("testdata/bitwarden.csv")
	if err != nil {
		t.Fatalf("failed to read bitwarden.csv fixture: %v", err)
	}
	aegisJSON, err := os.ReadFile("testdata/aegis_plain.json")
	if err != nil {
		t.Fatalf("failed to read aegis_plain.json fixture: %v", err)
	}

	tests := []struct {
		name  string
		data  []byte
		want  bool
	}{
		{
			name: "bitwarden JSON fixture",
			data: bwJSON,
			want: true,
		},
		{
			name: "bitwarden CSV fixture",
			data: bwCSV,
			want: true,
		},
		{
			name: "aegis plain JSON (not bitwarden)",
			data: aegisJSON,
			want: false,
		},
		{
			name: "random JSON object",
			data: []byte(`{"foo":"bar"}`),
			want: false,
		},
		{
			name: "CSV without login_totp column",
			data: []byte("name,username,password\nfoo,bar,baz"),
			want: false,
		},
		{
			name: "not JSON or CSV",
			data: []byte("hello world"),
			want: false,
		},
		{
			name: "empty input",
			data: []byte(""),
			want: false,
		},
	}

	p := &BitwardenParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(tt.data)
			if got != tt.want {
				t.Errorf("CanParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBitwardenParser_Parse_JSON verifies that the JSON fixture is parsed correctly,
// returning the expected number of OTP entries.
func TestBitwardenParser_Parse_JSON(t *testing.T) {
	data, err := os.ReadFile("testdata/bitwarden.json")
	if err != nil {
		t.Fatalf("failed to read bitwarden.json fixture: %v", err)
	}

	p := &BitwardenParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	// bitwarden.json has 4 items: 3 TOTP + 1 steam — all have login.totp
	if len(entries) != 4 {
		t.Fatalf("Parse() returned %d entries, want 4", len(entries))
	}

	// Spot-check first entry (Deno / Mason)
	e := entries[0]
	if e.Issuer != "Deno" {
		t.Errorf("entries[0].Issuer = %q, want %q", e.Issuer, "Deno")
	}
	if e.Name != "Mason" {
		t.Errorf("entries[0].Name = %q, want %q", e.Name, "Mason")
	}
	if e.Secret != "4SJHB4GSD43FZBAI7C2HLRJGPQ" {
		t.Errorf("entries[0].Secret = %q, want %q", e.Secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ")
	}
	if e.Type != "totp" {
		t.Errorf("entries[0].Type = %q, want %q", e.Type, "totp")
	}
	if e.Digits != 6 {
		t.Errorf("entries[0].Digits = %d, want 6", e.Digits)
	}
	if e.Period != uint(30) {
		t.Errorf("entries[0].Period = %d, want 30", e.Period)
	}
	if e.UUID == "" {
		t.Errorf("entries[0].UUID is empty, want a non-empty UUID")
	}

	// Spot-check second entry (SPDX / James — SHA256, 7 digits, 20s)
	e2 := entries[1]
	if e2.Issuer != "SPDX" {
		t.Errorf("entries[1].Issuer = %q, want %q", e2.Issuer, "SPDX")
	}
	if e2.Algo != "SHA256" {
		t.Errorf("entries[1].Algo = %q, want %q", e2.Algo, "SHA256")
	}
	if e2.Digits != 7 {
		t.Errorf("entries[1].Digits = %d, want 7", e2.Digits)
	}
	if e2.Period != uint(20) {
		t.Errorf("entries[1].Period = %d, want 20", e2.Period)
	}
}

// TestBitwardenParser_Parse_JSON_SteamEntry verifies that a steam:// URI produces a
// Type="steam" entry with Digits=5, Period=30, Algo="SHA1".
func TestBitwardenParser_Parse_JSON_SteamEntry(t *testing.T) {
	data, err := os.ReadFile("testdata/bitwarden.json")
	if err != nil {
		t.Fatalf("failed to read bitwarden.json fixture: %v", err)
	}

	p := &BitwardenParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}

	if len(entries) < 4 {
		t.Fatalf("Parse() returned %d entries, want at least 4", len(entries))
	}
	// Steam entry is the last one (index 3) in bitwarden.json
	steam := entries[3]
	if steam.Type != "steam" {
		t.Errorf("steam entry Type = %q, want %q", steam.Type, "steam")
	}
	if steam.Digits != 5 {
		t.Errorf("steam entry Digits = %d, want 5", steam.Digits)
	}
	if steam.Period != uint(30) {
		t.Errorf("steam entry Period = %d, want 30", steam.Period)
	}
	if steam.Algo != "SHA1" {
		t.Errorf("steam entry Algo = %q, want %q", steam.Algo, "SHA1")
	}
	if steam.Secret != "JRZCL47CMXVOQMNPZR2F7J4RGI" {
		t.Errorf("steam entry Secret = %q, want %q", steam.Secret, "JRZCL47CMXVOQMNPZR2F7J4RGI")
	}
}

// TestBitwardenParser_Parse_CSV verifies that the CSV fixture is parsed correctly.
func TestBitwardenParser_Parse_CSV(t *testing.T) {
	data, err := os.ReadFile("testdata/bitwarden.csv")
	if err != nil {
		t.Fatalf("failed to read bitwarden.csv fixture: %v", err)
	}

	p := &BitwardenParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	// bitwarden.csv has 4 rows: 3 TOTP + 1 steam
	if len(entries) != 4 {
		t.Fatalf("Parse() returned %d entries, want 4", len(entries))
	}

	// Spot-check first entry (Deno / Mason)
	e := entries[0]
	if e.Issuer != "Deno" {
		t.Errorf("entries[0].Issuer = %q, want %q", e.Issuer, "Deno")
	}
	if e.Secret != "4SJHB4GSD43FZBAI7C2HLRJGPQ" {
		t.Errorf("entries[0].Secret = %q, want %q", e.Secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ")
	}
	if e.UUID == "" {
		t.Errorf("entries[0].UUID is empty, want a non-empty UUID")
	}
}

// TestBitwardenParser_Parse_CSV_SteamEntry verifies steam:// URIs in CSV are parsed correctly.
func TestBitwardenParser_Parse_CSV_SteamEntry(t *testing.T) {
	data, err := os.ReadFile("testdata/bitwarden.csv")
	if err != nil {
		t.Fatalf("failed to read bitwarden.csv fixture: %v", err)
	}

	p := &BitwardenParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}

	if len(entries) < 4 {
		t.Fatalf("Parse() returned %d entries, want at least 4", len(entries))
	}
	// Steam entry is the last one (index 3) in bitwarden.csv
	steam := entries[3]
	if steam.Type != "steam" {
		t.Errorf("steam entry Type = %q, want %q", steam.Type, "steam")
	}
	if steam.Digits != 5 {
		t.Errorf("steam entry Digits = %d, want 5", steam.Digits)
	}
	if steam.Secret != "JRZCL47CMXVOQMNPZR2F7J4RGI" {
		t.Errorf("steam entry Secret = %q, want %q", steam.Secret, "JRZCL47CMXVOQMNPZR2F7J4RGI")
	}
}

// TestBitwardenParser_Parse_SkipsEmptyTOTP verifies that items with null/empty login.totp
// are silently skipped, not treated as errors.
func TestBitwardenParser_Parse_SkipsEmptyTOTP(t *testing.T) {
	input := `{
		"encrypted": false,
		"items": [
			{
				"id": "aaa",
				"type": 1,
				"name": "No TOTP",
				"login": {
					"username": "user@example.com",
					"password": "hunter2",
					"totp": null
				}
			},
			{
				"id": "bbb",
				"type": 1,
				"name": "Empty TOTP",
				"login": {
					"totp": ""
				}
			},
			{
				"id": "ccc",
				"type": 1,
				"name": "Has TOTP",
				"login": {
					"totp": "otpauth://totp/Test:User?secret=JBSWY3DPEHPK3PXP&issuer=Test&digits=6&period=30"
				}
			}
		]
	}`

	p := &BitwardenParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	// Only the third item has a TOTP field — other two should be silently skipped
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1 (items without TOTP should be skipped)", len(entries))
	}
	if entries[0].Issuer != "Test" {
		t.Errorf("entries[0].Issuer = %q, want %q", entries[0].Issuer, "Test")
	}
}

// TestBitwardenParser_CanParse_ProtonJSON verifies that CanParse returns false for
// Proton Authenticator JSON (which also has an "entries" field but no "items").
func TestBitwardenParser_CanParse_ProtonJSON(t *testing.T) {
	// Proton JSON: {"version":1,"entries":[...]} — no "items" field
	protonJSON := `{"version":1,"entries":[{"id":"abc","content":{"uri":"otpauth://totp/Test:User?secret=JBSWY3DPEHPK3PXP"}}]}`
	p := &BitwardenParser{}
	if p.CanParse([]byte(protonJSON)) {
		t.Errorf("CanParse() returned true for Proton Authenticator JSON, want false")
	}
}
