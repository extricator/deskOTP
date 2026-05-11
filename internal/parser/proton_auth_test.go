// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"os"
	"testing"
)

// TestProtonAuthParser_Name verifies the parser returns the expected display name.
func TestProtonAuthParser_Name(t *testing.T) {
	p := &ProtonAuthParser{}
	if got := p.Name(); got != "Proton Authenticator" {
		t.Errorf("Name() = %q, want %q", got, "Proton Authenticator")
	}
}

// TestProtonAuthParser_CanParse verifies CanParse returns true for the Proton fixture
// and false for other JSON formats and non-JSON input.
func TestProtonAuthParser_CanParse(t *testing.T) {
	protonJSON, err := os.ReadFile("testdata/proton_authenticator.json")
	if err != nil {
		t.Fatalf("failed to read proton_authenticator.json fixture: %v", err)
	}
	bitwardenJSON, err := os.ReadFile("testdata/bitwarden.json")
	if err != nil {
		t.Fatalf("failed to read bitwarden.json fixture: %v", err)
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
			name: "proton_authenticator.json fixture",
			data: protonJSON,
			want: true,
		},
		{
			name: "bitwarden.json (not proton)",
			data: bitwardenJSON,
			want: false,
		},
		{
			name: "aegis_plain.json (not proton)",
			data: aegisJSON,
			want: false,
		},
		{
			name: "JSON with version but no entries",
			data: []byte(`{"version":1,"other_key":[]}`),
			want: false,
		},
		{
			name: "JSON with entries but no version",
			data: []byte(`{"entries":[{"content":{"uri":"otpauth://totp/Test?secret=AAA"}}]}`),
			want: false,
		},
		{
			name: "random JSON object",
			data: []byte(`{"foo":"bar"}`),
			want: false,
		},
		{
			name: "not JSON",
			data: []byte("hello world"),
			want: false,
		},
		{
			name: "empty input",
			data: []byte(""),
			want: false,
		},
	}

	p := &ProtonAuthParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(tt.data)
			if got != tt.want {
				t.Errorf("CanParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestProtonAuthParser_Parse_Fixture verifies that the proton_authenticator.json fixture
// is parsed correctly, returning the expected number of entries with correct field values.
func TestProtonAuthParser_Parse_Fixture(t *testing.T) {
	data, err := os.ReadFile("testdata/proton_authenticator.json")
	if err != nil {
		t.Fatalf("failed to read proton_authenticator.json fixture: %v", err)
	}

	p := &ProtonAuthParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}

	// proton_authenticator.json has 3 entries: Deno/Mason, SPDX/James, Airbnb/Elijah
	if len(entries) != 3 {
		t.Fatalf("Parse() returned %d entries, want 3", len(entries))
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
	if e.Algo != "SHA1" {
		t.Errorf("entries[0].Algo = %q, want %q", e.Algo, "SHA1")
	}
	if e.Digits != 6 {
		t.Errorf("entries[0].Digits = %d, want 6", e.Digits)
	}
	if e.Period != uint(30) {
		t.Errorf("entries[0].Period = %d, want 30", e.Period)
	}
	if e.UUID == "" {
		t.Errorf("entries[0].UUID is empty, want non-empty UUID")
	}

	// Spot-check second entry (SPDX / James — SHA256, 7 digits, 20s)
	e2 := entries[1]
	if e2.Issuer != "SPDX" {
		t.Errorf("entries[1].Issuer = %q, want %q", e2.Issuer, "SPDX")
	}
	if e2.Name != "James" {
		t.Errorf("entries[1].Name = %q, want %q", e2.Name, "James")
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

// TestProtonAuthParser_Parse_PasswordIgnored verifies that Parse ignores the password parameter.
func TestProtonAuthParser_Parse_PasswordIgnored(t *testing.T) {
	data, err := os.ReadFile("testdata/proton_authenticator.json")
	if err != nil {
		t.Fatalf("failed to read proton_authenticator.json: %v", err)
	}

	p := &ProtonAuthParser{}
	entries, err := p.Parse(data, "somepassword")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("Parse() returned %d entries, want 3 (password should be ignored)", len(entries))
	}
}

// TestProtonAuthParser_Parse_MalformedJSON verifies that malformed JSON returns an error.
func TestProtonAuthParser_Parse_MalformedJSON(t *testing.T) {
	p := &ProtonAuthParser{}
	_, err := p.Parse([]byte("{not valid json"), "")
	if err == nil {
		t.Fatal("Parse() returned nil error for malformed JSON, want non-nil error")
	}
}
