// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"os"
	"testing"
)

// TestSteamGuardParser_Name verifies that SteamGuardParser.Name() returns "Steam Guard".
func TestSteamGuardParser_Name(t *testing.T) {
	p := &SteamGuardParser{}
	if got := p.Name(); got != "Steam Guard" {
		t.Errorf("Name() = %q, want %q", got, "Steam Guard")
	}
}

// TestSteamGuardParser_CanParse verifies CanParse correctly identifies both Steam Guard
// schema variants and rejects non-Steam formats.
func TestSteamGuardParser_CanParse(t *testing.T) {
	steamNew, err := os.ReadFile("testdata/steam.json")
	if err != nil {
		t.Fatalf("failed to read steam.json fixture: %v", err)
	}
	steamOld, err := os.ReadFile("testdata/steam_old.json")
	if err != nil {
		t.Fatalf("failed to read steam_old.json fixture: %v", err)
	}
	aegis, err := os.ReadFile("testdata/aegis_plain.json")
	if err != nil {
		t.Fatalf("failed to read aegis_plain.json fixture: %v", err)
	}
	andotp, err := os.ReadFile("testdata/andotp_plain.json")
	if err != nil {
		t.Fatalf("failed to read andotp_plain.json fixture: %v", err)
	}

	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "Steam Guard new schema (accounts map)",
			input: steamNew,
			want:  true,
		},
		{
			name:  "Steam Guard old schema (flat object)",
			input: steamOld,
			want:  true,
		},
		{
			name:  "Aegis plain vault (should reject)",
			input: aegis,
			want:  false,
		},
		{
			name:  "andOTP plain backup (should reject)",
			input: andotp,
			want:  false,
		},
		{
			name:  "empty JSON object",
			input: []byte(`{}`),
			want:  false,
		},
		{
			name:  "random JSON",
			input: []byte(`{"foo":"bar"}`),
			want:  false,
		},
		{
			name:  "non-JSON",
			input: []byte(`not json at all`),
			want:  false,
		},
	}

	p := &SteamGuardParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(tt.input)
			if got != tt.want {
				t.Errorf("CanParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSteamGuardParser_Parse_NewSchema verifies parsing of the new Steam Guard schema
// (accounts map with nested entry objects). All entries must have Type="steam", Digits=5, Algo="SHA1".
func TestSteamGuardParser_Parse_NewSchema(t *testing.T) {
	data, err := os.ReadFile("testdata/steam.json")
	if err != nil {
		t.Fatalf("failed to read steam.json fixture: %v", err)
	}

	p := &SteamGuardParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("Parse() returned 0 entries, want at least 1")
	}

	for i, e := range entries {
		if e.Type != "steam" {
			t.Errorf("entries[%d].Type = %q, want %q", i, e.Type, "steam")
		}
		if e.Digits != 5 {
			t.Errorf("entries[%d].Digits = %d, want 5", i, e.Digits)
		}
		if e.Algo != "SHA1" {
			t.Errorf("entries[%d].Algo = %q, want %q", i, e.Algo, "SHA1")
		}
		if e.Period != 30 {
			t.Errorf("entries[%d].Period = %d, want 30", i, e.Period)
		}
		if e.UUID == "" {
			t.Errorf("entries[%d].UUID = \"\", want non-empty UUID", i)
		}
		if len(e.UUID) != 36 {
			t.Errorf("entries[%d].UUID len = %d, want 36", i, len(e.UUID))
		}
		if e.Secret == "" {
			t.Errorf("entries[%d].Secret = \"\", want non-empty", i)
		}
		if e.Name == "" {
			t.Errorf("entries[%d].Name = \"\", want non-empty (account_name from URI label)", i)
		}
	}

	// Spot-check the known fixture entry: Sophia, secret JRZCL47CMXVOQMNPZR2F7J4RGI
	e0 := entries[0]
	if e0.Name != "Sophia" {
		t.Errorf("entries[0].Name = %q, want %q", e0.Name, "Sophia")
	}
	if e0.Secret != "JRZCL47CMXVOQMNPZR2F7J4RGI" {
		t.Errorf("entries[0].Secret = %q, want %q", e0.Secret, "JRZCL47CMXVOQMNPZR2F7J4RGI")
	}
}

// TestSteamGuardParser_Parse_OldSchema verifies parsing of the old (flat) Steam Guard schema.
// This schema stores the entry at the root object level with account_name and uri fields.
func TestSteamGuardParser_Parse_OldSchema(t *testing.T) {
	data, err := os.ReadFile("testdata/steam_old.json")
	if err != nil {
		t.Fatalf("failed to read steam_old.json fixture: %v", err)
	}

	p := &SteamGuardParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("Parse() returned 0 entries, want at least 1")
	}

	for i, e := range entries {
		if e.Type != "steam" {
			t.Errorf("entries[%d].Type = %q, want %q (URI says totp but must be overridden)", i, e.Type, "steam")
		}
		if e.Digits != 5 {
			t.Errorf("entries[%d].Digits = %d, want 5", i, e.Digits)
		}
		if e.Algo != "SHA1" {
			t.Errorf("entries[%d].Algo = %q, want %q", i, e.Algo, "SHA1")
		}
		if e.Period != 30 {
			t.Errorf("entries[%d].Period = %d, want 30", i, e.Period)
		}
		if e.UUID == "" {
			t.Errorf("entries[%d].UUID = \"\", want non-empty UUID", i)
		}
		if e.Secret == "" {
			t.Errorf("entries[%d].Secret = \"\", want non-empty", i)
		}
	}

	// Spot-check: old schema fixture is same entry (Sophia)
	e0 := entries[0]
	if e0.Name != "Sophia" {
		t.Errorf("entries[0].Name = %q, want %q", e0.Name, "Sophia")
	}
	if e0.Secret != "JRZCL47CMXVOQMNPZR2F7J4RGI" {
		t.Errorf("entries[0].Secret = %q, want %q", e0.Secret, "JRZCL47CMXVOQMNPZR2F7J4RGI")
	}
}

// TestSteamGuardParser_TypeOverride verifies that even if the URI says "otpauth://totp/",
// the parser ALWAYS overrides Type to "steam". This is the critical Steam Guard invariant.
func TestSteamGuardParser_TypeOverride(t *testing.T) {
	// Minimal new-schema Steam Guard JSON with a TOTP URI
	input := `{"accounts":{"abc":{"uri":"otpauth://totp/Steam:Alice?secret=AAAAAAAAAAAAAAAA&issuer=Steam","account_name":"Alice"}}}`

	p := &SteamGuardParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(entries))
	}
	if entries[0].Type != "steam" {
		t.Errorf("entries[0].Type = %q, want %q (URI says totp but must be overridden to steam)", entries[0].Type, "steam")
	}
	if entries[0].Digits != 5 {
		t.Errorf("entries[0].Digits = %d, want 5 (must be overridden from URI default of 6)", entries[0].Digits)
	}
}
