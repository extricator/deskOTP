// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"os"
	"testing"
)

// TestDuoParser_Name verifies DuoParser.Name() returns "Duo".
func TestDuoParser_Name(t *testing.T) {
	p := &DuoParser{}
	if got := p.Name(); got != "Duo" {
		t.Errorf("Name() = %q, want %q", got, "Duo")
	}
}

// TestDuoParser_CanParse verifies CanParse correctly identifies Duo JSON backups
// and rejects other formats — especially andOTP (CRITICAL: both are root JSON arrays).
func TestDuoParser_CanParse(t *testing.T) {
	duo, err := os.ReadFile("testdata/duo.json")
	if err != nil {
		t.Fatalf("failed to read duo.json fixture: %v", err)
	}
	andotp, err := os.ReadFile("testdata/andotp_plain.json")
	if err != nil {
		t.Fatalf("failed to read andotp_plain.json fixture: %v", err)
	}
	aegis, err := os.ReadFile("testdata/aegis_plain.json")
	if err != nil {
		t.Fatalf("failed to read aegis_plain.json fixture: %v", err)
	}

	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "Duo fixture (should accept)",
			input: duo,
			want:  true,
		},
		{
			name:  "andOTP fixture (CRITICAL: both root JSON arrays, must reject Duo)",
			input: andotp,
			want:  false,
		},
		{
			name:  "Aegis plain vault (should reject)",
			input: aegis,
			want:  false,
		},
		{
			name:  "empty JSON array",
			input: []byte(`[]`),
			want:  false,
		},
		{
			name:  "JSON array without otpGenerator",
			input: []byte(`[{"type":"TOTP","secret":"AAAA"}]`),
			want:  false,
		},
		{
			name:  "JSON array with null otpGenerator",
			input: []byte(`[{"otpGenerator":null}]`),
			want:  false,
		},
		{
			name:  "JSON object (not array)",
			input: []byte(`{"foo":"bar"}`),
			want:  false,
		},
		{
			name:  "non-JSON",
			input: []byte(`not json`),
			want:  false,
		},
	}

	p := &DuoParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(tt.input)
			if got != tt.want {
				t.Errorf("CanParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDuoParser_Parse_Fixture parses the real Duo backup fixture and verifies:
//   - Entry without counter -> TOTP (Type="totp", Period=30)
//   - Entry with counter -> HOTP (Type="hotp", Counter=value)
//   - All entries have empty Issuer (Duo has no issuer field)
//   - Secret comes from OTPGenerator.OTPSecret
func TestDuoParser_Parse_Fixture(t *testing.T) {
	data, err := os.ReadFile("testdata/duo.json")
	if err != nil {
		t.Fatalf("failed to read duo.json fixture: %v", err)
	}

	p := &DuoParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("Parse() returned %d entries, want 2", len(entries))
	}

	// Verify UUIDs are non-empty and unique
	seenUUIDs := make(map[string]int, len(entries))
	for i, e := range entries {
		if e.UUID == "" {
			t.Errorf("entries[%d].UUID = \"\", want non-empty UUID", i)
			continue
		}
		if len(e.UUID) != 36 {
			t.Errorf("entries[%d].UUID len = %d, want 36", i, len(e.UUID))
		}
		if prev, dup := seenUUIDs[e.UUID]; dup {
			t.Errorf("entries[%d].UUID = %q collides with entries[%d]", i, e.UUID, prev)
		}
		seenUUIDs[e.UUID] = i
	}

	// Entry[0]: Mason — no counter in fixture -> TOTP
	e0 := entries[0]
	if e0.Name != "Mason" {
		t.Errorf("entries[0].Name = %q, want %q", e0.Name, "Mason")
	}
	if e0.Issuer != "" {
		t.Errorf("entries[0].Issuer = %q, want empty (Duo has no issuer field)", e0.Issuer)
	}
	if e0.Secret != "4SJHB4GSD43FZBAI7C2HLRJGPQ" {
		t.Errorf("entries[0].Secret = %q, want %q", e0.Secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ")
	}
	if e0.Type != "totp" {
		t.Errorf("entries[0].Type = %q, want %q (no counter means TOTP)", e0.Type, "totp")
	}
	if e0.Period != 30 {
		t.Errorf("entries[0].Period = %d, want 30", e0.Period)
	}
	if e0.Digits != 6 {
		t.Errorf("entries[0].Digits = %d, want 6", e0.Digits)
	}
	if e0.Algo != "SHA1" {
		t.Errorf("entries[0].Algo = %q, want %q", e0.Algo, "SHA1")
	}

	// Entry[1]: James — counter=3 in fixture -> HOTP
	e1 := entries[1]
	if e1.Name != "James" {
		t.Errorf("entries[1].Name = %q, want %q", e1.Name, "James")
	}
	if e1.Issuer != "" {
		t.Errorf("entries[1].Issuer = %q, want empty (Duo has no issuer field)", e1.Issuer)
	}
	if e1.Secret != "YOOMIXWS5GN6RTBPUFFWKTW5M4" {
		t.Errorf("entries[1].Secret = %q, want %q", e1.Secret, "YOOMIXWS5GN6RTBPUFFWKTW5M4")
	}
	if e1.Type != "hotp" {
		t.Errorf("entries[1].Type = %q, want %q (counter present means HOTP)", e1.Type, "hotp")
	}
	if e1.Counter != 3 {
		t.Errorf("entries[1].Counter = %d, want 3", e1.Counter)
	}
}

// TestDuoParser_Parse_TOTPvsHOTP verifies the counter-based TOTP/HOTP branching logic
// using inline JSON (not fixture-dependent).
func TestDuoParser_Parse_TOTPvsHOTP(t *testing.T) {
	input := `[
		{"name":"Alice","otpGenerator":{"otpSecret":"AAAABBBBCCCCDDDD"}},
		{"name":"Bob","otpGenerator":{"otpSecret":"EEEEFFFFGGGGHHHH","counter":7}}
	]`

	p := &DuoParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("Parse() returned %d entries, want 2", len(entries))
	}

	// No counter -> TOTP
	alice := entries[0]
	if alice.Type != "totp" {
		t.Errorf("Alice.Type = %q, want %q", alice.Type, "totp")
	}
	if alice.Period != 30 {
		t.Errorf("Alice.Period = %d, want 30", alice.Period)
	}
	if alice.Counter != 0 {
		t.Errorf("Alice.Counter = %d, want 0", alice.Counter)
	}

	// Counter present -> HOTP
	bob := entries[1]
	if bob.Type != "hotp" {
		t.Errorf("Bob.Type = %q, want %q", bob.Type, "hotp")
	}
	if bob.Counter != 7 {
		t.Errorf("Bob.Counter = %d, want 7", bob.Counter)
	}
}

// TestDuoParser_Parse_EmptyIssuer verifies that all Duo entries always have empty Issuer.
// Duo format does not provide an issuer field.
func TestDuoParser_Parse_EmptyIssuer(t *testing.T) {
	data, err := os.ReadFile("testdata/duo.json")
	if err != nil {
		t.Fatalf("failed to read duo.json fixture: %v", err)
	}

	p := &DuoParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	for i, e := range entries {
		if e.Issuer != "" {
			t.Errorf("entries[%d].Issuer = %q, want empty (Duo has no issuer)", i, e.Issuer)
		}
	}
}
