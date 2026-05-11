// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"os"
	"testing"
)

// TestStratumParser_Name verifies Name() returns "Stratum".
func TestStratumParser_Name(t *testing.T) {
	p := &StratumParser{}
	if got := p.Name(); got != "Stratum" {
		t.Errorf("Name() = %q, want %q", got, "Stratum")
	}
}

// TestStratumParser_CanParse verifies CanParse accepts only Stratum JSON backups
// (root-level JSON object with an "Authenticators" array) and rejects other formats.
func TestStratumParser_CanParse(t *testing.T) {
	stratumFixture, err := os.ReadFile("testdata/stratum_plain.json")
	if err != nil {
		t.Fatalf("failed to read Stratum fixture: %v", err)
	}
	aegisFixture, err := os.ReadFile("testdata/aegis_plain.json")
	if err != nil {
		t.Fatalf("failed to read Aegis plain fixture: %v", err)
	}
	andotpFixture, err := os.ReadFile("testdata/andotp_plain.json")
	if err != nil {
		t.Fatalf("failed to read andOTP fixture: %v", err)
	}

	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "Stratum fixture (real file)",
			input: stratumFixture,
			want:  true,
		},
		{
			name:  "minimal Stratum JSON with Authenticators array",
			input: []byte(`{"Authenticators":[]}`),
			want:  true,
		},
		{
			name:  "Aegis plain vault",
			input: aegisFixture,
			want:  false,
		},
		{
			name:  "andOTP plain array",
			input: andotpFixture,
			want:  false,
		},
		{
			name:  "2FAS backup (schemaVersion)",
			input: []byte(`{"schemaVersion":4,"services":[]}`),
			want:  false,
		},
		{
			name:  "random JSON object without Authenticators",
			input: []byte(`{"foo":"bar"}`),
			want:  false,
		},
		{
			name:  "non-JSON",
			input: []byte(`hello world`),
			want:  false,
		},
		{
			name:  "empty input",
			input: []byte(``),
			want:  false,
		},
	}

	p := &StratumParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(tt.input)
			if got != tt.want {
				t.Errorf("CanParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestStratumParser_Parse_Fixture parses the real Stratum backup fixture (7 entries:
// 3 TOTP, 3 HOTP, 1 Steam) and verifies field mapping is correct for all entry types.
func TestStratumParser_Parse_Fixture(t *testing.T) {
	data, err := os.ReadFile("testdata/stratum_plain.json")
	if err != nil {
		t.Fatalf("failed to read Stratum fixture: %v", err)
	}

	p := &StratumParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 7 {
		t.Fatalf("Parse() returned %d entries, want 7", len(entries))
	}

	// Count types
	var totpCount, hotpCount, steamCount int
	for _, e := range entries {
		switch e.Type {
		case "totp":
			totpCount++
		case "hotp":
			hotpCount++
		case "steam":
			steamCount++
		}
	}
	if totpCount != 3 {
		t.Errorf("TOTP count = %d, want 3", totpCount)
	}
	if hotpCount != 3 {
		t.Errorf("HOTP count = %d, want 3", hotpCount)
	}
	if steamCount != 1 {
		t.Errorf("Steam count = %d, want 1", steamCount)
	}

	// All UUIDs must be non-empty and unique.
	seenUUIDs := make(map[string]int, len(entries))
	for i, e := range entries {
		if e.UUID == "" {
			t.Errorf("entries[%d].UUID = \"\", want non-empty synthetic UUID", i)
			continue
		}
		if len(e.UUID) != 36 {
			t.Errorf("entries[%d].UUID len = %d, want 36 (UUID v4 format)", i, len(e.UUID))
		}
		if prev, dup := seenUUIDs[e.UUID]; dup {
			t.Errorf("entries[%d].UUID = %q collides with entries[%d]", i, e.UUID, prev)
		}
		seenUUIDs[e.UUID] = i
	}
}

// TestStratumParser_Parse_TypeMapping verifies integer Type codes map to correct strings:
// 1=hotp, 2=totp, 4=steam.
func TestStratumParser_Parse_TypeMapping(t *testing.T) {
	// 3 entries: Type 1 (HOTP), 2 (TOTP), 4 (Steam)
	input := `{"Authenticators":[
		{"Type":1,"Issuer":"Foo","Username":"Bar","Secret":"AAAA","Algorithm":0,"Digits":6,"Period":30,"Counter":5},
		{"Type":2,"Issuer":"Foo","Username":"Bar","Secret":"BBBB","Algorithm":0,"Digits":6,"Period":30,"Counter":0},
		{"Type":4,"Issuer":"Foo","Username":"Bar","Secret":"CCCC","Algorithm":0,"Digits":5,"Period":30,"Counter":0}
	]}`

	p := &StratumParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("Parse() returned %d entries, want 3", len(entries))
	}

	if entries[0].Type != "hotp" {
		t.Errorf("Type=1 entry: Type = %q, want %q", entries[0].Type, "hotp")
	}
	if entries[1].Type != "totp" {
		t.Errorf("Type=2 entry: Type = %q, want %q", entries[1].Type, "totp")
	}
	if entries[2].Type != "steam" {
		t.Errorf("Type=4 entry: Type = %q, want %q", entries[2].Type, "steam")
	}
}

// TestStratumParser_Parse_AlgoMapping verifies integer Algorithm codes map to correct strings:
// 0=SHA1, 1=SHA256, 2=SHA512.
func TestStratumParser_Parse_AlgoMapping(t *testing.T) {
	input := `{"Authenticators":[
		{"Type":2,"Issuer":"Foo","Username":"Bar","Secret":"AAAA","Algorithm":0,"Digits":6,"Period":30,"Counter":0},
		{"Type":2,"Issuer":"Foo","Username":"Bar","Secret":"BBBB","Algorithm":1,"Digits":6,"Period":30,"Counter":0},
		{"Type":2,"Issuer":"Foo","Username":"Bar","Secret":"CCCC","Algorithm":2,"Digits":6,"Period":30,"Counter":0}
	]}`

	p := &StratumParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("Parse() returned %d entries, want 3", len(entries))
	}

	if entries[0].Algo != "SHA1" {
		t.Errorf("Algorithm=0 entry: Algo = %q, want %q", entries[0].Algo, "SHA1")
	}
	if entries[1].Algo != "SHA256" {
		t.Errorf("Algorithm=1 entry: Algo = %q, want %q", entries[1].Algo, "SHA256")
	}
	if entries[2].Algo != "SHA512" {
		t.Errorf("Algorithm=2 entry: Algo = %q, want %q", entries[2].Algo, "SHA512")
	}
}

// TestStratumParser_Parse_FieldMapping verifies Username->Name and Issuer->Issuer mapping.
func TestStratumParser_Parse_FieldMapping(t *testing.T) {
	// Verify first TOTP entry: Issuer=Deno, Username=Mason (from fixture)
	data, err := os.ReadFile("testdata/stratum_plain.json")
	if err != nil {
		t.Fatalf("failed to read Stratum fixture: %v", err)
	}

	p := &StratumParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}

	e0 := entries[0] // Deno / Mason (TOTP)
	if e0.Issuer != "Deno" {
		t.Errorf("entries[0].Issuer = %q, want %q", e0.Issuer, "Deno")
	}
	if e0.Name != "Mason" {
		t.Errorf("entries[0].Name = %q, want %q (Username maps to Name)", e0.Name, "Mason")
	}
	if e0.Secret != "4SJHB4GSD43FZBAI7C2HLRJGPQ" {
		t.Errorf("entries[0].Secret = %q, want %q", e0.Secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ")
	}
	if e0.Algo != "SHA1" {
		t.Errorf("entries[0].Algo = %q, want %q (Algorithm=0)", e0.Algo, "SHA1")
	}
	if e0.Digits != 6 {
		t.Errorf("entries[0].Digits = %d, want 6", e0.Digits)
	}
	if e0.Period != 30 {
		t.Errorf("entries[0].Period = %d, want 30", e0.Period)
	}
	if e0.Type != "totp" {
		t.Errorf("entries[0].Type = %q, want %q", e0.Type, "totp")
	}
}

// TestStratumParser_Parse_SteamOverride verifies Steam entries (Type=4) get Digits=5
// and Algo="SHA1" regardless of JSON values.
func TestStratumParser_Parse_SteamOverride(t *testing.T) {
	data, err := os.ReadFile("testdata/stratum_plain.json")
	if err != nil {
		t.Fatalf("failed to read Stratum fixture: %v", err)
	}

	p := &StratumParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}

	// Steam entry is the last one in the fixture: Boeing/Sophia, Type=4
	var steamEntry *struct {
		issuer string
		name   string
		digits int
		algo   string
		period uint
		typ    string
	}
	for _, e := range entries {
		if e.Type == "steam" {
			steamEntry = &struct {
				issuer string
				name   string
				digits int
				algo   string
				period uint
				typ    string
			}{e.Issuer, e.Name, e.Digits, e.Algo, e.Period, e.Type}
			break
		}
	}

	if steamEntry == nil {
		t.Fatal("no Steam entry found in parsed entries")
	}
	if steamEntry.issuer != "Boeing" {
		t.Errorf("Steam entry: Issuer = %q, want %q", steamEntry.issuer, "Boeing")
	}
	if steamEntry.name != "Sophia" {
		t.Errorf("Steam entry: Name = %q, want %q", steamEntry.name, "Sophia")
	}
	if steamEntry.digits != 5 {
		t.Errorf("Steam entry: Digits = %d, want 5 (forced override)", steamEntry.digits)
	}
	if steamEntry.algo != "SHA1" {
		t.Errorf("Steam entry: Algo = %q, want %q (forced override)", steamEntry.algo, "SHA1")
	}
	if steamEntry.period != 30 {
		t.Errorf("Steam entry: Period = %d, want 30", steamEntry.period)
	}
}

// TestStratumParser_Parse_SkipsUnknownType verifies entries with unknown Type codes
// are silently skipped without panicking.
func TestStratumParser_Parse_SkipsUnknownType(t *testing.T) {
	// Type=3 is unknown; Type=5 is unknown
	input := `{"Authenticators":[
		{"Type":3,"Issuer":"Foo","Username":"Bar","Secret":"AAAA","Algorithm":0,"Digits":6,"Period":30,"Counter":0},
		{"Type":5,"Issuer":"Baz","Username":"Qux","Secret":"BBBB","Algorithm":0,"Digits":6,"Period":30,"Counter":0},
		{"Type":2,"Issuer":"Valid","Username":"Entry","Secret":"CCCC","Algorithm":0,"Digits":6,"Period":30,"Counter":0}
	]}`

	p := &StratumParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	// Only the TOTP entry (Type=2) should be returned; Types 3 and 5 are skipped.
	if len(entries) != 1 {
		t.Errorf("Parse() returned %d entries, want 1 (unknown Types 3 and 5 must be skipped)", len(entries))
	}
	if len(entries) == 1 && entries[0].Type != "totp" {
		t.Errorf("remaining entry: Type = %q, want %q", entries[0].Type, "totp")
	}
}

// TestStratumParser_Parse_SkipsOutOfRangeAlgorithm verifies entries with out-of-range
// Algorithm codes are silently skipped without panicking.
func TestStratumParser_Parse_SkipsOutOfRangeAlgorithm(t *testing.T) {
	// Algorithm=3 is out of range (valid: 0, 1, 2); Algorithm=-1 is negative
	input := `{"Authenticators":[
		{"Type":2,"Issuer":"Foo","Username":"Bar","Secret":"AAAA","Algorithm":3,"Digits":6,"Period":30,"Counter":0},
		{"Type":2,"Issuer":"Baz","Username":"Qux","Secret":"BBBB","Algorithm":-1,"Digits":6,"Period":30,"Counter":0},
		{"Type":2,"Issuer":"Valid","Username":"Entry","Secret":"CCCC","Algorithm":0,"Digits":6,"Period":30,"Counter":0}
	]}`

	p := &StratumParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	// Only the valid entry (Algorithm=0) should be returned.
	if len(entries) != 1 {
		t.Errorf("Parse() returned %d entries, want 1 (out-of-range Algorithms must be skipped)", len(entries))
	}
}

// TestStratumParser_Parse_HOTPCounter verifies HOTP entries have Period=0 and correct Counter.
func TestStratumParser_Parse_HOTPCounter(t *testing.T) {
	data, err := os.ReadFile("testdata/stratum_plain.json")
	if err != nil {
		t.Fatalf("failed to read Stratum fixture: %v", err)
	}

	p := &StratumParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}

	// Find HOTP entries (Type=1 in fixture: Issuu/James counter=1, Air Canada/Benjamin counter=50, WWE/Mason counter=10300)
	var hotpEntries []interface{ GetName() string }
	for _, e := range entries {
		if e.Type == "hotp" {
			// Verify HOTP invariants
			if e.Period != 0 {
				t.Errorf("HOTP entry %q: Period = %d, want 0 (HOTP must have Period=0)", e.Name, e.Period)
			}
		}
	}
	_ = hotpEntries

	// Spot-check specific HOTP counters by matching name+issuer
	for _, e := range entries {
		switch {
		case e.Issuer == "Issuu" && e.Name == "James":
			if e.Counter != 1 {
				t.Errorf("Issuu/James HOTP: Counter = %d, want 1", e.Counter)
			}
		case e.Issuer == "Air Canada" && e.Name == "Benjamin":
			if e.Counter != 50 {
				t.Errorf("Air Canada/Benjamin HOTP: Counter = %d, want 50", e.Counter)
			}
		case e.Issuer == "WWE" && e.Name == "Mason":
			if e.Counter != 10300 {
				t.Errorf("WWE/Mason HOTP: Counter = %d, want 10300", e.Counter)
			}
		}
	}
}
