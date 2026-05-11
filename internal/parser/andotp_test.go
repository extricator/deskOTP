// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"os"
	"strings"
	"testing"
)

// TestAndOTPParser_CanParse verifies CanParse accepts only andOTP JSON backups
// (root-level JSON arrays) and rejects all other formats.
func TestAndOTPParser_CanParse(t *testing.T) {
	fixture, err := os.ReadFile("testdata/andotp_plain.json")
	if err != nil {
		t.Fatalf("failed to read andOTP fixture: %v", err)
	}

	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "andOTP fixture (real file)",
			input: fixture,
			want:  true,
		},
		{
			name:  "empty JSON array",
			input: []byte(`[]`),
			want:  false, // empty array — no elements to probe; CanParse requires type+secret fields
		},
		{
			name:  "Aegis plain vault",
			input: []byte(`{"version":1,"header":{"slots":null,"params":null},"db":{"version":2,"entries":[]}}`),
			want:  false,
		},
		{
			name:  "2FAS backup",
			input: []byte(`{"schemaVersion":4,"services":[]}`),
			want:  false,
		},
		{
			name:  "random JSON object",
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

	p := &AndOTPParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(tt.input)
			if got != tt.want {
				t.Errorf("CanParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAndOTPParser_Parse_Fixture parses the real andOTP plain backup fixture (7 entries:
// 3 TOTP, 3 HOTP, 1 Steam) and verifies field mapping is correct for all entry types.
func TestAndOTPParser_Parse_Fixture(t *testing.T) {
	data, err := os.ReadFile("testdata/andotp_plain.json")
	if err != nil {
		t.Fatalf("failed to read andOTP fixture: %v", err)
	}

	p := &AndOTPParser{}
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

	// All UUIDs within the parse call must be non-empty and unique.
	seenUUIDs := make(map[string]int, len(entries))
	for i, e := range entries {
		if e.UUID == "" {
			t.Errorf("entries[%d].UUID = \"\", want non-empty synthetic UUID (prevents copiedId collision)", i)
			continue
		}
		if len(e.UUID) != 36 {
			t.Errorf("entries[%d].UUID len = %d, want 36 (UUID v4 format)", i, len(e.UUID))
		}
		if prev, dup := seenUUIDs[e.UUID]; dup {
			t.Errorf("entries[%d].UUID = %q collides with entries[%d] (UUIDs must be unique)", i, e.UUID, prev)
		}
		seenUUIDs[e.UUID] = i
	}

	// Verify TOTP[0]: Deno / Mason
	e0 := entries[0]
	if e0.UUID == "" {
		t.Error("entry[0].UUID = \"\", want non-empty synthetic UUID")
	}
	if len(e0.UUID) != 36 {
		t.Errorf("entry[0].UUID len = %d, want 36 (UUID v4 format)", len(e0.UUID))
	}
	if e0.Issuer != "Deno" {
		t.Errorf("entry[0].Issuer = %q, want %q", e0.Issuer, "Deno")
	}
	if e0.Name != "Mason" {
		t.Errorf("entry[0].Name = %q, want %q", e0.Name, "Mason")
	}
	if e0.Secret != "4SJHB4GSD43FZBAI7C2HLRJGPQ======" {
		t.Errorf("entry[0].Secret = %q, want %q", e0.Secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ======")
	}
	if e0.Algo != "SHA1" {
		t.Errorf("entry[0].Algo = %q, want %q", e0.Algo, "SHA1")
	}
	if e0.Digits != 6 {
		t.Errorf("entry[0].Digits = %d, want 6", e0.Digits)
	}
	if e0.Period != 30 {
		t.Errorf("entry[0].Period = %d, want 30", e0.Period)
	}
	if e0.Type != "totp" {
		t.Errorf("entry[0].Type = %q, want %q", e0.Type, "totp")
	}

	// Verify TOTP[1]: SPDX / James
	e1 := entries[1]
	if e1.Issuer != "SPDX" {
		t.Errorf("entry[1].Issuer = %q, want %q", e1.Issuer, "SPDX")
	}
	if e1.Name != "James" {
		t.Errorf("entry[1].Name = %q, want %q", e1.Name, "James")
	}
	if e1.Algo != "SHA256" {
		t.Errorf("entry[1].Algo = %q, want %q", e1.Algo, "SHA256")
	}
	if e1.Digits != 7 {
		t.Errorf("entry[1].Digits = %d, want 7", e1.Digits)
	}
	if e1.Period != 20 {
		t.Errorf("entry[1].Period = %d, want 20", e1.Period)
	}

	// Verify TOTP[2]: Airbnb / Elijah
	e2 := entries[2]
	if e2.Issuer != "Airbnb" {
		t.Errorf("entry[2].Issuer = %q, want %q", e2.Issuer, "Airbnb")
	}
	if e2.Name != "Elijah" {
		t.Errorf("entry[2].Name = %q, want %q", e2.Name, "Elijah")
	}
	if e2.Algo != "SHA512" {
		t.Errorf("entry[2].Algo = %q, want %q", e2.Algo, "SHA512")
	}
	if e2.Digits != 8 {
		t.Errorf("entry[2].Digits = %d, want 8", e2.Digits)
	}
	if e2.Period != 50 {
		t.Errorf("entry[2].Period = %d, want 50", e2.Period)
	}

	// Verify HOTP[3]: Issuu / James
	e3 := entries[3]
	if e3.Issuer != "Issuu" {
		t.Errorf("entry[3].Issuer = %q, want %q", e3.Issuer, "Issuu")
	}
	if e3.Name != "James" {
		t.Errorf("entry[3].Name = %q, want %q", e3.Name, "James")
	}
	if e3.Type != "hotp" {
		t.Errorf("entry[3].Type = %q, want %q", e3.Type, "hotp")
	}
	if e3.Counter != 1 {
		t.Errorf("entry[3].Counter = %d, want 1", e3.Counter)
	}

	// Verify HOTP[4]: Air Canada / Benjamin
	e4 := entries[4]
	if e4.Issuer != "Air Canada" {
		t.Errorf("entry[4].Issuer = %q, want %q", e4.Issuer, "Air Canada")
	}
	if e4.Name != "Benjamin" {
		t.Errorf("entry[4].Name = %q, want %q", e4.Name, "Benjamin")
	}
	if e4.Type != "hotp" {
		t.Errorf("entry[4].Type = %q, want %q", e4.Type, "hotp")
	}
	if e4.Counter != 50 {
		t.Errorf("entry[4].Counter = %d, want 50", e4.Counter)
	}
	if e4.Digits != 7 {
		t.Errorf("entry[4].Digits = %d, want 7", e4.Digits)
	}
	if e4.Algo != "SHA256" {
		t.Errorf("entry[4].Algo = %q, want %q", e4.Algo, "SHA256")
	}

	// Verify HOTP[5]: WWE / Mason
	e5 := entries[5]
	if e5.Issuer != "WWE" {
		t.Errorf("entry[5].Issuer = %q, want %q", e5.Issuer, "WWE")
	}
	if e5.Name != "Mason" {
		t.Errorf("entry[5].Name = %q, want %q", e5.Name, "Mason")
	}
	if e5.Type != "hotp" {
		t.Errorf("entry[5].Type = %q, want %q", e5.Type, "hotp")
	}
	if e5.Counter != 10300 {
		t.Errorf("entry[5].Counter = %d, want 10300", e5.Counter)
	}
	if e5.Digits != 8 {
		t.Errorf("entry[5].Digits = %d, want 8", e5.Digits)
	}
	if e5.Algo != "SHA512" {
		t.Errorf("entry[5].Algo = %q, want %q", e5.Algo, "SHA512")
	}

	// Verify Steam[6]: Boeing / Sophia
	e6 := entries[6]
	if e6.Issuer != "Boeing" {
		t.Errorf("entry[6].Issuer = %q, want %q", e6.Issuer, "Boeing")
	}
	if e6.Name != "Sophia" {
		t.Errorf("entry[6].Name = %q, want %q", e6.Name, "Sophia")
	}
	if e6.Type != "steam" {
		t.Errorf("entry[6].Type = %q, want %q", e6.Type, "steam")
	}
	if e6.Algo != "SHA1" {
		t.Errorf("entry[6].Algo = %q, want %q", e6.Algo, "SHA1")
	}
	if e6.Digits != 5 {
		t.Errorf("entry[6].Digits = %d, want 5", e6.Digits)
	}
	if e6.Period != 30 {
		t.Errorf("entry[6].Period = %d, want 30", e6.Period)
	}
}

// TestAndOTPParser_Parse_IssuerFallback verifies the label-split issuer fallback logic:
// when the issuer field is absent, split label on " - " to extract issuer and name.
func TestAndOTPParser_Parse_IssuerFallback(t *testing.T) {
	// Two entries with NO issuer field -- fallback must split label on " - "
	input := `[
		{"secret":"AAAA","type":"TOTP","algorithm":"SHA1","digits":6,"period":30,"label":"GitHub - user@example.com"},
		{"secret":"BBBB","type":"TOTP","algorithm":"SHA1","digits":6,"period":30,"label":"JustALabel"}
	]`

	p := &AndOTPParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("Parse() returned %d entries, want 2", len(entries))
	}

	// entry[0]: label has " - " separator -> split
	e0 := entries[0]
	if e0.Issuer != "GitHub" {
		t.Errorf("entry[0].Issuer = %q, want %q", e0.Issuer, "GitHub")
	}
	if e0.Name != "user@example.com" {
		t.Errorf("entry[0].Name = %q, want %q", e0.Name, "user@example.com")
	}

	// entry[1]: label has no " - " separator -> name=label, issuer=""
	e1 := entries[1]
	if e1.Issuer != "" {
		t.Errorf("entry[1].Issuer = %q, want %q (empty)", e1.Issuer, "")
	}
	if e1.Name != "JustALabel" {
		t.Errorf("entry[1].Name = %q, want %q", e1.Name, "JustALabel")
	}
}

// TestAndOTPParser_Parse_SkipsUnsupportedTypes verifies that unknown types (MOTP, YANDEX, etc.)
// are silently skipped, returning 0 entries with no error.
func TestAndOTPParser_Parse_SkipsUnsupportedTypes(t *testing.T) {
	input := `[{"secret":"AAAA","type":"MOTP","algorithm":"SHA1","digits":6,"period":30,"label":"Test","issuer":"Foo"}]`

	p := &AndOTPParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Parse() returned %d entries, want 0 (MOTP should be skipped)", len(entries))
	}
}

// TestAndOTPParser_Parse_EmptyArray verifies that an empty JSON array returns a non-nil
// empty slice with no error.
func TestAndOTPParser_Parse_EmptyArray(t *testing.T) {
	p := &AndOTPParser{}
	entries, err := p.Parse([]byte(`[]`), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error for empty array: %v", err)
	}
	if entries == nil {
		t.Error("Parse() returned nil entries, want non-nil empty slice")
	}
	if len(entries) != 0 {
		t.Errorf("Parse() returned %d entries, want 0", len(entries))
	}
}

// TestAndOTPParser_Parse_MalformedJSON verifies that malformed JSON returns an error
// containing "malformed".
func TestAndOTPParser_Parse_MalformedJSON(t *testing.T) {
	p := &AndOTPParser{}
	entries, err := p.Parse([]byte(`{not valid json`), "")
	if err == nil {
		t.Fatal("Parse() returned nil error for malformed JSON, want non-nil error")
	}
	if !strings.Contains(err.Error(), "malformed") {
		t.Errorf("error %q does not contain 'malformed'", err.Error())
	}
	_ = entries
}

// TestImport_AndOTP_Dispatcher verifies that parser.Import routes andOTP data through
// the registry to AndOTPParser (end-to-end dispatcher integration test).
func TestImport_AndOTP_Dispatcher(t *testing.T) {
	data, err := os.ReadFile("testdata/andotp_plain.json")
	if err != nil {
		t.Fatalf("failed to read andOTP fixture: %v", err)
	}

	entries, _, err := Import(data, "")
	if err != nil {
		t.Fatalf("Import() returned unexpected error: %v", err)
	}
	if len(entries) != 7 {
		t.Fatalf("Import() returned %d entries, want 7 (proves dispatcher routes to AndOTPParser)", len(entries))
	}
}
