// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"os"
	"strings"
	"testing"
)

// TestTwoFASParser_CanParse verifies CanParse accepts 2FAS files and rejects all other formats.
func TestTwoFASParser_CanParse(t *testing.T) {
	v1data, err := os.ReadFile("testdata/2fas_schema_v1.json")
	if err != nil {
		t.Fatalf("failed to read v1 fixture: %v", err)
	}
	v2data, err := os.ReadFile("testdata/2fas_schema_v2.json")
	if err != nil {
		t.Fatalf("failed to read v2 fixture: %v", err)
	}
	v3data, err := os.ReadFile("testdata/2fas_schema_v3.json")
	if err != nil {
		t.Fatalf("failed to read v3 fixture: %v", err)
	}
	v4data, err := os.ReadFile("testdata/2fas_schema_v4.2fas")
	if err != nil {
		t.Fatalf("failed to read v4 fixture: %v", err)
	}

	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "2FAS schema v1 fixture",
			input: v1data,
			want:  true,
		},
		{
			name:  "2FAS schema v2 fixture",
			input: v2data,
			want:  true,
		},
		{
			name:  "2FAS schema v3 fixture",
			input: v3data,
			want:  true,
		},
		{
			name:  "2FAS schema v4 fixture",
			input: v4data,
			want:  true,
		},
		{
			name:  "Aegis plain vault",
			input: []byte(`{"version":1,"header":{"slots":null,"params":null},"db":{"version":2,"entries":[]}}`),
			want:  false,
		},
		{
			name:  "andOTP format (root array)",
			input: []byte(`[{"secret":"X","type":"TOTP"}]`),
			want:  false,
		},
		{
			name:  "random JSON object",
			input: []byte(`{"foo":"bar"}`),
			want:  false,
		},
		{
			name:  "services present but schemaVersion missing",
			input: []byte(`{"services":[]}`),
			want:  false, // schemaVersion defaults to 0, which is < 1
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

	p := &TwoFASParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(tt.input)
			if got != tt.want {
				t.Errorf("CanParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestTwoFASParser_Parse_V1 verifies schema v1 parsing: all TOTP, no tokenType, defaults applied.
func TestTwoFASParser_Parse_V1(t *testing.T) {
	data, err := os.ReadFile("testdata/2fas_schema_v1.json")
	if err != nil {
		t.Fatalf("failed to read v1 fixture: %v", err)
	}

	p := &TwoFASParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 6 {
		t.Fatalf("Parse() returned %d entries, want 6", len(entries))
	}

	// All entries must be TOTP (tokenType absent in v1 — defaults to TOTP)
	for i, e := range entries {
		if e.Type != "totp" {
			t.Errorf("entries[%d].Type = %q, want %q (tokenType absent should default to TOTP)", i, e.Type, "totp")
		}
	}

	// Verify entry[0]: Deno/Mason
	e0 := entries[0]
	if e0.Issuer != "Deno" {
		t.Errorf("entries[0].Issuer = %q, want %q", e0.Issuer, "Deno")
	}
	if e0.Name != "Mason" {
		t.Errorf("entries[0].Name = %q, want %q", e0.Name, "Mason")
	}
	if e0.Secret != "4SJHB4GSD43FZBAI7C2HLRJGPQ" {
		t.Errorf("entries[0].Secret = %q, want %q", e0.Secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ")
	}
	// 2FAS parsers must generate synthetic UUIDs — every entry needs a non-empty UUID v4.
	if e0.UUID == "" {
		t.Error("entries[0].UUID = \"\", want non-empty synthetic UUID (prevents copiedId collision)")
	}
	if len(e0.UUID) != 36 {
		t.Errorf("entries[0].UUID len = %d, want 36 (UUID v4 format)", len(e0.UUID))
	}

	// All UUIDs within the parse call must be unique.
	seen := make(map[string]int, len(entries))
	for i, e := range entries {
		if e.UUID == "" {
			t.Errorf("entries[%d].UUID = \"\", want non-empty synthetic UUID", i)
			continue
		}
		if prev, dup := seen[e.UUID]; dup {
			t.Errorf("entries[%d].UUID = %q collides with entries[%d] (UUIDs must be unique)", i, e.UUID, prev)
		}
		seen[e.UUID] = i
	}

	// v1 has no digits/period/algorithm in otp block — defaults must be applied
	if e0.Algo != "SHA1" {
		t.Errorf("entries[0].Algo = %q, want %q (default)", e0.Algo, "SHA1")
	}
	if e0.Digits != 6 {
		t.Errorf("entries[0].Digits = %d, want %d (default)", e0.Digits, 6)
	}
	if e0.Period != uint(30) {
		t.Errorf("entries[0].Period = %d, want %d (default)", e0.Period, uint(30))
	}
}

// TestTwoFASParser_Parse_V2 verifies schema v2 parsing: all TOTP (no tokenType), explicit digits/period/algorithm.
// Real Aegis fixture: 4 services with varying OTP parameters, some missing period field.
func TestTwoFASParser_Parse_V2(t *testing.T) {
	data, err := os.ReadFile("testdata/2fas_schema_v2.json")
	if err != nil {
		t.Fatalf("failed to read v2 fixture: %v", err)
	}

	p := &TwoFASParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("Parse() returned %d entries, want 4", len(entries))
	}

	// All entries must be TOTP (tokenType absent in v2 — defaults to TOTP)
	for i, e := range entries {
		if e.Type != "totp" {
			t.Errorf("entries[%d].Type = %q, want %q", i, e.Type, "totp")
		}
	}

	// entries[0]: Deno/Mason — standard SHA1/6/30
	e0 := entries[0]
	if e0.Issuer != "Deno" {
		t.Errorf("entries[0].Issuer = %q, want %q", e0.Issuer, "Deno")
	}
	if e0.Name != "Mason" {
		t.Errorf("entries[0].Name = %q, want %q", e0.Name, "Mason")
	}
	if e0.Algo != "SHA1" {
		t.Errorf("entries[0].Algo = %q, want %q", e0.Algo, "SHA1")
	}
	if e0.Digits != 6 {
		t.Errorf("entries[0].Digits = %d, want 6", e0.Digits)
	}
	if e0.Period != 30 {
		t.Errorf("entries[0].Period = %d, want 30", e0.Period)
	}

	// entries[1]: Airbnb/Elijah — non-default SHA512/8/50
	e1 := entries[1]
	if e1.Issuer != "Airbnb" {
		t.Errorf("entries[1].Issuer = %q, want %q", e1.Issuer, "Airbnb")
	}
	if e1.Algo != "SHA512" {
		t.Errorf("entries[1].Algo = %q, want %q", e1.Algo, "SHA512")
	}
	if e1.Digits != 8 {
		t.Errorf("entries[1].Digits = %d, want 8", e1.Digits)
	}
	if e1.Period != 50 {
		t.Errorf("entries[1].Period = %d, want 50", e1.Period)
	}

	// entries[2]: Issuu/James — period absent in fixture, should default to 30
	e2 := entries[2]
	if e2.Issuer != "Issuu" {
		t.Errorf("entries[2].Issuer = %q, want %q", e2.Issuer, "Issuu")
	}
	if e2.Period != 30 {
		t.Errorf("entries[2].Period = %d, want 30 (default when absent)", e2.Period)
	}

	// entries[3]: WWE/Mason — non-default SHA512/8, period absent
	e3 := entries[3]
	if e3.Issuer != "WWE" {
		t.Errorf("entries[3].Issuer = %q, want %q", e3.Issuer, "WWE")
	}
	if e3.Algo != "SHA512" {
		t.Errorf("entries[3].Algo = %q, want %q", e3.Algo, "SHA512")
	}
	if e3.Digits != 8 {
		t.Errorf("entries[3].Digits = %d, want 8", e3.Digits)
	}
	if e3.Period != 30 {
		t.Errorf("entries[3].Period = %d, want 30 (default when absent)", e3.Period)
	}
}

// TestTwoFASParser_Parse_V3 verifies schema v3 parsing: introduces tokenType, mixed TOTP/HOTP.
// Real Aegis fixture: 6 services — 3 TOTP (Deno, SPDX, Airbnb) + 3 HOTP (Issuu, Air Canada, WWE).
func TestTwoFASParser_Parse_V3(t *testing.T) {
	data, err := os.ReadFile("testdata/2fas_schema_v3.json")
	if err != nil {
		t.Fatalf("failed to read v3 fixture: %v", err)
	}

	p := &TwoFASParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 6 {
		t.Fatalf("Parse() returned %d entries, want 6", len(entries))
	}

	// Count types
	var totpCount, hotpCount int
	for _, e := range entries {
		switch e.Type {
		case "totp":
			totpCount++
		case "hotp":
			hotpCount++
		}
	}
	if totpCount != 3 {
		t.Errorf("TOTP count = %d, want 3", totpCount)
	}
	if hotpCount != 3 {
		t.Errorf("HOTP count = %d, want 3", hotpCount)
	}

	// entries[0]: TOTP — Deno/Mason, SHA1/6/30
	if entries[0].Type != "totp" {
		t.Errorf("entries[0].Type = %q, want %q", entries[0].Type, "totp")
	}
	if entries[0].Issuer != "Deno" {
		t.Errorf("entries[0].Issuer = %q, want %q", entries[0].Issuer, "Deno")
	}
	if entries[0].Digits != 6 {
		t.Errorf("entries[0].Digits = %d, want 6", entries[0].Digits)
	}

	// entries[1]: TOTP — SPDX/James, SHA256/7/20 (non-default params)
	if entries[1].Type != "totp" {
		t.Errorf("entries[1].Type = %q, want %q", entries[1].Type, "totp")
	}
	if entries[1].Issuer != "SPDX" {
		t.Errorf("entries[1].Issuer = %q, want %q", entries[1].Issuer, "SPDX")
	}
	if entries[1].Algo != "SHA256" {
		t.Errorf("entries[1].Algo = %q, want %q", entries[1].Algo, "SHA256")
	}
	if entries[1].Digits != 7 {
		t.Errorf("entries[1].Digits = %d, want 7", entries[1].Digits)
	}
	if entries[1].Period != 20 {
		t.Errorf("entries[1].Period = %d, want 20", entries[1].Period)
	}

	// entries[2]: TOTP — Airbnb/Elijah, SHA512/8/50
	if entries[2].Type != "totp" {
		t.Errorf("entries[2].Type = %q, want %q", entries[2].Type, "totp")
	}
	if entries[2].Issuer != "Airbnb" {
		t.Errorf("entries[2].Issuer = %q, want %q", entries[2].Issuer, "Airbnb")
	}
	if entries[2].Algo != "SHA512" {
		t.Errorf("entries[2].Algo = %q, want %q", entries[2].Algo, "SHA512")
	}
	if entries[2].Digits != 8 {
		t.Errorf("entries[2].Digits = %d, want 8", entries[2].Digits)
	}
	if entries[2].Period != 50 {
		t.Errorf("entries[2].Period = %d, want 50", entries[2].Period)
	}

	// entries[3]: HOTP — Issuu/James, SHA1/6, counter=1
	if entries[3].Type != "hotp" {
		t.Errorf("entries[3].Type = %q, want %q", entries[3].Type, "hotp")
	}
	if entries[3].Issuer != "Issuu" {
		t.Errorf("entries[3].Issuer = %q, want %q", entries[3].Issuer, "Issuu")
	}
	if entries[3].Counter != 1 {
		t.Errorf("entries[3].Counter = %d, want 1", entries[3].Counter)
	}
	if entries[3].Period != 0 {
		t.Errorf("entries[3].Period = %d, want 0 (HOTP is counter-based)", entries[3].Period)
	}

	// entries[4]: HOTP — Air Canada/Benjamin, SHA256/7, counter=50
	if entries[4].Type != "hotp" {
		t.Errorf("entries[4].Type = %q, want %q", entries[4].Type, "hotp")
	}
	if entries[4].Issuer != "Air Canada" {
		t.Errorf("entries[4].Issuer = %q, want %q", entries[4].Issuer, "Air Canada")
	}
	if entries[4].Counter != 50 {
		t.Errorf("entries[4].Counter = %d, want 50", entries[4].Counter)
	}
	if entries[4].Algo != "SHA256" {
		t.Errorf("entries[4].Algo = %q, want %q", entries[4].Algo, "SHA256")
	}

	// entries[5]: HOTP — WWE/Mason, SHA512/8, counter=10300
	if entries[5].Type != "hotp" {
		t.Errorf("entries[5].Type = %q, want %q", entries[5].Type, "hotp")
	}
	if entries[5].Issuer != "WWE" {
		t.Errorf("entries[5].Issuer = %q, want %q", entries[5].Issuer, "WWE")
	}
	if entries[5].Counter != 10300 {
		t.Errorf("entries[5].Counter = %d, want 10300", entries[5].Counter)
	}
	if entries[5].Algo != "SHA512" {
		t.Errorf("entries[5].Algo = %q, want %q", entries[5].Algo, "SHA512")
	}
	if entries[5].Digits != 8 {
		t.Errorf("entries[5].Digits = %d, want 8", entries[5].Digits)
	}
}

// TestTwoFASParser_Parse_V4 verifies schema v4 parsing: mixed TOTP, HOTP, and Steam types.
func TestTwoFASParser_Parse_V4(t *testing.T) {
	data, err := os.ReadFile("testdata/2fas_schema_v4.2fas")
	if err != nil {
		t.Fatalf("failed to read v4 fixture: %v", err)
	}

	p := &TwoFASParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("Parse() returned %d entries, want 5", len(entries))
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
	if totpCount != 1 {
		t.Errorf("TOTP count = %d, want 1", totpCount)
	}
	if hotpCount != 3 {
		t.Errorf("HOTP count = %d, want 3", hotpCount)
	}
	if steamCount != 1 {
		t.Errorf("Steam count = %d, want 1", steamCount)
	}

	// All UUIDs within the v4 parse call must be non-empty and unique.
	seen := make(map[string]int, len(entries))
	for i, e := range entries {
		if e.UUID == "" {
			t.Errorf("entries[%d].UUID = \"\", want non-empty synthetic UUID", i)
			continue
		}
		if len(e.UUID) != 36 {
			t.Errorf("entries[%d].UUID len = %d, want 36 (UUID v4 format)", i, len(e.UUID))
		}
		if prev, dup := seen[e.UUID]; dup {
			t.Errorf("entries[%d].UUID = %q collides with entries[%d] (UUIDs must be unique)", i, e.UUID, prev)
		}
		seen[e.UUID] = i
	}

	// entries[0]: TOTP — Deno/Mason
	totp := entries[0]
	if totp.Issuer != "Deno" {
		t.Errorf("TOTP Issuer = %q, want %q", totp.Issuer, "Deno")
	}
	if totp.Name != "Mason" {
		t.Errorf("TOTP Name = %q, want %q", totp.Name, "Mason")
	}
	if totp.Type != "totp" {
		t.Errorf("TOTP Type = %q, want %q", totp.Type, "totp")
	}
	if totp.Algo != "SHA1" {
		t.Errorf("TOTP Algo = %q, want %q", totp.Algo, "SHA1")
	}
	if totp.Digits != 6 {
		t.Errorf("TOTP Digits = %d, want 6", totp.Digits)
	}
	if totp.Period != uint(30) {
		t.Errorf("TOTP Period = %d, want 30", totp.Period)
	}

	// entries[1]: HOTP — Issuu/James, counter=1
	hotp1 := entries[1]
	if hotp1.Issuer != "Issuu" {
		t.Errorf("HOTP[1] Issuer = %q, want %q", hotp1.Issuer, "Issuu")
	}
	if hotp1.Name != "James" {
		t.Errorf("HOTP[1] Name = %q, want %q", hotp1.Name, "James")
	}
	if hotp1.Type != "hotp" {
		t.Errorf("HOTP[1] Type = %q, want %q", hotp1.Type, "hotp")
	}
	if hotp1.Counter != 1 {
		t.Errorf("HOTP[1] Counter = %d, want 1", hotp1.Counter)
	}
	if hotp1.Digits != 6 {
		t.Errorf("HOTP[1] Digits = %d, want 6", hotp1.Digits)
	}
	// HOTP has no period (time-based)
	if hotp1.Period != 0 {
		t.Errorf("HOTP[1] Period = %d, want 0 (HOTP is counter-based)", hotp1.Period)
	}

	// entries[2]: HOTP — Air Canada/Benjamin, counter=50, digits=7, SHA256
	hotp2 := entries[2]
	if hotp2.Issuer != "Air Canada" {
		t.Errorf("HOTP[2] Issuer = %q, want %q", hotp2.Issuer, "Air Canada")
	}
	if hotp2.Name != "Benjamin" {
		t.Errorf("HOTP[2] Name = %q, want %q", hotp2.Name, "Benjamin")
	}
	if hotp2.Type != "hotp" {
		t.Errorf("HOTP[2] Type = %q, want %q", hotp2.Type, "hotp")
	}
	if hotp2.Counter != 50 {
		t.Errorf("HOTP[2] Counter = %d, want 50", hotp2.Counter)
	}
	if hotp2.Digits != 7 {
		t.Errorf("HOTP[2] Digits = %d, want 7", hotp2.Digits)
	}
	if hotp2.Algo != "SHA256" {
		t.Errorf("HOTP[2] Algo = %q, want %q", hotp2.Algo, "SHA256")
	}

	// entries[4]: Steam — Boeing/Sophia (last entry in fixture)
	steam := entries[4]
	if steam.Issuer != "Boeing" {
		t.Errorf("Steam Issuer = %q, want %q", steam.Issuer, "Boeing")
	}
	if steam.Name != "Sophia" {
		t.Errorf("Steam Name = %q, want %q", steam.Name, "Sophia")
	}
	if steam.Type != "steam" {
		t.Errorf("Steam Type = %q, want %q", steam.Type, "steam")
	}
	if steam.Algo != "SHA1" {
		t.Errorf("Steam Algo = %q, want %q (Steam always SHA1)", steam.Algo, "SHA1")
	}
	if steam.Digits != 5 {
		t.Errorf("Steam Digits = %d, want 5 (Steam always 5)", steam.Digits)
	}
	if steam.Period != uint(30) {
		t.Errorf("Steam Period = %d, want 30 (Steam always 30s)", steam.Period)
	}
}

// TestTwoFASParser_Parse_EmptyServices verifies empty services array returns empty non-nil slice.
func TestTwoFASParser_Parse_EmptyServices(t *testing.T) {
	input := []byte(`{"schemaVersion":4,"services":[]}`)

	p := &TwoFASParser{}
	entries, err := p.Parse(input, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if entries == nil {
		t.Fatal("Parse() returned nil slice, want non-nil empty slice")
	}
	if len(entries) != 0 {
		t.Errorf("Parse() returned %d entries, want 0", len(entries))
	}
}

// TestTwoFASParser_Parse_MalformedJSON verifies malformed JSON returns an error containing "malformed".
func TestTwoFASParser_Parse_MalformedJSON(t *testing.T) {
	input := []byte(`{not valid json`)

	p := &TwoFASParser{}
	entries, err := p.Parse(input, "")
	if err == nil {
		t.Fatal("Parse() returned nil error for malformed JSON, want non-nil error")
	}
	if !strings.Contains(err.Error(), "malformed") {
		t.Errorf("error %q does not contain 'malformed'", err.Error())
	}
	_ = entries
}

// TestTwoFASParser_Parse_IgnoresPassword verifies the password parameter is accepted but ignored.
func TestTwoFASParser_Parse_IgnoresPassword(t *testing.T) {
	data, err := os.ReadFile("testdata/2fas_schema_v1.json")
	if err != nil {
		t.Fatalf("failed to read v1 fixture: %v", err)
	}

	p := &TwoFASParser{}
	entriesNoPass, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse(empty password) returned error: %v", err)
	}
	entriesWithPass, err := p.Parse(data, "somepassword")
	if err != nil {
		t.Fatalf("Parse(somepassword) returned error: %v", err)
	}

	if len(entriesNoPass) != len(entriesWithPass) {
		t.Errorf("entry count differs: no-pass=%d, with-pass=%d", len(entriesNoPass), len(entriesWithPass))
	}
}

// TestImport_TwoFAS_Dispatcher verifies that parser.Import routes 2FAS data to TwoFASParser.
func TestImport_TwoFAS_Dispatcher(t *testing.T) {
	data, err := os.ReadFile("testdata/2fas_schema_v4.2fas")
	if err != nil {
		t.Fatalf("failed to read v4 fixture: %v", err)
	}

	entries, _, err := Import(data, "")
	if err != nil {
		t.Fatalf("Import() returned unexpected error: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("Import() returned %d entries, want 5 (proves dispatcher routes to TwoFASParser)", len(entries))
	}
}
