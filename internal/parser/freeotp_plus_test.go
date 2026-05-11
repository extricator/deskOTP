// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"os"
	"testing"
)

// TestSignedBytesToBase32 verifies the signedBytesToBase32 conversion with a known
// test vector from research. The expected output matches the andOTP plaintext secret
// for the same account (Deno/Mason), confirming the conversion is correct.
//
// Input:  [-28,-110,112,-16,-46,31,54,92,-124,8,-8,-76,117,-59,38,124]
// Output: "4SJHB4GSD43FZBAI7C2HLRJGPQ" (no padding — trimmed for consistency)
func TestSignedBytesToBase32(t *testing.T) {
	input := []int{-28, -110, 112, -16, -46, 31, 54, 92, -124, 8, -8, -76, 117, -59, 38, 124}
	want := "4SJHB4GSD43FZBAI7C2HLRJGPQ"
	got := signedBytesToBase32(input)
	if got != want {
		t.Errorf("signedBytesToBase32() = %q, want %q", got, want)
	}
}

// TestSignedBytesToBase32_Empty verifies empty input returns empty string.
func TestSignedBytesToBase32_Empty(t *testing.T) {
	got := signedBytesToBase32([]int{})
	if got != "" {
		t.Errorf("signedBytesToBase32(empty) = %q, want %q", got, "")
	}
}

// TestSignedBytesToBase32_NoPadding verifies the conversion always strips trailing '=' padding.
func TestSignedBytesToBase32_NoPadding(t *testing.T) {
	// Any single-byte input will have padding in standard Base32 encoding.
	got := signedBytesToBase32([]int{0})
	for _, ch := range got {
		if ch == '=' {
			t.Errorf("signedBytesToBase32() result %q contains '=' padding, want no padding", got)
			break
		}
	}
}

// TestFreeOTPPlusParser_Name verifies Name() returns "FreeOTP+".
func TestFreeOTPPlusParser_Name(t *testing.T) {
	p := &FreeOTPPlusParser{}
	if got := p.Name(); got != "FreeOTP+" {
		t.Errorf("Name() = %q, want %q", got, "FreeOTP+")
	}
}

// TestFreeOTPPlusParser_CanParse verifies CanParse accepts only FreeOTP+ JSON backups
// (root-level JSON object with a "tokens" array) and rejects other formats.
func TestFreeOTPPlusParser_CanParse(t *testing.T) {
	freeotp_fixture, err := os.ReadFile("testdata/freeotp_plus.json")
	if err != nil {
		t.Fatalf("failed to read FreeOTP+ fixture: %v", err)
	}
	aegisFixture, err := os.ReadFile("testdata/aegis_plain.json")
	if err != nil {
		t.Fatalf("failed to read Aegis plain fixture: %v", err)
	}
	stratumFixture, err := os.ReadFile("testdata/stratum_plain.json")
	if err != nil {
		t.Fatalf("failed to read Stratum fixture: %v", err)
	}

	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "FreeOTP+ fixture (real file)",
			input: freeotp_fixture,
			want:  true,
		},
		{
			name:  "minimal FreeOTP+ JSON with tokens array",
			input: []byte(`{"tokens":[]}`),
			want:  true,
		},
		{
			name:  "Aegis plain vault",
			input: aegisFixture,
			want:  false,
		},
		{
			name:  "Stratum plain backup",
			input: stratumFixture,
			want:  false,
		},
		{
			name:  "2FAS backup (schemaVersion)",
			input: []byte(`{"schemaVersion":4,"services":[]}`),
			want:  false,
		},
		{
			name:  "andOTP root array",
			input: []byte(`[{"secret":"AAAA","type":"TOTP","algorithm":"SHA1","digits":6,"period":30,"label":"Test"}]`),
			want:  false,
		},
		{
			name:  "random JSON object without tokens",
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

	p := &FreeOTPPlusParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(tt.input)
			if got != tt.want {
				t.Errorf("CanParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestFreeOTPPlusParser_Parse_Fixture parses the real FreeOTP+ fixture (6 entries:
// 3 TOTP, 3 HOTP) and verifies field mapping is correct for all entry types.
func TestFreeOTPPlusParser_Parse_Fixture(t *testing.T) {
	data, err := os.ReadFile("testdata/freeotp_plus.json")
	if err != nil {
		t.Fatalf("failed to read FreeOTP+ fixture: %v", err)
	}

	p := &FreeOTPPlusParser{}
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

	// Verify no secrets contain '=' padding.
	for i, e := range entries {
		for _, ch := range e.Secret {
			if ch == '=' {
				t.Errorf("entries[%d].Secret = %q contains '=' padding, want no padding", i, e.Secret)
				break
			}
		}
	}
}

// TestFreeOTPPlusParser_Parse_SecretConversion verifies signed byte array secrets are
// correctly converted to Base32 strings without padding.
// The Deno/Mason entry in the fixture has secret [-28,-110,112,...] = "4SJHB4GSD43FZBAI7C2HLRJGPQ".
func TestFreeOTPPlusParser_Parse_SecretConversion(t *testing.T) {
	data, err := os.ReadFile("testdata/freeotp_plus.json")
	if err != nil {
		t.Fatalf("failed to read FreeOTP+ fixture: %v", err)
	}

	p := &FreeOTPPlusParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}

	// Find Deno/Mason TOTP entry and verify its secret conversion.
	var found bool
	for _, e := range entries {
		if e.Issuer == "Deno" && e.Name == "Mason" {
			found = true
			if e.Secret != "4SJHB4GSD43FZBAI7C2HLRJGPQ" {
				t.Errorf("Deno/Mason Secret = %q, want %q (known test vector)", e.Secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ")
			}
			if e.Type != "totp" {
				t.Errorf("Deno/Mason Type = %q, want %q", e.Type, "totp")
			}
			if e.Algo != "SHA1" {
				t.Errorf("Deno/Mason Algo = %q, want %q", e.Algo, "SHA1")
			}
			if e.Digits != 6 {
				t.Errorf("Deno/Mason Digits = %d, want 6", e.Digits)
			}
			if e.Period != 30 {
				t.Errorf("Deno/Mason Period = %d, want 30", e.Period)
			}
			break
		}
	}
	if !found {
		t.Error("did not find Deno/Mason entry in parsed entries")
	}
}

// TestFreeOTPPlusParser_Parse_FieldMapping verifies issuerExt->Issuer and label->Name mapping.
func TestFreeOTPPlusParser_Parse_FieldMapping(t *testing.T) {
	// Inline fixture with explicit field values
	input := `{"tokens":[
		{"algo":"SHA256","counter":0,"digits":7,"issuerExt":"TestIssuer","issuerInt":"TestIssuer","label":"TestUser","period":20,"secret":[0,0,0,0],"type":"TOTP"}
	]}`

	p := &FreeOTPPlusParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(entries))
	}

	e := entries[0]
	if e.Issuer != "TestIssuer" {
		t.Errorf("Issuer = %q, want %q (issuerExt maps to Issuer)", e.Issuer, "TestIssuer")
	}
	if e.Name != "TestUser" {
		t.Errorf("Name = %q, want %q (label maps to Name)", e.Name, "TestUser")
	}
	if e.Algo != "SHA256" {
		t.Errorf("Algo = %q, want %q", e.Algo, "SHA256")
	}
	if e.Digits != 7 {
		t.Errorf("Digits = %d, want 7", e.Digits)
	}
	if e.Period != 20 {
		t.Errorf("Period = %d, want 20", e.Period)
	}
	if e.Type != "totp" {
		t.Errorf("Type = %q, want %q (TOTP->totp)", e.Type, "totp")
	}
}

// TestFreeOTPPlusParser_Parse_HOTPHandling verifies HOTP entries have Period=0 and
// correct Counter from the "counter" field.
func TestFreeOTPPlusParser_Parse_HOTPHandling(t *testing.T) {
	data, err := os.ReadFile("testdata/freeotp_plus.json")
	if err != nil {
		t.Fatalf("failed to read FreeOTP+ fixture: %v", err)
	}

	p := &FreeOTPPlusParser{}
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}

	// HOTP invariant: all HOTP entries must have Period=0
	for _, e := range entries {
		if e.Type == "hotp" && e.Period != 0 {
			t.Errorf("HOTP entry %q/%q: Period = %d, want 0", e.Issuer, e.Name, e.Period)
		}
	}

	// Spot-check specific HOTP entries from fixture:
	// WWE/Mason: counter=10299 (fixture value), HOTP
	// Air Canada/Benjamin: counter=49, HOTP
	// Issuu/James: counter=0, HOTP
	for _, e := range entries {
		switch {
		case e.Issuer == "WWE" && e.Name == "Mason":
			if e.Counter != 10299 {
				t.Errorf("WWE/Mason Counter = %d, want 10299", e.Counter)
			}
			if e.Type != "hotp" {
				t.Errorf("WWE/Mason Type = %q, want %q", e.Type, "hotp")
			}
		case e.Issuer == "Air Canada" && e.Name == "Benjamin":
			if e.Counter != 49 {
				t.Errorf("Air Canada/Benjamin Counter = %d, want 49", e.Counter)
			}
			if e.Type != "hotp" {
				t.Errorf("Air Canada/Benjamin Type = %q, want %q", e.Type, "hotp")
			}
		}
	}
}

// TestFreeOTPPlusParser_Parse_TOTPPeriodDefault verifies TOTP entries with period=0
// default to 30 seconds.
func TestFreeOTPPlusParser_Parse_TOTPPeriodDefault(t *testing.T) {
	input := `{"tokens":[
		{"algo":"SHA1","counter":0,"digits":6,"issuerExt":"Foo","issuerInt":"Foo","label":"Bar","period":0,"secret":[0,0,0,0],"type":"TOTP"}
	]}`

	p := &FreeOTPPlusParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(entries))
	}
	if entries[0].Period != 30 {
		t.Errorf("TOTP period=0 entry: Period = %d, want 30 (default)", entries[0].Period)
	}
}

// TestFreeOTPPlusParser_Parse_AlgoNormalization verifies algo strings are uppercased.
func TestFreeOTPPlusParser_Parse_AlgoNormalization(t *testing.T) {
	// FreeOTP+ always stores algo in uppercase, but verify normalization is applied.
	input := `{"tokens":[
		{"algo":"sha1","counter":0,"digits":6,"issuerExt":"Foo","issuerInt":"Foo","label":"Bar","period":30,"secret":[0,0,0,0],"type":"TOTP"},
		{"algo":"SHA256","counter":0,"digits":6,"issuerExt":"Baz","issuerInt":"Baz","label":"Qux","period":30,"secret":[0,0,0,0],"type":"TOTP"}
	]}`

	p := &FreeOTPPlusParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("Parse() returned %d entries, want 2", len(entries))
	}
	if entries[0].Algo != "SHA1" {
		t.Errorf("entries[0].Algo = %q, want %q (lowercased algo must be uppercased)", entries[0].Algo, "SHA1")
	}
	if entries[1].Algo != "SHA256" {
		t.Errorf("entries[1].Algo = %q, want %q", entries[1].Algo, "SHA256")
	}
}
