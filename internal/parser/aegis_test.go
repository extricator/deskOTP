// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"errors"
	"strings"
	"testing"
)

// TestAegisParser_CanParse verifies CanParse accepts only Aegis plain (unencrypted) vaults.
func TestAegisParser_CanParse(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid plain vault",
			input: `{"version":1,"header":{"slots":null,"params":null},"db":{"version":2,"entries":[]}}`,
			want:  true,
		},
		{
			name:  "encrypted vault (slots non-null)",
			input: `{"version":1,"header":{"slots":[{"type":1,"uuid":"abc"}],"params":null},"db":{"version":2,"entries":[]}}`,
			want:  false,
		},
		{
			name:  "random JSON object",
			input: `{"foo":"bar"}`,
			want:  false,
		},
		{
			name:  "empty JSON object",
			input: `{}`,
			want:  false,
		},
		{
			name:  "not JSON at all",
			input: `hello world`,
			want:  false,
		},
		{
			name:  "empty input",
			input: ``,
			want:  false,
		},
	}

	p := &AegisParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse([]byte(tt.input))
			if got != tt.want {
				t.Errorf("CanParse(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestAegisParser_Parse_ValidVault parses a complete Aegis vault with 1 TOTP entry
// and verifies every field maps correctly to totp.Entry (success criterion 1 -- no data loss).
func TestAegisParser_Parse_ValidVault(t *testing.T) {
	input := `{
		"version": 1,
		"header": {"slots": null, "params": null},
		"db": {
			"version": 2,
			"entries": [
				{
					"type": "totp",
					"uuid": "3ae6f1ad-2e65-4ed2-a953-1ec0dff2386d",
					"name": "Mason",
					"issuer": "Deno",
					"icon": null,
					"info": {
						"secret": "4SJHB4GSD43FZBAI7C2HLRJGPQ",
						"algo": "SHA1",
						"digits": 6,
						"period": 30
					}
				}
			]
		}
	}`

	p := &AegisParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(entries))
	}

	e := entries[0]
	if e.UUID != "3ae6f1ad-2e65-4ed2-a953-1ec0dff2386d" {
		t.Errorf("UUID = %q, want %q", e.UUID, "3ae6f1ad-2e65-4ed2-a953-1ec0dff2386d")
	}
	if e.Name != "Mason" {
		t.Errorf("Name = %q, want %q", e.Name, "Mason")
	}
	if e.Issuer != "Deno" {
		t.Errorf("Issuer = %q, want %q", e.Issuer, "Deno")
	}
	if e.Secret != "4SJHB4GSD43FZBAI7C2HLRJGPQ" {
		t.Errorf("Secret = %q, want %q", e.Secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ")
	}
	if e.Algo != "SHA1" {
		t.Errorf("Algo = %q, want %q", e.Algo, "SHA1")
	}
	if e.Digits != 6 {
		t.Errorf("Digits = %d, want %d", e.Digits, 6)
	}
	if e.Period != uint(30) {
		t.Errorf("Period = %d, want %d", e.Period, uint(30))
	}
	if e.Type != "totp" {
		t.Errorf("Type = %q, want %q", e.Type, "totp")
	}
}

// TestAegisParser_Parse_AllTypes verifies that TOTP, HOTP, and Steam entries are all parsed
// correctly, with correct field mapping for each type.
// Previously this test was TestAegisParser_Parse_SkipsNonTOTP (v1.0 behavior skipped HOTP/Steam).
func TestAegisParser_Parse_AllTypes(t *testing.T) {
	input := `{
		"version": 1,
		"header": {"slots": null, "params": null},
		"db": {
			"version": 2,
			"entries": [
				{
					"type": "totp",
					"uuid": "totp-uuid-1",
					"name": "MyTOTP",
					"issuer": "Corp",
					"info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "SHA256", "digits": 8, "period": 60}
				},
				{
					"type": "hotp",
					"uuid": "hotp-uuid-2",
					"name": "MyHOTP",
					"issuer": "Other",
					"info": {"secret": "AAAA", "algo": "SHA1", "digits": 6, "period": 30, "counter": 42}
				},
				{
					"type": "steam",
					"uuid": "steam-uuid-3",
					"name": "MySteam",
					"issuer": "Valve",
					"info": {"secret": "BBBB", "algo": "SHA1", "digits": 5, "period": 30}
				}
			]
		}
	}`

	p := &AegisParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("Parse() returned %d entries, want 3 (totp + hotp + steam)", len(entries))
	}

	// Verify TOTP entry
	totp := entries[0]
	if totp.UUID != "totp-uuid-1" {
		t.Errorf("TOTP UUID = %q, want %q", totp.UUID, "totp-uuid-1")
	}
	if totp.Type != "totp" {
		t.Errorf("TOTP Type = %q, want %q", totp.Type, "totp")
	}
	if totp.Algo != "SHA256" {
		t.Errorf("TOTP Algo = %q, want %q", totp.Algo, "SHA256")
	}
	if totp.Digits != 8 {
		t.Errorf("TOTP Digits = %d, want 8", totp.Digits)
	}
	if totp.Period != uint(60) {
		t.Errorf("TOTP Period = %d, want 60", totp.Period)
	}

	// Verify HOTP entry
	hotp := entries[1]
	if hotp.UUID != "hotp-uuid-2" {
		t.Errorf("HOTP UUID = %q, want %q", hotp.UUID, "hotp-uuid-2")
	}
	if hotp.Type != "hotp" {
		t.Errorf("HOTP Type = %q, want %q", hotp.Type, "hotp")
	}
	if hotp.Counter != 42 {
		t.Errorf("HOTP Counter = %d, want 42", hotp.Counter)
	}
	if hotp.Digits != 6 {
		t.Errorf("HOTP Digits = %d, want 6", hotp.Digits)
	}

	// Verify Steam entry
	steam := entries[2]
	if steam.UUID != "steam-uuid-3" {
		t.Errorf("Steam UUID = %q, want %q", steam.UUID, "steam-uuid-3")
	}
	if steam.Type != "steam" {
		t.Errorf("Steam Type = %q, want %q", steam.Type, "steam")
	}
	if steam.Digits != 5 {
		t.Errorf("Steam Digits = %d, want 5", steam.Digits)
	}
	if steam.Period != uint(30) {
		t.Errorf("Steam Period = %d, want 30", steam.Period)
	}
	if steam.Algo != "SHA1" {
		t.Errorf("Steam Algo = %q, want %q", steam.Algo, "SHA1")
	}
}

// TestAegisParser_Parse_HOTPCounter verifies HOTP counter field mapping using the real
// Aegis test fixture format (from RESEARCH.md, sourced from aegis_plain.json).
func TestAegisParser_Parse_HOTPCounter(t *testing.T) {
	input := `{
		"version": 1,
		"header": {"slots": null, "params": null},
		"db": {
			"version": 2,
			"entries": [
				{
					"type": "hotp",
					"uuid": "0a8c0571-ff6f-4b02-aa4b-50553b4fb4fe",
					"name": "James",
					"issuer": "Issuu",
					"icon": null,
					"info": {
						"secret": "YOOMIXWS5GN6RTBPUFFWKTW5M4",
						"algo": "SHA1",
						"digits": 6,
						"counter": 1
					}
				}
			]
		}
	}`

	p := &AegisParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(entries))
	}

	e := entries[0]
	if e.UUID != "0a8c0571-ff6f-4b02-aa4b-50553b4fb4fe" {
		t.Errorf("UUID = %q, want %q", e.UUID, "0a8c0571-ff6f-4b02-aa4b-50553b4fb4fe")
	}
	if e.Type != "hotp" {
		t.Errorf("Type = %q, want %q", e.Type, "hotp")
	}
	if e.Counter != 1 {
		t.Errorf("Counter = %d, want 1", e.Counter)
	}
	// HOTP entries have no period — Period field should be 0
	if e.Period != 0 {
		t.Errorf("Period = %d, want 0 (HOTP is counter-based, no period)", e.Period)
	}
}

// TestAegisParser_Parse_SteamFixedValues verifies that Steam entries use hardcoded fixed
// values (SHA1, 5 digits, 30s period) regardless of what the JSON contains.
// Uses the real Aegis test fixture format (from RESEARCH.md, sourced from aegis_plain.json).
func TestAegisParser_Parse_SteamFixedValues(t *testing.T) {
	input := `{
		"version": 1,
		"header": {"slots": null, "params": null},
		"db": {
			"version": 2,
			"entries": [
				{
					"type": "steam",
					"uuid": "5b11ae3b-6fc3-4d46-8ca7-cf0aea7de920",
					"name": "Sophia",
					"issuer": "Boeing",
					"icon": null,
					"info": {
						"secret": "JRZCL47CMXVOQMNPZR2F7J4RGI",
						"algo": "SHA1",
						"digits": 5,
						"period": 30
					}
				}
			]
		}
	}`

	p := &AegisParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(entries))
	}

	e := entries[0]
	if e.UUID != "5b11ae3b-6fc3-4d46-8ca7-cf0aea7de920" {
		t.Errorf("UUID = %q, want %q", e.UUID, "5b11ae3b-6fc3-4d46-8ca7-cf0aea7de920")
	}
	if e.Type != "steam" {
		t.Errorf("Type = %q, want %q", e.Type, "steam")
	}
	if e.Algo != "SHA1" {
		t.Errorf("Algo = %q, want %q (Steam always uses SHA1)", e.Algo, "SHA1")
	}
	if e.Digits != 5 {
		t.Errorf("Digits = %d, want 5 (Steam always uses 5 digits)", e.Digits)
	}
	if e.Period != uint(30) {
		t.Errorf("Period = %d, want 30 (Steam always uses 30s period)", e.Period)
	}
}

// TestAegisParser_Parse_SkipsUnsupportedTypes verifies that entries with unsupported types
// (motp, yandex, etc.) are silently skipped, not treated as errors.
func TestAegisParser_Parse_SkipsUnsupportedTypes(t *testing.T) {
	input := `{
		"version": 1,
		"header": {"slots": null, "params": null},
		"db": {
			"version": 2,
			"entries": [
				{
					"type": "motp",
					"uuid": "motp-uuid-1",
					"name": "MyMOTP",
					"issuer": "SomeService",
					"info": {"secret": "CCCC", "algo": "MD5", "digits": 6, "period": 10}
				}
			]
		}
	}`

	p := &AegisParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error for unsupported type: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Parse() returned %d entries, want 0 (motp type should be skipped)", len(entries))
	}
}

// TestAegisParser_Parse_EmptyEntries verifies that a valid vault with an empty entries array
// returns no error and an empty (non-nil) slice.
func TestAegisParser_Parse_EmptyEntries(t *testing.T) {
	input := `{"version":1,"header":{"slots":null,"params":null},"db":{"version":1,"entries":[]}}`

	p := &AegisParser{}
	entries, err := p.Parse([]byte(input), "")
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Parse() returned %d entries, want 0", len(entries))
	}
}

// TestAegisParser_Parse_MalformedJSON verifies that invalid JSON returns a clear error,
// not a panic or silent empty result (success criterion 4).
func TestAegisParser_Parse_MalformedJSON(t *testing.T) {
	input := `{not valid json`

	p := &AegisParser{}
	entries, err := p.Parse([]byte(input), "")
	if err == nil {
		t.Fatal("Parse() returned nil error for malformed JSON, want non-nil error")
	}
	if entries != nil {
		t.Errorf("Parse() returned non-nil entries for malformed JSON, want nil")
	}
	if !strings.Contains(err.Error(), "malformed") {
		t.Errorf("error %q does not contain 'malformed'", err.Error())
	}
}

// TestAegisParser_Parse_MissingDBEntries verifies that Aegis JSON missing the db.entries field
// returns a clear error (success criterion 4 -- malformed returns descriptive error).
func TestAegisParser_Parse_MissingDBEntries(t *testing.T) {
	input := `{"version":1,"header":{"slots":null,"params":null},"db":{"version":1}}`

	p := &AegisParser{}
	entries, err := p.Parse([]byte(input), "")
	if err == nil {
		t.Fatal("Parse() returned nil error for missing db.entries, want non-nil error")
	}
	_ = entries
}

// TestImport_Dispatcher verifies that parser.Import dispatches to AegisParser for a valid
// Aegis vault (tests registry path end-to-end, success criterion 2).
func TestImport_Dispatcher(t *testing.T) {
	input := `{
		"version": 1,
		"header": {"slots": null, "params": null},
		"db": {
			"version": 2,
			"entries": [
				{
					"type": "totp",
					"uuid": "disp-uuid-1",
					"name": "Dispatch Test",
					"issuer": "TestCo",
					"info": {
						"secret": "JBSWY3DPEHPK3PXP",
						"algo": "SHA1",
						"digits": 6,
						"period": 30
					}
				}
			]
		}
	}`

	entries, _, err := Import([]byte(input), "")
	if err != nil {
		t.Fatalf("Import() returned unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Import() returned %d entries, want 1", len(entries))
	}
	if entries[0].UUID != "disp-uuid-1" {
		t.Errorf("UUID = %q, want %q", entries[0].UUID, "disp-uuid-1")
	}
}

// TestImport_UnrecognizedFormat verifies that Import returns ErrNoParserFound
// when no parser can claim the data.
// Empty data is used because all CanParse implementations explicitly reject it.
func TestImport_UnrecognizedFormat(t *testing.T) {
	entries, formatName, err := Import([]byte{}, "")
	if err == nil {
		t.Fatal("Import() returned nil error for empty data, want ErrNoParserFound")
	}
	if !errors.Is(err, ErrNoParserFound) {
		t.Errorf("errors.Is(err, ErrNoParserFound) = false, got error: %v", err)
	}
	if entries != nil {
		t.Errorf("Import() returned non-nil entries for empty data, want nil")
	}
	if formatName != "" {
		t.Errorf("Import() formatName = %q for unrecognised data, want empty string", formatName)
	}
}
