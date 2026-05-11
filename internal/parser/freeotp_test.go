// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"os"
	"testing"
)

func TestFreeOTP_Name(t *testing.T) {
	p := &FreeOTPParser{}
	if got := p.Name(); got != "FreeOTP" {
		t.Errorf("Name() = %q; want %q", got, "FreeOTP")
	}
}

func TestFreeOTP_CanParse(t *testing.T) {
	fixture, err := os.ReadFile("testdata/freeotp.xml")
	if err != nil {
		t.Fatalf("failed to read freeotp.xml: %v", err)
	}

	aegisJSON, err := os.ReadFile("testdata/aegis_plain.json")
	if err != nil {
		t.Fatalf("failed to read aegis_plain.json: %v", err)
	}

	plainTxt, err := os.ReadFile("testdata/plain.txt")
	if err != nil {
		t.Fatalf("failed to read plain.txt: %v", err)
	}

	p := &FreeOTPParser{}

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"freeotp.xml fixture", fixture, true},
		{"empty data", []byte{}, false},
		{"JSON data (aegis_plain.json)", aegisJSON, false},
		{"text data (plain.txt)", plainTxt, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.CanParse(tt.data); got != tt.want {
				t.Errorf("CanParse() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestFreeOTP_Parse(t *testing.T) {
	fixture, err := os.ReadFile("testdata/freeotp.xml")
	if err != nil {
		t.Fatalf("failed to read freeotp.xml: %v", err)
	}

	p := &FreeOTPParser{}
	entries, err := p.Parse(fixture, "")
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	// Should have 4 entries (tokenOrder is skipped)
	if len(entries) != 4 {
		t.Fatalf("Parse() returned %d entries; want 4", len(entries))
	}

	// Verify no entry has Name=="tokenOrder"
	for _, e := range entries {
		if e.Name == "tokenOrder" || e.Issuer == "tokenOrder" {
			t.Errorf("tokenOrder key was included as an entry: %+v", e)
		}
	}

	// Find Deno:Mason by issuer
	var denoEntry *struct {
		Type    string
		Algo    string
		Digits  int
		Period  uint
		Secret  string
		UUID    string
		Name    string
		Issuer  string
		Counter uint64
	}
	for _, e := range entries {
		if e.Issuer == "Deno" {
			eCopy := struct {
				Type    string
				Algo    string
				Digits  int
				Period  uint
				Secret  string
				UUID    string
				Name    string
				Issuer  string
				Counter uint64
			}{
				Type: e.Type, Algo: e.Algo, Digits: e.Digits, Period: e.Period,
				Secret: e.Secret, UUID: e.UUID, Name: e.Name, Issuer: e.Issuer,
				Counter: e.Counter,
			}
			denoEntry = &eCopy
			break
		}
	}

	if denoEntry == nil {
		t.Fatal("no entry with Issuer=Deno found")
	}

	// Deno:Mason — TOTP SHA1/6/30
	expectedDenoSecret := signedBytesToBase32([]int{-28, -110, 112, -16, -46, 31, 54, 92, -124, 8, -8, -76, 117, -59, 38, 124})
	if denoEntry.Type != "totp" {
		t.Errorf("Deno entry Type = %q; want %q", denoEntry.Type, "totp")
	}
	if denoEntry.Algo != "SHA1" {
		t.Errorf("Deno entry Algo = %q; want %q", denoEntry.Algo, "SHA1")
	}
	if denoEntry.Digits != 6 {
		t.Errorf("Deno entry Digits = %d; want 6", denoEntry.Digits)
	}
	if denoEntry.Period != 30 {
		t.Errorf("Deno entry Period = %d; want 30", denoEntry.Period)
	}
	if denoEntry.Secret != expectedDenoSecret {
		t.Errorf("Deno entry Secret = %q; want %q", denoEntry.Secret, expectedDenoSecret)
	}
	if denoEntry.Name != "Mason" {
		t.Errorf("Deno entry Name = %q; want %q", denoEntry.Name, "Mason")
	}

	// Find WWE:Mason by issuer — HOTP SHA512/8/counter=10299
	var wweEntry *struct {
		Type    string
		Algo    string
		Digits  int
		Period  uint
		Counter uint64
	}
	for _, e := range entries {
		if e.Issuer == "WWE" {
			eCopy := struct {
				Type    string
				Algo    string
				Digits  int
				Period  uint
				Counter uint64
			}{
				Type: e.Type, Algo: e.Algo, Digits: e.Digits, Period: e.Period,
				Counter: e.Counter,
			}
			wweEntry = &eCopy
			break
		}
	}

	if wweEntry == nil {
		t.Fatal("no entry with Issuer=WWE found")
	}

	if wweEntry.Type != "hotp" {
		t.Errorf("WWE entry Type = %q; want %q", wweEntry.Type, "hotp")
	}
	if wweEntry.Algo != "SHA512" {
		t.Errorf("WWE entry Algo = %q; want %q", wweEntry.Algo, "SHA512")
	}
	if wweEntry.Digits != 8 {
		t.Errorf("WWE entry Digits = %d; want 8", wweEntry.Digits)
	}
	if wweEntry.Period != 0 {
		t.Errorf("WWE entry Period = %d; want 0 (HOTP)", wweEntry.Period)
	}
	if wweEntry.Counter != 10299 {
		t.Errorf("WWE entry Counter = %d; want 10299", wweEntry.Counter)
	}

	// Verify all entries have UUIDs
	for i, e := range entries {
		if e.UUID == "" {
			t.Errorf("entry[%d] has empty UUID", i)
		}
	}

	// Verify types are lowercase
	for _, e := range entries {
		if e.Type != "totp" && e.Type != "hotp" {
			t.Errorf("entry %q has unexpected type %q (want lowercase totp or hotp)", e.Issuer, e.Type)
		}
	}
}
