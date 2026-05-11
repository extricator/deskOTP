// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"os"
	"testing"
)

func TestAuthy_Name(t *testing.T) {
	p := &AuthyParser{}
	if got := p.Name(); got != "Authy" {
		t.Errorf("Name() = %q; want %q", got, "Authy")
	}
}

func TestAuthy_CanParse(t *testing.T) {
	authyXML, err := os.ReadFile("testdata/authy_plain.xml")
	if err != nil {
		t.Fatalf("failed to read authy_plain.xml: %v", err)
	}

	freeotpXML, err := os.ReadFile("testdata/freeotp.xml")
	if err != nil {
		t.Fatalf("failed to read freeotp.xml: %v", err)
	}

	battlenetXML, err := os.ReadFile("testdata/battle_net_authenticator.xml")
	if err != nil {
		t.Fatalf("failed to read battle_net_authenticator.xml: %v", err)
	}

	aegisJSON, err := os.ReadFile("testdata/aegis_plain.json")
	if err != nil {
		t.Fatalf("failed to read aegis_plain.json: %v", err)
	}

	plainTxt, err := os.ReadFile("testdata/plain.txt")
	if err != nil {
		t.Fatalf("failed to read plain.txt: %v", err)
	}

	p := &AuthyParser{}

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"authy_plain.xml fixture", authyXML, true},
		{"freeotp.xml (other XML)", freeotpXML, false},
		{"battle_net_authenticator.xml (other XML)", battlenetXML, false},
		{"JSON data (aegis_plain.json)", aegisJSON, false},
		{"text data (plain.txt)", plainTxt, false},
		{"empty data", []byte{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.CanParse(tt.data); got != tt.want {
				t.Errorf("CanParse() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestAuthy_Parse(t *testing.T) {
	fixture, err := os.ReadFile("testdata/authy_plain.xml")
	if err != nil {
		t.Fatalf("failed to read authy_plain.xml: %v", err)
	}

	p := &AuthyParser{}
	entries, err := p.Parse(fixture, "")
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("Parse() returned %d entries; want 3", len(entries))
	}

	// Find entries by issuer
	byIssuer := make(map[string]int)
	for i, e := range entries {
		byIssuer[e.Issuer] = i
	}

	// Verify Deno:Mason
	denoIdx, ok := byIssuer["Deno"]
	if !ok {
		t.Fatal("no entry with Issuer=Deno found")
	}
	deno := entries[denoIdx]
	if deno.Name != "Mason" {
		t.Errorf("Deno Name = %q; want %q", deno.Name, "Mason")
	}
	if deno.Secret != "4SJHB4GSD43FZBAI7C2HLRJGPQ" {
		t.Errorf("Deno Secret = %q; want %q", deno.Secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ")
	}
	if deno.Digits != 6 {
		t.Errorf("Deno Digits = %d; want 6", deno.Digits)
	}
	if deno.Algo != "SHA1" {
		t.Errorf("Deno Algo = %q; want %q", deno.Algo, "SHA1")
	}
	if deno.Period != 30 {
		t.Errorf("Deno Period = %d; want 30", deno.Period)
	}
	if deno.Type != "totp" {
		t.Errorf("Deno Type = %q; want %q", deno.Type, "totp")
	}
	if deno.UUID == "" {
		t.Error("Deno UUID is empty")
	}

	// Verify SPDX:James
	spdxIdx, ok := byIssuer["SPDX"]
	if !ok {
		t.Fatal("no entry with Issuer=SPDX found")
	}
	spdx := entries[spdxIdx]
	if spdx.Name != "James" {
		t.Errorf("SPDX Name = %q; want %q", spdx.Name, "James")
	}
	if spdx.Secret != "5OM4WOOGPLQEF6UGN3CPEOOLWU" {
		t.Errorf("SPDX Secret = %q; want %q", spdx.Secret, "5OM4WOOGPLQEF6UGN3CPEOOLWU")
	}
	if spdx.Digits != 7 {
		t.Errorf("SPDX Digits = %d; want 7", spdx.Digits)
	}
	if spdx.Algo != "SHA1" {
		t.Errorf("SPDX Algo = %q; want %q", spdx.Algo, "SHA1")
	}
	if spdx.Period != 30 {
		t.Errorf("SPDX Period = %d; want 30", spdx.Period)
	}
	if spdx.Type != "totp" {
		t.Errorf("SPDX Type = %q; want %q", spdx.Type, "totp")
	}

	// Verify Airbnb:Elijah
	airbnbIdx, ok := byIssuer["Airbnb"]
	if !ok {
		t.Fatal("no entry with Issuer=Airbnb found")
	}
	airbnb := entries[airbnbIdx]
	if airbnb.Name != "Elijah" {
		t.Errorf("Airbnb Name = %q; want %q", airbnb.Name, "Elijah")
	}
	if airbnb.Secret != "7ELGJSGXNCCTV3O6LKJWYFV2RA" {
		t.Errorf("Airbnb Secret = %q; want %q", airbnb.Secret, "7ELGJSGXNCCTV3O6LKJWYFV2RA")
	}
	if airbnb.Digits != 8 {
		t.Errorf("Airbnb Digits = %d; want 8", airbnb.Digits)
	}
	if airbnb.Algo != "SHA1" {
		t.Errorf("Airbnb Algo = %q; want %q", airbnb.Algo, "SHA1")
	}
	if airbnb.Period != 30 {
		t.Errorf("Airbnb Period = %d; want 30", airbnb.Period)
	}
	if airbnb.Type != "totp" {
		t.Errorf("Airbnb Type = %q; want %q", airbnb.Type, "totp")
	}
}

func TestAuthy_ResolveIssuerName(t *testing.T) {
	tests := []struct {
		name           string
		originalIssuer string
		originalName   string
		entryName      string
		accountType    string
		wantIssuer     string
		wantName       string
	}{
		{
			// Level 1: originalIssuer is set
			name:           "level 1 — originalIssuer set",
			originalIssuer: "Deno",
			originalName:   "Deno:Mason",
			entryName:      "Deno: Mason",
			accountType:    "authenticator",
			wantIssuer:     "Deno",
			wantName:       "Mason",
		},
		{
			// Level 2: originalIssuer empty, originalName has colon
			// name field matches "issuer:name" with no space after colon
			name:           "level 2 — originalName has colon",
			originalIssuer: "",
			originalName:   "Deno:Mason",
			entryName:      "Deno:Mason",
			accountType:    "authenticator",
			wantIssuer:     "Deno",
			wantName:       "Mason",
		},
		{
			// Level 3: originalIssuer empty, no colon in originalName, name has " - "
			name:           "level 3 — name has dash",
			originalIssuer: "",
			originalName:   "",
			entryName:      "Deno - Mason",
			accountType:    "authenticator",
			wantIssuer:     "Deno",
			wantName:       "Mason",
		},
		{
			// Level 4: all empty except accountType
			name:           "level 4 — accountType fallback",
			originalIssuer: "",
			originalName:   "",
			entryName:      "Mason",
			accountType:    "authenticator",
			wantIssuer:     "Authenticator",
			wantName:       "Mason",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIssuer, gotName := resolveAuthyIssuerName(tt.originalIssuer, tt.originalName, tt.entryName, tt.accountType)
			if gotIssuer != tt.wantIssuer {
				t.Errorf("issuer = %q; want %q", gotIssuer, tt.wantIssuer)
			}
			if gotName != tt.wantName {
				t.Errorf("name = %q; want %q", gotName, tt.wantName)
			}
		})
	}
}
