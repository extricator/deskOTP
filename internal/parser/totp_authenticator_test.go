// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"os"
	"testing"
)

func TestTotpAuth_Name(t *testing.T) {
	p := &TotpAuthenticatorParser{}
	if got := p.Name(); got != "TOTP Authenticator" {
		t.Errorf("Name() = %q; want %q", got, "TOTP Authenticator")
	}
}

func TestTotpAuth_CanParse(t *testing.T) {
	totpAuthXML, err := os.ReadFile("testdata/totp_authenticator_internal.xml")
	if err != nil {
		t.Fatalf("failed to read totp_authenticator_internal.xml: %v", err)
	}

	freeotpXML, err := os.ReadFile("testdata/freeotp.xml")
	if err != nil {
		t.Fatalf("failed to read freeotp.xml: %v", err)
	}

	authyXML, err := os.ReadFile("testdata/authy_plain.xml")
	if err != nil {
		t.Fatalf("failed to read authy_plain.xml: %v", err)
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

	p := &TotpAuthenticatorParser{}

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"totp_authenticator_internal.xml fixture", totpAuthXML, true},
		{"freeotp.xml (other XML)", freeotpXML, false},
		{"authy_plain.xml (other XML)", authyXML, false},
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

func TestTotpAuth_Parse(t *testing.T) {
	fixture, err := os.ReadFile("testdata/totp_authenticator_internal.xml")
	if err != nil {
		t.Fatalf("failed to read totp_authenticator_internal.xml: %v", err)
	}

	p := &TotpAuthenticatorParser{}
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

	// Deno entry: hex E49270F0D21F365C8408F8B475C5267C -> base32 4SJHB4GSD43FZBAI7C2HLRJGPQ
	denoIdx, ok := byIssuer["Deno"]
	if !ok {
		t.Fatal("no entry with Issuer=Deno found")
	}
	deno := entries[denoIdx]
	if deno.Name != "mason" {
		t.Errorf("Deno Name = %q; want %q", deno.Name, "mason")
	}
	if deno.Secret != "4SJHB4GSD43FZBAI7C2HLRJGPQ" {
		t.Errorf("Deno Secret = %q; want %q", deno.Secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ")
	}
	if deno.Digits != 6 {
		t.Errorf("Deno Digits = %d; want 6", deno.Digits)
	}
	if deno.Period != 30 {
		t.Errorf("Deno Period = %d; want 30", deno.Period)
	}
	if deno.Algo != "SHA1" {
		t.Errorf("Deno Algo = %q; want %q", deno.Algo, "SHA1")
	}
	if deno.Type != "totp" {
		t.Errorf("Deno Type = %q; want %q", deno.Type, "totp")
	}
	if deno.UUID == "" {
		t.Error("Deno UUID is empty")
	}

	// SPDX entry: hex EB99CB39C67AE042FA866EC4F239CBB5 -> base32 5OM4WOOGPLQEF6UGN3CPEOOLWU
	spdxIdx, ok := byIssuer["SPDX"]
	if !ok {
		t.Fatal("no entry with Issuer=SPDX found")
	}
	spdx := entries[spdxIdx]
	if spdx.Name != "james" {
		t.Errorf("SPDX Name = %q; want %q", spdx.Name, "james")
	}
	if spdx.Secret != "5OM4WOOGPLQEF6UGN3CPEOOLWU" {
		t.Errorf("SPDX Secret = %q; want %q", spdx.Secret, "5OM4WOOGPLQEF6UGN3CPEOOLWU")
	}
	if spdx.Digits != 7 {
		t.Errorf("SPDX Digits = %d; want 7", spdx.Digits)
	}
	if spdx.Period != 20 {
		t.Errorf("SPDX Period = %d; want 20", spdx.Period)
	}
	if spdx.Algo != "SHA1" {
		t.Errorf("SPDX Algo = %q; want %q", spdx.Algo, "SHA1")
	}
	if spdx.Type != "totp" {
		t.Errorf("SPDX Type = %q; want %q", spdx.Type, "totp")
	}

	// Airbnb entry: hex F91664C8D768853AEDDE5A936C16BA88 -> base32 7ELGJSGXNCCTV3O6LKJWYFV2RA
	airbnbIdx, ok := byIssuer["Airbnb"]
	if !ok {
		t.Fatal("no entry with Issuer=Airbnb found")
	}
	airbnb := entries[airbnbIdx]
	if airbnb.Name != "elijah" {
		t.Errorf("Airbnb Name = %q; want %q", airbnb.Name, "elijah")
	}
	if airbnb.Secret != "7ELGJSGXNCCTV3O6LKJWYFV2RA" {
		t.Errorf("Airbnb Secret = %q; want %q", airbnb.Secret, "7ELGJSGXNCCTV3O6LKJWYFV2RA")
	}
	if airbnb.Digits != 8 {
		t.Errorf("Airbnb Digits = %d; want 8", airbnb.Digits)
	}
	if airbnb.Period != 50 {
		t.Errorf("Airbnb Period = %d; want 50", airbnb.Period)
	}
	if airbnb.Algo != "SHA1" {
		t.Errorf("Airbnb Algo = %q; want %q", airbnb.Algo, "SHA1")
	}
	if airbnb.Type != "totp" {
		t.Errorf("Airbnb Type = %q; want %q", airbnb.Type, "totp")
	}
}

func TestTotpAuth_DecodeTotpAuthSecret(t *testing.T) {
	// Raw bytes from hex("E49270F0D21F365C8408F8B475C5267C")
	// -> base32 (no padding): 4SJHB4GSD43FZBAI7C2HLRJGPQ
	const hexKey = "E49270F0D21F365C8408F8B475C5267C"
	const expectedBase32 = "4SJHB4GSD43FZBAI7C2HLRJGPQ"

	tests := []struct {
		name        string
		base        int
		key         string
		wantSecret  string
		wantErr     bool
	}{
		{
			name:       "base=16 hex decode + base32 encode",
			base:       16,
			key:        hexKey,
			wantSecret: expectedBase32,
		},
		{
			name:       "base=32 round-trip identity",
			base:       32,
			key:        expectedBase32,
			wantSecret: expectedBase32,
		},
		{
			name:       "base=64 decode + base32 encode",
			base:       64,
			// base64 of raw bytes from hex("E49270F0D21F365C8408F8B475C5267C")
			// = base64.StdEncoding.EncodeToString(bytes)
			// bytes: [0xe4, 0x92, 0x70, 0xf0, 0xd2, 0x1f, 0x36, 0x5c, 0x84, 0x08, 0xf8, 0xb4, 0x75, 0xc5, 0x26, 0x7c]
			// base64: 5JJw8NIfNlyECPi0dcUmfA==
			key:        "5JJw8NIfNlyECPi0dcUmfA==",
			wantSecret: expectedBase32,
		},
		{
			name:    "unsupported base returns error",
			base:    99,
			key:     hexKey,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeTotpAuthSecret(tt.base, tt.key)
			if tt.wantErr {
				if err == nil {
					t.Errorf("decodeTotpAuthSecret(%d, %q) returned nil error; want error", tt.base, tt.key)
				}
				return
			}
			if err != nil {
				t.Errorf("decodeTotpAuthSecret(%d, %q) returned error: %v", tt.base, tt.key, err)
				return
			}
			if got != tt.wantSecret {
				t.Errorf("decodeTotpAuthSecret(%d, %q) = %q; want %q", tt.base, tt.key, got, tt.wantSecret)
			}
		})
	}
}
