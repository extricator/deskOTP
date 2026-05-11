// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"os"
	"testing"
)

func TestBattleNet_Name(t *testing.T) {
	p := &BattleNetParser{}
	if got := p.Name(); got != "Battle.net" {
		t.Errorf("Name() = %q; want %q", got, "Battle.net")
	}
}

func TestBattleNet_CanParse(t *testing.T) {
	battlenetXML, err := os.ReadFile("testdata/battle_net_authenticator.xml")
	if err != nil {
		t.Fatalf("failed to read battle_net_authenticator.xml: %v", err)
	}

	freeotpXML, err := os.ReadFile("testdata/freeotp.xml")
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

	p := &BattleNetParser{}

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"battle_net_authenticator.xml fixture", battlenetXML, true},
		{"freeotp.xml (other XML format)", freeotpXML, false},
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

func TestBattleNet_Parse(t *testing.T) {
	fixture, err := os.ReadFile("testdata/battle_net_authenticator.xml")
	if err != nil {
		t.Fatalf("failed to read battle_net_authenticator.xml: %v", err)
	}

	p := &BattleNetParser{}
	entries, err := p.Parse(fixture, "")
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries; want 1", len(entries))
	}

	e := entries[0]

	if e.Issuer != "Battle.net" {
		t.Errorf("Issuer = %q; want %q", e.Issuer, "Battle.net")
	}
	if e.Name != "US-2211-2050-3346" {
		t.Errorf("Name = %q; want %q", e.Name, "US-2211-2050-3346")
	}
	if e.Secret != "BMGRXPGFARQQF4GMT25JATL2VYLAHDBI" {
		t.Errorf("Secret = %q; want %q", e.Secret, "BMGRXPGFARQQF4GMT25JATL2VYLAHDBI")
	}
	if e.Algo != "SHA1" {
		t.Errorf("Algo = %q; want %q", e.Algo, "SHA1")
	}
	if e.Digits != 8 {
		t.Errorf("Digits = %d; want 8", e.Digits)
	}
	if e.Period != 30 {
		t.Errorf("Period = %d; want 30", e.Period)
	}
	if e.Type != "totp" {
		t.Errorf("Type = %q; want %q", e.Type, "totp")
	}
	if e.UUID == "" {
		t.Error("UUID is empty; want non-empty UUID")
	}
}

func TestBattleNet_Unmask(t *testing.T) {
	// XOR the fixture's DEVICE_SECRET hex with the key and verify the result.
	// The unmasked result is itself a hex string of the raw TOTP secret bytes.
	const fixtureSecretHex = "09ec179861450806035080d113c5f05e62f67316110eec1bd495a9cdb65a3cb3f93b1f80b80b4507"
	const expectedUnmasked = "0b0d1bbcc5046102f0cc9eba904d7aae16038c28"

	result, err := battleNetUnmask(fixtureSecretHex)
	if err != nil {
		t.Fatalf("battleNetUnmask() returned error: %v", err)
	}
	if result != expectedUnmasked {
		t.Errorf("battleNetUnmask() = %q; want %q", result, expectedUnmasked)
	}

	// Verify serial unmask as well.
	const fixtureSerialHex = "6cdd0ace62165b48525585d508c7f35832"
	const expectedSerial = "US-2211-2050-3346"

	serial, err := battleNetUnmask(fixtureSerialHex)
	if err != nil {
		t.Fatalf("battleNetUnmask() serial returned error: %v", err)
	}
	if serial != expectedSerial {
		t.Errorf("battleNetUnmask() serial = %q; want %q", serial, expectedSerial)
	}
}
