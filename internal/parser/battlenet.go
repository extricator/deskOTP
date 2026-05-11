// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"encoding/base32"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"

	"deskotp/internal/totp"
)

// battleNetKey is the 57-byte XOR key used to unmask Battle.net Authenticator
// secrets and serials. This is a well-known constant reverse-engineered from
// Blizzard's app and used by all tools that support this format (including Aegis).
// Source: Aegis BattleNetImporter.java
var battleNetKey []byte

func init() {
	var err error
	battleNetKey, err = hex.DecodeString("398e27fc50276a656065b0e525f4c06c04c61075286b8e7aeda59da9813b5dd6c80d2fb38068773fa59ba47c17ca6c6479015c1d5b8b8f6b9a")
	if err != nil {
		panic("battlenet: invalid XOR key constant: " + err.Error())
	}
}

// battleNetUnmask XOR-unmasks a hex-encoded, masked value using the battleNetKey.
// The returned string is the unmasked bytes interpreted as an ASCII string:
//   - For AUTHENTICATOR_DEVICE_SECRET: a hex string of the raw secret bytes
//   - For AUTHENTICATOR_SERIAL: a human-readable serial like "US-2211-2050-3346"
func battleNetUnmask(hexStr string) (string, error) {
	masked, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", fmt.Errorf("battlenet: invalid hex: %w", err)
	}
	if len(masked) > len(battleNetKey) {
		return "", fmt.Errorf("battlenet: masked data (%d bytes) exceeds key length (%d bytes)", len(masked), len(battleNetKey))
	}
	result := make([]byte, len(masked))
	for i, b := range masked {
		result[i] = b ^ battleNetKey[i]
	}
	return string(result), nil
}

// BattleNetParser implements BackupParser for the Battle.net Authenticator
// Android SharedPreferences XML format.
//
// Battle.net stores a hex-encoded XOR-masked secret in the key
// "com.blizzard.messenger.AUTHENTICATOR_DEVICE_SECRET" and a masked serial in
// "com.blizzard.messenger.AUTHENTICATOR_SERIAL". Both are unmasked with the
// known 57-byte battleNetKey.
//
// After unmasking, the secret string is itself a hex string of the raw TOTP
// secret bytes — it must be hex-decoded then base32-encoded to produce the
// Secret field. The serial becomes a human-readable string used as the entry Name.
type BattleNetParser struct{}

func (p *BattleNetParser) Name() string { return "Battle.net" }

// CanParse returns true if data is a Battle.net Authenticator SharedPreferences XML.
// It probes for the "com.blizzard.messenger.AUTHENTICATOR_DEVICE_SECRET" key,
// which is unique to this format.
func (p *BattleNetParser) CanParse(data []byte) bool {
	m, err := parseAndroidPrefsXML(data)
	if err != nil {
		return false
	}
	_, ok := m["com.blizzard.messenger.AUTHENTICATOR_DEVICE_SECRET"]
	return ok
}

// Parse decodes a Battle.net Authenticator XML into a single OTP entry.
//
// The entry always has:
//   - Issuer: "Battle.net" (hardcoded)
//   - Name: the unmasked AUTHENTICATOR_SERIAL string (empty if key absent)
//   - Secret: base32(hex.DecodeString(battleNetUnmask(AUTHENTICATOR_DEVICE_SECRET)))
//   - Algo: "SHA1", Digits: 8, Period: 30, Type: "totp"
func (p *BattleNetParser) Parse(data []byte, _ string) ([]totp.Entry, error) {
	m, err := parseAndroidPrefsXML(data)
	if err != nil {
		return nil, fmt.Errorf("battlenet: failed to parse XML: %w", err)
	}

	secretHex, ok := m["com.blizzard.messenger.AUTHENTICATOR_DEVICE_SECRET"]
	if !ok {
		return nil, fmt.Errorf("battlenet: AUTHENTICATOR_DEVICE_SECRET key not found")
	}

	// Unmask the secret — result is an ASCII hex string of the raw secret bytes.
	secretStr, err := battleNetUnmask(secretHex)
	if err != nil {
		return nil, fmt.Errorf("battlenet: failed to unmask secret: %w", err)
	}

	// Decode the unmasked hex string to raw bytes, then base32-encode.
	secretBytes, err := hex.DecodeString(secretStr)
	if err != nil {
		return nil, fmt.Errorf("battlenet: failed to decode unmasked secret hex: %w", err)
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)

	// Unmask the serial (entry name). Empty serial is valid — Aegis handles it gracefully.
	var name string
	if serialHex, hasSerial := m["com.blizzard.messenger.AUTHENTICATOR_SERIAL"]; hasSerial && serialHex != "" {
		unmasked, err := battleNetUnmask(serialHex)
		if err != nil {
			return nil, fmt.Errorf("battlenet: failed to unmask serial: %w", err)
		}
		name = unmasked
	}

	entry := totp.Entry{
		UUID:   uuid.New().String(),
		Issuer: "Battle.net",
		Name:   name,
		Secret: secret,
		Algo:   "SHA1",
		Digits: 8,
		Period: 30,
		Type:   "totp",
	}

	return []totp.Entry{entry}, nil
}
