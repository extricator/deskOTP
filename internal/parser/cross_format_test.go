// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCanParse_CrossFormatMatrix verifies that each fixture file is recognised
// by exactly one parser (no false positives, no zero matches).
// This is the TEST-02 cross-format safety net: any CanParse ordering mistake
// that causes a fixture to match the wrong parser is caught here.
func TestCanParse_CrossFormatMatrix(t *testing.T) {
	fixtures := []struct {
		file           string
		expectedParser string
	}{
		{"deskotp_plain.json", "deskOTP Backup"},
		{"deskotp_encrypted.json", "deskOTP Backup (Encrypted)"},
		{"aegis_plain.json", "Aegis"},
		{"aegis_encrypted.json", "Aegis (Encrypted)"},
		{"andotp_plain.json", "andOTP"},
		{"andotp_encrypted_new.bin", "andOTP (Encrypted)"},
		{"andotp_encrypted_old.bin", "andOTP (Encrypted)"},
		{"2fas_schema_v1.json", "2FAS"},
		{"2fas_schema_v2.json", "2FAS"},
		{"2fas_schema_v3.json", "2FAS"},
		{"2fas_schema_v4.2fas", "2FAS"},
		{"twofas_encrypted.2fas", "2FAS (Encrypted)"},
		{"plain.txt", "Google Authenticator"},
		{"ente_auth.txt", "Google Authenticator"},
		{"bitwarden.json", "Bitwarden"},
		{"bitwarden.csv", "Bitwarden"},
		{"proton_authenticator.json", "Proton Authenticator"},
		{"steam.json", "Steam Guard"},
		{"steam_old.json", "Steam Guard"},
		{"duo.json", "Duo"},
		{"stratum_plain.json", "Stratum"},
		{"freeotp_plus.json", "FreeOTP+"},
		// Android XML formats
		{"freeotp.xml", "FreeOTP"},
		{"battle_net_authenticator.xml", "Battle.net"},
		{"authy_plain.xml", "Authy"},
		{"totp_authenticator_internal.xml", "TOTP Authenticator"},
		// Phase 15: Complex encrypted formats
		{"stratum_encrypted_current.bin", "Stratum (Encrypted)"},
		{"stratum_encrypted_legacy.bin", "Stratum (Encrypted)"},
		{"authy_encrypted.xml", "Authy (Encrypted)"},
		{"totp_authenticator_encrypted.bin", "TOTP Authenticator (Encrypted)"},
	}

	for _, fx := range fixtures {
		t.Run(fx.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", fx.file))
			if err != nil {
				t.Fatalf("cannot read fixture %s: %v", fx.file, err)
			}

			var matched []string
			for _, p := range parsers {
				got := p.CanParse(data)
				want := p.Name() == fx.expectedParser
				if got != want {
					t.Errorf(
						"fixture=%s parser=%q: CanParse()=%v, want %v",
						fx.file, p.Name(), got, want,
					)
				}
				if got {
					matched = append(matched, p.Name())
				}
			}

			switch len(matched) {
			case 0:
				t.Errorf("fixture=%s: no parser matched (expected %q)", fx.file, fx.expectedParser)
			case 1:
				if matched[0] != fx.expectedParser {
					t.Errorf("fixture=%s: matched %q, want %q", fx.file, matched[0], fx.expectedParser)
				}
			default:
				t.Errorf("fixture=%s: multiple parsers matched %v (expected only %q)", fx.file, matched, fx.expectedParser)
			}
		})
	}
}
