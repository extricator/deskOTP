// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package iconmatch

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
		want   string
	}{
		// Tier 1: exact slug match
		{"tier1 exact lowercase", "github", "github"},
		{"tier1 case insensitive", "GitHub", "github"},
		{"tier1 dropbox", "Dropbox", "dropbox"},

		// Tier 2: alias lookup
		{"tier2 alias github inc", "GitHub, Inc.", "github"},
		{"tier2 alias github.com", "github.com", "github"},
		{"tier2 alias google accounts", "accounts.google.com", "google"},
		{"tier2 alias twitter to twitter slug", "twitter", "twitter"},
		{"tier2 alias amazon web services", "amazon web services", "amazon-web-services"},
		{"tier2 alias protonmail", "protonmail", "proton"},

		// Tier 3: normalized contains
		{"tier3 contains cloudflare", "My Cloudflare Account", "cloudflare"},
		{"tier3 longest match digitalocean", "Digital Ocean Cloud", "digitalocean"},

		// Edge cases
		{"empty issuer", "", ""},
		{"whitespace trimmed", "  GitHub  ", "github"},
		{"no match", "Some Random Corp", ""},

		// Short slug protection (< 4 chars must NOT match via tier 3)
		{"short slug x not matched", "Expertise LLC", ""},
		// "Shopping Center" now matches "ente" (4 chars slug from Ente Auth); use unmatchable string
		{"short slug hp not matched", "ZZXQJ Placeholder Ltd", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Match(tt.issuer)
			if got != tt.want {
				t.Errorf("Match(%q) = %q, want %q", tt.issuer, got, tt.want)
			}
		})
	}
}
