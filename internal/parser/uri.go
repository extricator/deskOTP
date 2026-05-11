// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ParsedURI holds fields extracted from an otpauth:// URI.
// Used by URI-based parsers (Google Auth, Ente Auth, WinAuth, Bitwarden, Proton).
// Callers construct totp.Entry from ParsedURI, adding their own UUID generation.
// ParsedURI is intentionally separate from totp.Entry — callers must generate
// their own UUIDs and may override fields before constructing the final entry.
type ParsedURI struct {
	Type    string // "totp", "hotp", "steam"
	Issuer  string
	Name    string
	Secret  string
	Algo    string // default "SHA1"
	Digits  int    // default 6
	Period  uint   // default 30
	Counter uint64 // default 0; meaningful for HOTP only
}

// ParseURI parses a single otpauth:// URI into a ParsedURI.
// Returns error if scheme is not otpauth, type is unrecognised, or secret is absent.
//
// URI format: otpauth://{type}/{label}?{params}
//   - label may be "issuer:account" or just "account"
//   - query param issuer overrides label-derived issuer when non-empty
//   - percent-encoded characters are decoded by net/url automatically
//   - defaults applied when params are absent or unparseable:
//     algorithm=SHA1, digits=6, period=30, counter=0
func ParseURI(raw string) (ParsedURI, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return ParsedURI{}, fmt.Errorf("parseuri: %w", err)
	}

	if u.Scheme != "otpauth" {
		return ParsedURI{}, fmt.Errorf("parseuri: expected otpauth scheme, got %q", u.Scheme)
	}

	// OTP type is encoded as the host component.
	otpType := strings.ToLower(u.Host)
	switch otpType {
	case "totp", "hotp", "steam":
		// supported
	default:
		return ParsedURI{}, fmt.Errorf("parseuri: unsupported otp type %q", otpType)
	}

	// Label is the path, without leading slash.
	// url.Parse percent-decodes u.Path automatically.
	label := strings.TrimPrefix(u.Path, "/")

	var issuer, name string
	if idx := strings.Index(label, ":"); idx >= 0 {
		// "issuer:account" form — split on first colon only.
		parts := strings.SplitN(label, ":", 2)
		issuer = strings.TrimSpace(parts[0])
		name = strings.TrimSpace(parts[1])
	} else {
		// No colon — entire label is the account name, no label-derived issuer.
		name = label
		issuer = ""
	}

	q := u.Query()

	// Query param issuer overrides label-derived issuer when non-empty.
	if qi := q.Get("issuer"); qi != "" {
		issuer = qi
	}

	secret := q.Get("secret")
	if secret == "" {
		return ParsedURI{}, fmt.Errorf("parseuri: missing secret in URI")
	}

	// Algorithm defaults to SHA1.
	algo := q.Get("algorithm")
	if algo == "" {
		algo = "SHA1"
	}

	// Digits defaults to 6; fall back on parse error.
	digits := 6
	if ds := q.Get("digits"); ds != "" {
		if d, err := strconv.Atoi(ds); err == nil {
			digits = d
		}
	}

	// Period defaults to 30; fall back on parse error.
	period := uint(30)
	if ps := q.Get("period"); ps != "" {
		if p, err := strconv.ParseUint(ps, 10, 64); err == nil {
			period = uint(p)
		}
	}

	// Counter defaults to 0; fall back on parse error.
	counter := uint64(0)
	if cs := q.Get("counter"); cs != "" {
		if c, err := strconv.ParseUint(cs, 10, 64); err == nil {
			counter = c
		}
	}

	return ParsedURI{
		Type:    otpType,
		Issuer:  issuer,
		Name:    name,
		Secret:  secret,
		Algo:    algo,
		Digits:  digits,
		Period:  period,
		Counter: counter,
	}, nil
}
