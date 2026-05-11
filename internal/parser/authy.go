// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"deskotp/internal/totp"
)

// AuthyParser implements BackupParser for the Authy Android XML export format.
// Authy stores OTP tokens in Android SharedPreferences XML inside a JSON array
// under the "com.authy.storage.tokens.authenticator.key" key.
//
// Each token has a decryptedSecret field that is already a base32 string —
// it is used directly without any byte conversion. Tokens that only have
// secretSeed (Authy-native entries without a TOTP decryptedSecret) are skipped.
//
// The 4-level issuer heuristic is an exact port of Aegis AuthyImporter.java
// sanitizeEntryInfo (non-Authy branch). All entries are hardcoded to
// SHA1/30s/totp since Authy does not expose algorithm or period parameters.
type AuthyParser struct{}

// authyToken represents a single entry in the Authy JSON array.
type authyToken struct {
	AccountType     string `json:"accountType"`
	DecryptedSecret string `json:"decryptedSecret"`
	Digits          int    `json:"digits"`
	OriginalIssuer  string `json:"originalIssuer"`
	OriginalName    string `json:"originalName"`
	Name            string `json:"name"`
	SecretSeed      string `json:"secretSeed"` // Authy-native entries — skip these
}

func (p *AuthyParser) Name() string { return "Authy" }

// CanParse returns true if data is a plain Authy Android XML export (decryptedSecret entries).
// Authy exports contain the "com.authy.storage.tokens.authenticator.key" key.
//
// Returns false if all token entries with secrets are encrypted (encryptedSecret set,
// decryptedSecret absent) — those files are handled by AuthyEncryptedParser.
// Both plain and encrypted Authy files share the same XML key, so CanParse must
// inspect the token array to distinguish them.
func (p *AuthyParser) CanParse(data []byte) bool {
	m, err := parseAndroidPrefsXML(data)
	if err != nil {
		return false
	}
	jsonStr, ok := m["com.authy.storage.tokens.authenticator.key"]
	if !ok {
		return false
	}

	// Inspect the token array to distinguish plain from encrypted backups.
	// An encrypted backup has tokens with encryptedSecret set and decryptedSecret absent.
	// A plain backup has tokens with decryptedSecret set (or secretSeed-only Authy-native entries).
	// authyToken has both fields (decryptedSecret, encryptedSecret) for discrimination.
	var tokens []struct {
		DecryptedSecret string `json:"decryptedSecret"`
		EncryptedSecret string `json:"encryptedSecret"`
		SecretSeed      string `json:"secretSeed"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &tokens); err != nil {
		return false
	}

	// Return false if every token with a secret is encrypted (no decryptedSecret anywhere).
	// A plain Authy file must have at least one token with decryptedSecret set.
	hasPlain := false
	for _, tok := range tokens {
		if tok.DecryptedSecret != "" {
			hasPlain = true
			break
		}
	}
	return hasPlain
}

// resolveAuthyIssuerName applies the 4-level issuer heuristic from Aegis
// AuthyImporter.java sanitizeEntryInfo (non-Authy branch).
//
// Level 1: originalIssuer != ""           -> issuer = originalIssuer
// Level 2: originalName contains ":"      -> issuer = part before first ":"
// Level 3: name contains " - "           -> issuer = part before first " - "
// Level 4: accountType != ""             -> issuer = capitalize(accountType)
//
// After resolving issuer, the name is cleaned by removing the issuer+separator
// prefix. If the resulting name still starts with ": ", that prefix is stripped.
func resolveAuthyIssuerName(originalIssuer, originalName, name, accountType string) (issuer, cleanName string) {
	var separator string
	switch {
	case originalIssuer != "":
		issuer = originalIssuer
		separator = ""
	case originalName != "" && strings.Contains(originalName, ":"):
		idx := strings.Index(originalName, ":")
		issuer = originalName[:idx]
		separator = ":"
	case strings.Contains(name, " - "):
		idx := strings.Index(name, " - ")
		issuer = name[:idx]
		separator = " - "
	default:
		if len(accountType) > 0 {
			issuer = strings.ToUpper(accountType[:1]) + accountType[1:]
		}
	}
	cleanName = strings.Replace(name, issuer+separator, "", 1)
	if strings.HasPrefix(cleanName, ": ") {
		cleanName = cleanName[2:]
	}
	return issuer, cleanName
}

// Parse decodes an Authy Android XML export into OTP entries.
//
// Field mapping:
//   - originalIssuer / originalName / name / accountType -> Issuer + Name via 4-level heuristic
//   - decryptedSecret -> Secret (already base32, used directly)
//   - digits -> Digits (defaults to 6 if 0)
//   - Algo: hardcoded "SHA1" (Authy does not expose algorithm)
//   - Period: hardcoded 30 (Authy plain is always TOTP/30s)
//   - Type: hardcoded "totp" (Authy does not support HOTP)
//
// Tokens with empty decryptedSecret (Authy-native entries with secretSeed only)
// are silently skipped — they cannot be converted to standard TOTP entries.
// password is accepted for interface compliance but ignored — plain-only format.
func (p *AuthyParser) Parse(data []byte, _ string) ([]totp.Entry, error) {
	m, err := parseAndroidPrefsXML(data)
	if err != nil {
		return nil, fmt.Errorf("authy: failed to parse XML: %w", err)
	}

	jsonStr, ok := m["com.authy.storage.tokens.authenticator.key"]
	if !ok {
		return nil, fmt.Errorf("authy: missing com.authy.storage.tokens.authenticator.key in XML")
	}

	var tokens []authyToken
	if err := json.Unmarshal([]byte(jsonStr), &tokens); err != nil {
		return nil, fmt.Errorf("authy: failed to parse token JSON: %w", err)
	}

	entries := make([]totp.Entry, 0, len(tokens))
	for _, tok := range tokens {
		// Skip Authy-native entries that have only secretSeed, no decryptedSecret.
		if tok.DecryptedSecret == "" {
			continue
		}

		issuer, name := resolveAuthyIssuerName(tok.OriginalIssuer, tok.OriginalName, tok.Name, tok.AccountType)

		digits := tok.Digits
		if digits == 0 {
			digits = 6
		}

		entries = append(entries, totp.Entry{
			UUID:   uuid.New().String(),
			Issuer: issuer,
			Name:   name,
			Secret: tok.DecryptedSecret, // already base32, use directly
			Algo:   "SHA1",              // Authy does not expose algorithm
			Digits: digits,
			Period: 30,     // Authy plain is always TOTP/30s
			Type:   "totp", // Authy does not support HOTP
		})
	}

	return entries, nil
}
