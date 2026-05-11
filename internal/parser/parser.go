// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"errors"

	"deskotp/internal/totp"
)

// ErrPasswordRequired is returned by encrypted parsers when no password is provided.
// app.go ImportFile checks errors.Is(err, parser.ErrPasswordRequired) to show the password modal.
//
// The vault package declares its own vault.ErrPasswordRequired for master-password
// vault operations. The duplication is intentional: parser sentinels scope to
// import-file decryption while vault sentinels scope to vault unlock/password-change.
// Keeping them separate avoids a cross-package dependency between parser and vault.
var ErrPasswordRequired = errors.New("parser: password required")

// ErrWrongPassword is returned by encrypted parsers when the supplied password
// does not decrypt the vault. Distinct from ErrPasswordRequired.
//
// The vault package declares its own vault.ErrWrongPassword with the same semantics
// but different scope. See ErrPasswordRequired comment above for rationale.
var ErrWrongPassword = errors.New("parser: incorrect password")

// ErrNoParserFound is returned by Import when no registered parser recognises the file.
var ErrNoParserFound = errors.New("parser: no supported backup format found")

// BackupParser is implemented by each backup format.
// Implementations are registered with Register and invoked via Import.
type BackupParser interface {
	// Name returns a human-readable label used in error messages.
	Name() string
	// CanParse returns true if data looks like a valid instance of this format.
	// Implementations should be fast and non-destructive -- read-only probe.
	CanParse(data []byte) bool
	// Parse decodes data into a slice of TOTP entries.
	// password is the vault decryption password (empty string for plain vaults).
	// Returns a non-nil error for malformed or semantically invalid input.
	Parse(data []byte, password string) ([]totp.Entry, error)
}

var parsers []BackupParser

func init() {
	// Registration order is EXPLICIT and intentional.
	// Most-specific CanParse probes first, broadest last.
	//
	// deskOTP parsers MUST precede Aegis — deskOTP files would lose x-deskotp fields
	// (icon_slug, usage_count, group, note) if the corresponding Aegis parser wins first.
	//
	// deskOTP encrypted MUST precede Aegis encrypted — both have version + non-null slots,
	// but deskOTP encrypted uses "data" key while Aegis encrypted uses "db" key.
	Register(&DeskOTPEncryptedParser{}) // 0. deskOTP encrypted (slots + "data" key, not "db")
	Register(&DeskOTPParser{})          // 1. deskOTP plain (deskotp_version in db)
	//
	// JSON object formats (probe specific keys):
	Register(&AegisEncryptedParser{})   // 2. Encrypted Aegis (version + non-null slots, "db" key)
	Register(&AegisParser{})            // 2. Plain Aegis (version + null slots)
	Register(&TwoFASEncryptedParser{})  // 3. 2FAS Encrypted (schemaVersion + servicesEncrypted string)
	Register(&TwoFASParser{})           // 4. 2FAS Plain (schemaVersion + services array)
	Register(&StratumEncryptedParser{}) // 5. Stratum Encrypted (Argon2id/PBKDF2 binary; magic header probe) — MUST precede AndOTPEncryptedParser
	Register(&StratumParser{})          // 6. Stratum (Authenticators key — capital A)
	Register(&ProtonAuthParser{})       // 7. Proton (version + entries keys)
	Register(&SteamGuardParser{})       // 8. Steam Guard (accounts map OR uri+account_name)
	Register(&BitwardenParser{})        // 9. Bitwarden JSON (items key) or CSV (login_totp header)
	Register(&FreeOTPPlusParser{})      // 10. FreeOTP+ (tokens key)
	//
	// Binary formats (non-JSON — must precede andOTP plain JSON):
	Register(&AndOTPEncryptedParser{})  // 11. andOTP encrypted .bin (non-JSON binary; CanParse: not a JSON array)
	//
	// JSON array formats (root-level arrays — order matters):
	Register(&DuoParser{})              // 12. Duo (array with otpGenerator) MUST precede andOTP
	Register(&AndOTPParser{})           // 13. andOTP LAST among JSON (broadest: any JSON array)
	//
	// Text formats (line-based, not JSON):
	Register(&GoogleAuthParser{})       // 14. Google Auth / Ente Auth (otpauth:// URI text)
	Register(&WinAuthParser{})          // 15. WinAuth (same CanParse as GoogleAuth — unreachable via auto-detect, registered for completeness)
	//
	// Android XML formats (SharedPreferences XML — specific key probes):
	Register(&FreeOTPParser{})          // 16. FreeOTP v1 (tokenOrder key)
	Register(&BattleNetParser{})        // 17. Battle.net (DEVICE_SECRET key)
	Register(&AuthyEncryptedParser{})   // 18. Authy encrypted (encryptedSecret per-entry) — MUST precede AuthyParser
	Register(&AuthyParser{})            // 19. Authy plain (com.authy.storage.tokens.authenticator.key)
	Register(&TotpAuthenticatorEncryptedParser{}) // 20. TOTP Authenticator encrypted (base64-encoded AES-CBC binary) — MUST precede TotpAuthenticatorParser
	Register(&TotpAuthenticatorParser{})          // 21. TOTP Authenticator plain (STATIC_TOTP_CODES_LIST key)
}

// Register adds a BackupParser to the global registry.
// Called from init() in parser.go with explicit ordering.
func Register(p BackupParser) {
	parsers = append(parsers, p)
}

// Import iterates registered parsers, finds the first that can handle data,
// and returns the parsed entries along with the matched parser's name.
// password is threaded through to the matched parser.
// Returns the parser Name() even when Parse returns an error (e.g. wrong password).
// Returns ErrNoParserFound when no parser recognises the data.
func Import(data []byte, password string) ([]totp.Entry, string, error) {
	for _, p := range parsers {
		if p.CanParse(data) {
			entries, err := p.Parse(data, password)
			return entries, p.Name(), err
		}
	}
	return nil, "", ErrNoParserFound
}
