// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"deskotp/internal/entries"
	"deskotp/internal/parser"
	"deskotp/internal/totp"
	"deskotp/internal/vault"
)

// testEntry is a canonical TOTP entry for use in tests.
var testEntry = totp.Entry{
	UUID:       "test-uuid-1",
	Name:       "Alice",
	Issuer:     "GitHub",
	Secret:     "JBSWY3DPEHPK3PXP",
	Algo:       "SHA1",
	Digits:     6,
	Period:     30,
	Type:       "totp",
	Icon:       "github",
	UsageCount: 5,
	Group:      "Work",
}

// TestExport_DBVersion verifies plain export JSON has db.version=1 and deskotp_version=1.
func TestExport_DBVersion(t *testing.T) {
	data, err := Export([]totp.Entry{testEntry}, []entries.GroupInfo{}, nil, nil)
	if err != nil {
		t.Fatalf("Export() error: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	db, ok := raw["db"].(map[string]any)
	if !ok {
		t.Fatalf("db is not an object: %T", raw["db"])
	}

	version, ok := db["version"].(float64)
	if !ok {
		t.Fatalf("db.version is not a number: %T", db["version"])
	}
	if version != 1 {
		t.Errorf("db.version = %v, want 1", version)
	}

	desktopVersion, ok := db["deskotp_version"].(float64)
	if !ok {
		t.Fatalf("db.deskotp_version is not a number: %T", db["deskotp_version"])
	}
	if desktopVersion != 1 {
		t.Errorf("db.deskotp_version = %v, want 1", desktopVersion)
	}
}

// TestExport_PlainAcceptedByDeskOTPParser verifies DeskOTPParser.CanParse returns true
// on plain export output. Plain backups include deskotp_version=1 in the db object,
// so they are claimed by DeskOTPParser (not AegisParser which rejects deskotp_version >= 1).
func TestExport_PlainAcceptedByDeskOTPParser(t *testing.T) {
	data, err := Export([]totp.Entry{testEntry}, []entries.GroupInfo{}, nil, nil)
	if err != nil {
		t.Fatalf("Export() error: %v", err)
	}

	p := &parser.DeskOTPParser{}
	if !p.CanParse(data) {
		t.Error("exported plain backup not recognized by DeskOTPParser.CanParse")
	}
}

// TestExport_XDeskOTPExtension verifies each entry has x-deskotp with icon_slug,
// usage_count, and group fields populated.
func TestExport_XDeskOTPExtension(t *testing.T) {
	data, err := Export([]totp.Entry{testEntry}, []entries.GroupInfo{}, nil, nil)
	if err != nil {
		t.Fatalf("Export() error: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	db := raw["db"].(map[string]any)
	entries := db["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	entry := entries[0].(map[string]any)

	xDeskotp, ok := entry["x-deskotp"].(map[string]any)
	if !ok {
		t.Fatalf("x-deskotp missing or not an object: %T", entry["x-deskotp"])
	}

	if iconSlug, ok := xDeskotp["icon_slug"].(string); !ok || iconSlug != testEntry.Icon {
		t.Errorf("x-deskotp.icon_slug = %v, want %q", xDeskotp["icon_slug"], testEntry.Icon)
	}
	if usageCount, ok := xDeskotp["usage_count"].(float64); !ok || int(usageCount) != testEntry.UsageCount {
		t.Errorf("x-deskotp.usage_count = %v, want %d", xDeskotp["usage_count"], testEntry.UsageCount)
	}
	if group, ok := xDeskotp["group"].(string); !ok || group != testEntry.Group {
		t.Errorf("x-deskotp.group = %v, want %q", xDeskotp["group"], testEntry.Group)
	}
}

// TestExport_IconFieldsAreNull verifies every entry has "icon": null and
// "icon_mime": null (not omitted from JSON).
func TestExport_IconFieldsAreNull(t *testing.T) {
	data, err := Export([]totp.Entry{testEntry}, []entries.GroupInfo{}, nil, nil)
	if err != nil {
		t.Fatalf("Export() error: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	db := raw["db"].(map[string]any)
	entries := db["entries"].([]any)
	entry := entries[0].(map[string]any)

	// "icon" must be present and null (not omitted)
	icon, iconPresent := entry["icon"]
	if !iconPresent {
		t.Error(`"icon" field is missing from entry (must be present as null)`)
	} else if icon != nil {
		t.Errorf(`"icon" field: want null, got %v`, icon)
	}

	// "icon_mime" must be present and null
	iconMime, iconMimePresent := entry["icon_mime"]
	if !iconMimePresent {
		t.Error(`"icon_mime" field is missing from entry (must be present as null)`)
	} else if iconMime != nil {
		t.Errorf(`"icon_mime" field: want null, got %v`, iconMime)
	}
}

// TestExport_GroupsEmptyArray verifies entry "groups" field is [] (empty array),
// not null or missing.
func TestExport_GroupsEmptyArray(t *testing.T) {
	data, err := Export([]totp.Entry{testEntry}, []entries.GroupInfo{}, nil, nil)
	if err != nil {
		t.Fatalf("Export() error: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	db := raw["db"].(map[string]any)
	entries := db["entries"].([]any)
	entry := entries[0].(map[string]any)

	groups, ok := entry["groups"]
	if !ok {
		t.Fatal(`"groups" field is missing from entry`)
	}
	groupsSlice, ok := groups.([]any)
	if !ok {
		t.Fatalf(`"groups" field is not an array: %T = %v`, groups, groups)
	}
	if len(groupsSlice) != 0 {
		t.Errorf(`"groups" has %d elements, want 0 (empty array)`, len(groupsSlice))
	}
}

// TestExport_PlainHeaderNulls verifies plain export has slots:null and params:null
// in header.
func TestExport_PlainHeaderNulls(t *testing.T) {
	data, err := Export([]totp.Entry{testEntry}, []entries.GroupInfo{}, nil, nil)
	if err != nil {
		t.Fatalf("Export() error: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	header, ok := raw["header"].(map[string]any)
	if !ok {
		t.Fatalf("header is not an object: %T", raw["header"])
	}

	if slots := header["slots"]; slots != nil {
		t.Errorf("header.slots = %v, want null", slots)
	}
	if params := header["params"]; params != nil {
		t.Errorf("header.params = %v, want null", params)
	}
}

// TestExport_HOTPEntry verifies HOTP entry has counter field but no period,
// and TOTP has period but no counter.
func TestExport_HOTPEntry(t *testing.T) {
	hotpEntry := totp.Entry{
		UUID:    "hotp-uuid",
		Name:    "HOTP Account",
		Issuer:  "Service",
		Secret:  "JBSWY3DPEHPK3PXP",
		Algo:    "SHA1",
		Digits:  6,
		Type:    "hotp",
		Counter: 42,
	}
	totpEntry := totp.Entry{
		UUID:   "totp-uuid",
		Name:   "TOTP Account",
		Issuer: "Service",
		Secret: "JBSWY3DPEHPK3PXP",
		Algo:   "SHA1",
		Digits: 6,
		Period: 30,
		Type:   "totp",
	}

	data, err := Export([]totp.Entry{hotpEntry, totpEntry}, []entries.GroupInfo{}, nil, nil)
	if err != nil {
		t.Fatalf("Export() error: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	db := raw["db"].(map[string]any)
	entries := db["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	hotp := entries[0].(map[string]any)
	hotpInfo := hotp["info"].(map[string]any)

	// HOTP must have counter
	if counter, ok := hotpInfo["counter"].(float64); !ok || counter != 42 {
		t.Errorf("HOTP info.counter = %v, want 42", hotpInfo["counter"])
	}
	// HOTP must not have period
	if _, ok := hotpInfo["period"]; ok {
		t.Errorf("HOTP info.period should not be present (got %v)", hotpInfo["period"])
	}

	totpEntry2 := entries[1].(map[string]any)
	totpInfo := totpEntry2["info"].(map[string]any)

	// TOTP must have period
	if period, ok := totpInfo["period"].(float64); !ok || period != 30 {
		t.Errorf("TOTP info.period = %v, want 30", totpInfo["period"])
	}
	// TOTP must not have counter
	if _, ok := totpInfo["counter"]; ok {
		t.Errorf("TOTP info.counter should not be present (got %v)", totpInfo["counter"])
	}
}

// TestExport_NilMasterKeyProducesPlainJSON verifies Export(entries, nil, nil)
// returns valid plain JSON (not encrypted).
func TestExport_NilMasterKeyProducesPlainJSON(t *testing.T) {
	data, err := Export([]totp.Entry{testEntry}, []entries.GroupInfo{}, nil, nil)
	if err != nil {
		t.Fatalf("Export(nil masterKey) error: %v", err)
	}

	// Must be valid JSON
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Must have "db" as a JSON object (not a string/base64)
	db, ok := raw["db"].(map[string]any)
	if !ok {
		t.Errorf("db is not a JSON object (plain export): %T = %v", raw["db"], raw["db"])
	}
	_ = db
}

// TestExport_PlainRoundTrip verifies AegisParser.Parse on plain export output
// returns entries with matching Secret, Name, Issuer, Algo, Digits, Period.
func TestExport_PlainRoundTrip(t *testing.T) {
	ents := []totp.Entry{testEntry}

	data, err := Export(ents, []entries.GroupInfo{}, nil, nil)
	if err != nil {
		t.Fatalf("Export() error: %v", err)
	}

	p := &parser.AegisParser{}
	parsed, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("AegisParser.Parse() error: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(parsed))
	}

	got := parsed[0]
	want := ents[0]

	if got.Secret != want.Secret {
		t.Errorf("Secret: got %q, want %q", got.Secret, want.Secret)
	}
	if got.Name != want.Name {
		t.Errorf("Name: got %q, want %q", got.Name, want.Name)
	}
	if got.Issuer != want.Issuer {
		t.Errorf("Issuer: got %q, want %q", got.Issuer, want.Issuer)
	}
	if got.Algo != want.Algo {
		t.Errorf("Algo: got %q, want %q", got.Algo, want.Algo)
	}
	if got.Digits != want.Digits {
		t.Errorf("Digits: got %d, want %d", got.Digits, want.Digits)
	}
	if got.Period != want.Period {
		t.Errorf("Period: got %d, want %d", got.Period, want.Period)
	}
}

// encryptedTestSetup creates a vault, extracts the master key, and exports entries
// using the encrypted path. Returns the exported bytes, vault data, and master key.
func encryptedTestSetup(t *testing.T, ents []totp.Entry, password string) (exported, vaultData, masterKey []byte) {
	t.Helper()
	var err error
	vaultData, err = vault.Encrypt(ents, []entries.GroupInfo{}, password)
	if err != nil {
		t.Fatalf("vault.Encrypt() error: %v", err)
	}
	masterKey, err = vault.DecryptKey(vaultData, password)
	if err != nil {
		t.Fatalf("vault.DecryptKey() error: %v", err)
	}
	exported, err = Export(ents, []entries.GroupInfo{}, masterKey, vaultData)
	if err != nil {
		t.Fatalf("backup.Export(encrypted) error: %v", err)
	}
	return exported, vaultData, masterKey
}

// TestExport_EncryptedCanParse verifies DeskOTPEncryptedParser.CanParse returns true
// on encrypted export output. Encrypted backups use a "data" key (not "db"), so they
// are claimed by DeskOTPEncryptedParser, not AegisEncryptedParser.
func TestExport_EncryptedCanParse(t *testing.T) {
	entries := []totp.Entry{testEntry}
	exported, _, _ := encryptedTestSetup(t, entries, "test-password")

	p := &parser.DeskOTPEncryptedParser{}
	if !p.CanParse(exported) {
		t.Error("encrypted export output not recognized by DeskOTPEncryptedParser.CanParse")
	}
}

// TestExport_EncryptedRoundTrip verifies that decrypting the encrypted export with
// the correct password recovers the original OTP fields (Secret, Name, Issuer).
// Also verifies the decrypted inner JSON is BackupDB format (has deskotp_version and
// x-deskotp fields), not the raw []totp.Entry format used by vault.Encrypt.
//
// Round-trip for OTP fields uses vault.Decrypt which expects the VaultFile "data" key.
// BackupDB structure is verified via manual AES-GCM decryption of the "data" payload.
func TestExport_EncryptedRoundTrip(t *testing.T) {
	entries := []totp.Entry{testEntry}
	const password = "test-password"

	exported, _, masterKey := encryptedTestSetup(t, entries, password)

	// Round-trip OTP fields: vault.Decrypt reads the "data" field of the VaultFile.
	// It unmarshals as []totp.Entry (not BackupDB) — but the crypto works end-to-end
	// because EncryptBytes encrypts BackupDB JSON, which is a superset of totp.Entry
	// fields (Secret, Name, Issuer are present in BackupDB entries).
	// NOTE: vault.Decrypt expects []totp.Entry JSON — but the exported "data" is
	// BackupDB JSON. This means vault.Decrypt will fail to unmarshal. The correct
	// round-trip path for the exported format is manual decryption (see below).
	// We verify OTP field recovery using the manual decrypt approach.

	// Manual decrypt: read "data" + "header.params" from the exported VaultFile.
	var vf struct {
		Header struct {
			Params struct {
				Nonce string `json:"nonce"`
				Tag   string `json:"tag"`
			} `json:"params"`
		} `json:"header"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal(exported, &vf); err != nil {
		t.Fatalf("unmarshal exported: %v", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(vf.Data)
	if err != nil {
		t.Fatalf("base64 decode data: %v", err)
	}
	dataNonce, err := hex.DecodeString(vf.Header.Params.Nonce)
	if err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	dataTag, err := hex.DecodeString(vf.Header.Params.Tag)
	if err != nil {
		t.Fatalf("decode tag: %v", err)
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	plaintext, err := gcm.Open(nil, dataNonce, append(ciphertext, dataTag...), nil)
	if err != nil {
		t.Fatalf("gcm.Open (decrypt inner data): %v", err)
	}

	// The plaintext must be BackupDB JSON (deskotp_version=1, entries with x-deskotp).
	var db map[string]any
	if err := json.Unmarshal(plaintext, &db); err != nil {
		t.Fatalf("unmarshal decrypted plaintext as JSON: %v", err)
	}

	deskotpVersion, ok := db["deskotp_version"].(float64)
	if !ok {
		t.Errorf("decrypted inner JSON missing deskotp_version field: %v", db)
	} else if deskotpVersion != 1 {
		t.Errorf("deskotp_version = %v, want 1", deskotpVersion)
	}

	rawEntries, ok := db["entries"].([]any)
	if !ok || len(rawEntries) == 0 {
		t.Fatalf("decrypted inner JSON missing entries: %v", db)
	}
	entry0, ok := rawEntries[0].(map[string]any)
	if !ok {
		t.Fatalf("entries[0] is not a JSON object: %T", rawEntries[0])
	}
	if _, hasXDeskotp := entry0["x-deskotp"]; !hasXDeskotp {
		t.Error("entries[0] missing x-deskotp field (not BackupDB format)")
	}

	// Verify OTP fields survived the crypto round-trip.
	info, ok := entry0["info"].(map[string]any)
	if !ok {
		t.Fatalf("entries[0].info is not a JSON object: %T", entry0["info"])
	}
	if secret, _ := info["secret"].(string); secret != testEntry.Secret {
		t.Errorf("Secret: got %q, want %q", secret, testEntry.Secret)
	}
	if name, _ := entry0["name"].(string); name != testEntry.Name {
		t.Errorf("Name: got %q, want %q", name, testEntry.Name)
	}
	if issuer, _ := entry0["issuer"].(string); issuer != testEntry.Issuer {
		t.Errorf("Issuer: got %q, want %q", issuer, testEntry.Issuer)
	}
}

// TestExport_EncryptedPreservesSlots verifies that encrypted export output has the
// same slot UUID, salt, and KDF parameters as the original vault.
func TestExport_EncryptedPreservesSlots(t *testing.T) {
	entries := []totp.Entry{testEntry}
	const password = "test-password"
	exported, vaultData, _ := encryptedTestSetup(t, entries, password)

	// Parse original vault slots
	var originalVF struct {
		Header struct {
			Slots []struct {
				UUID string `json:"uuid"`
				Salt string `json:"salt"`
				N    int    `json:"n"`
				R    int    `json:"r"`
				P    int    `json:"p"`
			} `json:"slots"`
		} `json:"header"`
	}
	if err := json.Unmarshal(vaultData, &originalVF); err != nil {
		t.Fatalf("unmarshal original vaultData: %v", err)
	}

	// Parse exported output slots
	var exportedVF struct {
		Header struct {
			Slots []struct {
				UUID string `json:"uuid"`
				Salt string `json:"salt"`
				N    int    `json:"n"`
				R    int    `json:"r"`
				P    int    `json:"p"`
			} `json:"slots"`
		} `json:"header"`
	}
	if err := json.Unmarshal(exported, &exportedVF); err != nil {
		t.Fatalf("unmarshal exported: %v", err)
	}

	origSlots := originalVF.Header.Slots
	expSlots := exportedVF.Header.Slots
	if len(expSlots) != len(origSlots) {
		t.Fatalf("slot count: exported %d, original %d", len(expSlots), len(origSlots))
	}
	for i := range origSlots {
		if expSlots[i].UUID != origSlots[i].UUID {
			t.Errorf("slot[%d].UUID: exported %q, original %q", i, expSlots[i].UUID, origSlots[i].UUID)
		}
		if expSlots[i].Salt != origSlots[i].Salt {
			t.Errorf("slot[%d].Salt: exported %q, original %q", i, expSlots[i].Salt, origSlots[i].Salt)
		}
		if expSlots[i].N != origSlots[i].N {
			t.Errorf("slot[%d].N: exported %d, original %d", i, expSlots[i].N, origSlots[i].N)
		}
		if expSlots[i].R != origSlots[i].R {
			t.Errorf("slot[%d].R: exported %d, original %d", i, expSlots[i].R, origSlots[i].R)
		}
		if expSlots[i].P != origSlots[i].P {
			t.Errorf("slot[%d].P: exported %d, original %d", i, expSlots[i].P, origSlots[i].P)
		}
	}
}

// TestExport_EncryptedInvalidKey verifies Export returns an error when the master key
// has wrong length (16 bytes instead of 32).
func TestExport_EncryptedInvalidKey(t *testing.T) {
	ents := []totp.Entry{testEntry}
	vaultData, err := vault.Encrypt(ents, []entries.GroupInfo{}, "test-password")
	if err != nil {
		t.Fatalf("vault.Encrypt() error: %v", err)
	}

	shortKey := make([]byte, 16) // 16 bytes — wrong length for AES-256
	_, err = Export(ents, []entries.GroupInfo{}, shortKey, vaultData)
	if err == nil {
		t.Error("Export with 16-byte key: expected error, got nil")
	}
}

// TestExport_DeskOTPRoundTrip_PreservesGroup verifies Export -> DeskOTPParser.Parse
// preserves x-deskotp.group for grouped and ungrouped entries.
func TestExport_DeskOTPRoundTrip_PreservesGroup(t *testing.T) {
	ents := []totp.Entry{
		{
			UUID:   "rt-group-uuid",
			Name:   "Alice",
			Issuer: "GitHub",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
			Group:  "Work",
		},
		{
			UUID:   "rt-nogroup-uuid",
			Name:   "Bob",
			Issuer: "Google",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
			Group:  "",
		},
	}

	data, err := Export(ents, []entries.GroupInfo{}, nil, nil)
	if err != nil {
		t.Fatalf("Export() error: %v", err)
	}

	p := &parser.DeskOTPParser{}
	parsed, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("DeskOTPParser.Parse() error: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(parsed))
	}

	if parsed[0].Group != "Work" {
		t.Errorf("parsed[0].Group = %q, want %q", parsed[0].Group, "Work")
	}
	if parsed[1].Group != "" {
		t.Errorf("parsed[1].Group = %q, want empty string (ungrouped)", parsed[1].Group)
	}
}

// TestExportPreservesGroupIcons verifies that groups with icon slugs are included
// in the exported backup JSON with their icons preserved.
func TestExportPreservesGroupIcons(t *testing.T) {
	groups := []entries.GroupInfo{
		{Name: "Work", Icon: "briefcase"},
		{Name: "Personal", Icon: "house"},
		{Name: "NoIcon", Icon: ""},
	}
	ents := []totp.Entry{testEntry}

	data, err := Export(ents, groups, nil, nil)
	if err != nil {
		t.Fatalf("Export() error: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	db, ok := raw["db"].(map[string]any)
	if !ok {
		t.Fatalf("db is not an object: %T", raw["db"])
	}

	rawGroups, ok := db["groups"].([]any)
	if !ok {
		t.Fatalf("db.groups is not an array: %T", db["groups"])
	}

	if len(rawGroups) != 3 {
		t.Fatalf("len(db.groups) = %d, want 3", len(rawGroups))
	}

	wantGroups := []struct {
		name string
		icon string
	}{
		{"Work", "briefcase"},
		{"Personal", "house"},
		{"NoIcon", ""},
	}

	for i, want := range wantGroups {
		g, ok := rawGroups[i].(map[string]any)
		if !ok {
			t.Fatalf("db.groups[%d] is not an object: %T", i, rawGroups[i])
		}
		name, _ := g["name"].(string)
		if name != want.name {
			t.Errorf("db.groups[%d].name = %q, want %q", i, name, want.name)
		}
		// icon field: present with value (or absent when empty)
		icon, _ := g["icon"].(string)
		if icon != want.icon {
			t.Errorf("db.groups[%d].icon = %q, want %q", i, icon, want.icon)
		}
	}
}
