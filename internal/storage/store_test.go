// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package storage

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"deskotp/internal/entries"
	"deskotp/internal/totp"
)

// redirectToTempDir overrides the config directory to an isolated temp directory
// for the duration of the test. Prevents tests from touching ~/.config/deskotp/.
func redirectToTempDir(t *testing.T) {
	t.Helper()
	original := configDirOverride
	configDirOverride = t.TempDir()
	t.Cleanup(func() { configDirOverride = original })
}

// singleEntry is the canonical test entry used for single-entry tests.
var singleEntry = totp.Entry{
	UUID:   "test-uuid-001",
	Name:   "alice@example.com",
	Issuer: "Example Corp",
	Secret: "JBSWY3DPEHPK3PXP",
	Algo:   "SHA1",
	Digits: 6,
	Period: 30,
}

// TestSaveLoad_RoundTrip verifies that a single entry saved via Save() is fully
// recovered by Load() with every field matching. Covers PLAT-01 success criterion 1.
func TestSaveLoad_RoundTrip(t *testing.T) {
	redirectToTempDir(t)

	ents := []totp.Entry{singleEntry}
	if err := Save(ents, []entries.GroupInfo{}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, _, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("Load() returned %d entries, want 1", len(got))
	}

	if !reflect.DeepEqual(got[0], singleEntry) {
		t.Errorf("Load() entry mismatch\ngot:  %+v\nwant: %+v", got[0], singleEntry)
	}
}

// TestSaveLoad_MultipleEntries verifies that multiple entries with different
// algorithm configurations survive a save/load cycle. Covers PLAT-01 success
// criterion 1 for realistic multi-account scenarios.
func TestSaveLoad_MultipleEntries(t *testing.T) {
	redirectToTempDir(t)

	ents := []totp.Entry{
		{
			UUID:   "uuid-sha1",
			Name:   "sha1@example.com",
			Issuer: "SHA1Corp",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
		},
		{
			UUID:   "uuid-sha256",
			Name:   "sha256@example.com",
			Issuer: "SHA256Corp",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA256",
			Digits: 8,
			Period: 60,
		},
		{
			UUID:   "uuid-sha512",
			Name:   "sha512@example.com",
			Issuer: "SHA512Corp",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA512",
			Digits: 6,
			Period: 30,
		},
	}

	if err := Save(ents, []entries.GroupInfo{}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, _, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(got) != len(ents) {
		t.Fatalf("Load() returned %d entries, want %d", len(got), len(ents))
	}

	for i := range ents {
		if !reflect.DeepEqual(got[i], ents[i]) {
			t.Errorf("Load() entry[%d] mismatch\ngot:  %+v\nwant: %+v", i, got[i], ents[i])
		}
	}
}

// TestLoad_MissingFile verifies that Load() returns an empty slice and nil error
// when no data file exists. Covers PLAT-01 success criterion 4 (first-run case).
func TestLoad_MissingFile(t *testing.T) {
	redirectToTempDir(t)

	got, groups, err := Load()
	if err != nil {
		t.Fatalf("Load() on missing file returned error = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Errorf("Load() returned %d entries, want 0 (empty slice on missing file)", len(got))
	}
	if groups != nil {
		t.Errorf("Load() returned groups = %v, want nil on missing file", groups)
	}
}

// TestSave_FilePermissions verifies that the data file is created with 0600
// permissions at the expected path. Covers PLAT-01 success criterion 2.
func TestSave_FilePermissions(t *testing.T) {
	redirectToTempDir(t)

	if err := Save([]totp.Entry{}, []entries.GroupInfo{}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	path, err := dataPath()
	if err != nil {
		t.Fatalf("dataPath() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat(%q) error = %v", path, err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("file permissions = %04o, want 0600", info.Mode().Perm())
	}

	// Verify the parent directory exists.
	dir := strings.TrimSuffix(path, "/accounts.json")
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("parent dir stat error = %v", err)
	}
	if !dirInfo.IsDir() {
		t.Errorf("parent path %q is not a directory", dir)
	}
}

// TestSave_AtomicWrite_NoTempFileLeft verifies that no *.tmp files remain in
// the config directory after Save() completes, and that the written file
// contains valid JSON. Covers PLAT-01 success criterion 3.
func TestSave_AtomicWrite_NoTempFileLeft(t *testing.T) {
	redirectToTempDir(t)

	ents := []totp.Entry{singleEntry}
	if err := Save(ents, []entries.GroupInfo{}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	path, err := dataPath()
	if err != nil {
		t.Fatalf("dataPath() error = %v", err)
	}

	// Build the directory path from the data file path.
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash < 0 {
		t.Fatalf("unexpected path format: %q", path)
	}
	dir := path[:lastSlash]

	entries2, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%q) error = %v", dir, err)
	}

	for _, e := range entries2 {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file left behind after Save(): %q", e.Name())
		}
	}

	// Verify the content is valid JSON.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) error = %v", path, err)
	}

	var loaded StorageFile
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Errorf("file content is not valid JSON: %v\ncontent: %s", err, data)
	}
}

// --- SaveRaw / LoadRaw tests ---

// TestSaveRawLoadRaw_RoundTrip verifies that arbitrary bytes survive a SaveRaw/LoadRaw cycle.
func TestSaveRawLoadRaw_RoundTrip(t *testing.T) {
	redirectToTempDir(t)

	raw := []byte("encrypted-vault-binary-data-\x00\x01\xff")
	if err := SaveRaw(raw); err != nil {
		t.Fatalf("SaveRaw() error = %v", err)
	}

	got, err := LoadRaw()
	if err != nil {
		t.Fatalf("LoadRaw() error = %v", err)
	}

	if !reflect.DeepEqual(got, raw) {
		t.Errorf("LoadRaw() mismatch\ngot:  %v\nwant: %v", got, raw)
	}
}

// TestSaveRaw_NoTempFileLeft verifies atomicity: no .tmp files remain after SaveRaw.
func TestSaveRaw_NoTempFileLeft(t *testing.T) {
	redirectToTempDir(t)

	if err := SaveRaw([]byte("some data")); err != nil {
		t.Fatalf("SaveRaw() error = %v", err)
	}

	path, err := dataPath()
	if err != nil {
		t.Fatalf("dataPath() error = %v", err)
	}

	dir := path[:strings.LastIndex(path, "/")]
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%q) error = %v", dir, err)
	}

	for _, e := range dirEntries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file left behind after SaveRaw(): %q", e.Name())
		}
	}
}

// TestSaveRaw_FilePermissions verifies that SaveRaw writes with 0600 permissions.
func TestSaveRaw_FilePermissions(t *testing.T) {
	redirectToTempDir(t)

	if err := SaveRaw([]byte("secret")); err != nil {
		t.Fatalf("SaveRaw() error = %v", err)
	}

	path, err := dataPath()
	if err != nil {
		t.Fatalf("dataPath() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat(%q) error = %v", path, err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("file permissions = %04o, want 0600", info.Mode().Perm())
	}
}

// TestLoadRaw_MissingFile verifies that LoadRaw returns (nil, nil) when no file exists.
func TestLoadRaw_MissingFile(t *testing.T) {
	redirectToTempDir(t)

	got, err := LoadRaw()
	if err != nil {
		t.Fatalf("LoadRaw() on missing file returned error = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("LoadRaw() returned %v, want nil", got)
	}
}

// TestSaveRaw_ThenLoad_Fails verifies format isolation: raw bytes written by
// SaveRaw are not valid JSON entries, so Load() must fail.
func TestSaveRaw_ThenLoad_Fails(t *testing.T) {
	redirectToTempDir(t)

	// Write bytes that are NOT valid JSON entry array
	if err := SaveRaw([]byte("not-json-at-all")); err != nil {
		t.Fatalf("SaveRaw() error = %v", err)
	}

	_, _, err := Load()
	if err == nil {
		t.Error("Load() after SaveRaw(non-JSON) should return error, got nil")
	}
}

// ---------------------------------------------------------------------------
// New StorageFile and group tests
// ---------------------------------------------------------------------------

// TestSaveLoad_WithGroups verifies that Save with groups saves both and Load recovers both.
func TestSaveLoad_WithGroups(t *testing.T) {
	redirectToTempDir(t)

	ents := []totp.Entry{singleEntry}
	groups := []entries.GroupInfo{{Name: "Work"}, {Name: "Personal"}}

	if err := Save(ents, groups); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	gotEntries, gotGroups, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(gotEntries) != 1 {
		t.Fatalf("Load() returned %d entries, want 1", len(gotEntries))
	}
	if !reflect.DeepEqual(gotEntries[0], singleEntry) {
		t.Errorf("Load() entry mismatch\ngot:  %+v\nwant: %+v", gotEntries[0], singleEntry)
	}

	if len(gotGroups) != 2 {
		t.Fatalf("Load() returned %d groups, want 2", len(gotGroups))
	}
	if !reflect.DeepEqual(gotGroups, groups) {
		t.Errorf("Load() groups mismatch\ngot:  %v\nwant: %v", gotGroups, groups)
	}
}

// TestLoad_LegacyFormat verifies that a bare JSON array file loads correctly
// and returns nil groups (signals legacy format to the caller).
func TestLoad_LegacyFormat(t *testing.T) {
	redirectToTempDir(t)

	// Write legacy bare array format
	legacyData := `[{"uuid":"legacy-uuid","name":"legacy@example.com","issuer":"Legacy Corp","secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":30}]`
	path, err := dataPath()
	if err != nil {
		t.Fatalf("dataPath() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(legacyData), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	gotEntries, gotGroups, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(gotEntries) != 1 {
		t.Fatalf("Load() returned %d entries, want 1", len(gotEntries))
	}
	if gotEntries[0].UUID != "legacy-uuid" {
		t.Errorf("UUID = %q, want %q", gotEntries[0].UUID, "legacy-uuid")
	}

	// groups must be nil for legacy format
	if gotGroups != nil {
		t.Errorf("groups = %v, want nil (legacy format)", gotGroups)
	}
}

// TestLoadLegacyStringGroups verifies that accounts.json with old []string groups
// is migrated transparently to []GroupInfo with empty icons.
func TestLoadLegacyStringGroups(t *testing.T) {
	redirectToTempDir(t)

	// Write a StorageFile JSON with old-style []string groups
	legacyData := `{"entries":[],"groups":["A","B"]}`
	path, err := dataPath()
	if err != nil {
		t.Fatalf("dataPath() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(legacyData), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, gotGroups, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(gotGroups) != 2 {
		t.Fatalf("Load() returned %d groups, want 2", len(gotGroups))
	}
	if gotGroups[0].Name != "A" || gotGroups[0].Icon != "" {
		t.Errorf("gotGroups[0] = %+v, want {Name:A, Icon:}", gotGroups[0])
	}
	if gotGroups[1].Name != "B" || gotGroups[1].Icon != "" {
		t.Errorf("gotGroups[1] = %+v, want {Name:B, Icon:}", gotGroups[1])
	}
}

// TestLoadNewGroupInfoFormat verifies that accounts.json with []GroupInfo groups
// preserves icon slugs through a save/load cycle.
func TestLoadNewGroupInfoFormat(t *testing.T) {
	redirectToTempDir(t)

	// Write a StorageFile JSON with new-style []GroupInfo groups
	newData := `{"entries":[],"groups":[{"name":"A","icon":"star"}]}`
	path, err := dataPath()
	if err != nil {
		t.Fatalf("dataPath() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(newData), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, gotGroups, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(gotGroups) != 1 {
		t.Fatalf("Load() returned %d groups, want 1", len(gotGroups))
	}
	if gotGroups[0].Name != "A" {
		t.Errorf("gotGroups[0].Name = %q, want %q", gotGroups[0].Name, "A")
	}
	if gotGroups[0].Icon != "star" {
		t.Errorf("gotGroups[0].Icon = %q, want %q (icon should be preserved)", gotGroups[0].Icon, "star")
	}
}

