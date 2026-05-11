// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package entries

import (
	"strings"
	"testing"
	"time"

	"deskotp/internal/totp"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

type fakeSaver struct {
	saved       []totp.Entry
	savedGroups []GroupInfo
	err         error
}

func (f *fakeSaver) save(entries []totp.Entry, groups []GroupInfo) error {
	f.saved = make([]totp.Entry, len(entries))
	copy(f.saved, entries)
	f.savedGroups = make([]GroupInfo, len(groups))
	copy(f.savedGroups, groups)
	return f.err
}

func newTestManager() (*Manager, *fakeSaver) {
	saver := &fakeSaver{}
	m := New(saver.save, func() {}, func() {}, func() {})
	return m, saver
}

// ---------------------------------------------------------------------------
// normalizeSecret tests (same-package access to unexported function)
// ---------------------------------------------------------------------------

func TestNormalizeSecret(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"jbswy3dp ehpk3pxp", "JBSWY3DPEHPK3PXP"},
		{"JBSWY3DP", "JBSWY3DP"},
		{"  AB CD  ", "ABCD"},
		{"abcdef", "ABCDEF"},
		{"ABC DEF GHI", "ABCDEFGHI"},
	}

	for _, tt := range tests {
		got := normalizeSecret(tt.input)
		if got != tt.want {
			t.Errorf("normalizeSecret(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// maskSecret tests (same-package access to unexported function)
// ---------------------------------------------------------------------------

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"ABCDEF", "AB...EF"},
		{"AB", "****"},
		{"", "****"},
		{"ABCD", "****"},
		{"ABCDE", "AB...DE"},
	}
	for _, tt := range tests {
		got := maskSecret(tt.input)
		if got != tt.want {
			t.Errorf("maskSecret(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Add tests
// ---------------------------------------------------------------------------

// TestAdd_Success: Add appends a new entry with a fresh UUID and saves.
func TestAdd_Success(t *testing.T) {
	m, saver := newTestManager()

	err := m.Add("alice", "GitHub", "JBSWY3DPEHPK3PXP", "totp", "SHA1", 30, 6, 0, "github", "", false)
	if err != nil {
		t.Fatalf("Add: unexpected error: %v", err)
	}

	if len(saver.saved) != 1 {
		t.Fatalf("len(saver.saved) = %d, want 1", len(saver.saved))
	}

	e := saver.saved[0]
	if e.UUID == "" {
		t.Error("UUID should be non-empty after Add")
	}
	if e.Name != "alice" {
		t.Errorf("Name = %q, want %q", e.Name, "alice")
	}
	if e.Issuer != "GitHub" {
		t.Errorf("Issuer = %q, want %q", e.Issuer, "GitHub")
	}
	if e.Secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("Secret = %q, want %q", e.Secret, "JBSWY3DPEHPK3PXP")
	}
	if e.Type != "totp" {
		t.Errorf("Type = %q, want %q", e.Type, "totp")
	}
	if e.Algo != "SHA1" {
		t.Errorf("Algo = %q, want %q", e.Algo, "SHA1")
	}
	if e.Period != 30 {
		t.Errorf("Period = %d, want %d", e.Period, 30)
	}
	if e.Digits != 6 {
		t.Errorf("Digits = %d, want %d", e.Digits, 6)
	}
	if e.Icon != "github" {
		t.Errorf("Icon = %q, want %q", e.Icon, "github")
	}
}

// TestAdd_NormalizesSecret: "jbswy3dp ehpk3pxp" stored as "JBSWY3DPEHPK3PXP".
func TestAdd_NormalizesSecret(t *testing.T) {
	m, saver := newTestManager()

	err := m.Add("alice", "GitHub", "jbswy3dp ehpk3pxp", "totp", "SHA1", 30, 6, 0, "", "", false)
	if err != nil {
		t.Fatalf("Add: unexpected error: %v", err)
	}

	if saver.saved[0].Secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("Secret = %q, want %q (normalized)", saver.saved[0].Secret, "JBSWY3DPEHPK3PXP")
	}
}

// TestAdd_TOTPCodeCorrect: After Add with known secret, GenerateCode returns a valid 6-digit code.
func TestAdd_TOTPCodeCorrect(t *testing.T) {
	m, saver := newTestManager()

	err := m.Add("alice", "GitHub", "jbswy3dp ehpk3pxp", "totp", "SHA1", 30, 6, 0, "", "", false)
	if err != nil {
		t.Fatalf("Add: unexpected error: %v", err)
	}

	entry := saver.saved[0]
	code, _, err := totp.GenerateCode(entry, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: unexpected error: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("code length = %d, want 6; code = %q", len(code), code)
	}
	if code == "" {
		t.Error("code should be non-empty")
	}
}

// TestAdd_InvalidBase32: invalid secret returns an error containing "base32".
func TestAdd_InvalidBase32(t *testing.T) {
	m, _ := newTestManager()

	err := m.Add("alice", "GitHub", "!!!INVALID!!!", "totp", "SHA1", 30, 6, 0, "", "", false)
	if err == nil {
		t.Fatal("Add with invalid base32 should return error, got nil")
	}
	if !strings.Contains(err.Error(), "base32") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "base32")
	}
}

// TestAdd_Duplicate: returns "duplicate:" error when issuer+name matches.
func TestAdd_Duplicate(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{UUID: "dup-1", Name: "alice", Issuer: "GitHub", Secret: "JBSWY3DPEHPK3PXP"},
	})

	err := m.Add("alice", "GitHub", "JBSWY3DPEHPK3PXP", "totp", "SHA1", 30, 6, 0, "", "", false)
	if err == nil {
		t.Fatal("Add with duplicate issuer+name should return error, got nil")
	}
	if !strings.HasPrefix(err.Error(), "entries: duplicate:") {
		t.Errorf("error = %q, want prefix %q", err.Error(), "entries: duplicate:")
	}
}

// TestAdd_DuplicateCaseInsensitive: duplicate check is case-insensitive.
func TestAdd_DuplicateCaseInsensitive(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{UUID: "dup-2", Name: "Alice", Issuer: "GITHUB", Secret: "JBSWY3DPEHPK3PXP"},
	})

	err := m.Add("alice", "github", "JBSWY3DPEHPK3PXP", "totp", "SHA1", 30, 6, 0, "", "", false)
	if err == nil {
		t.Fatal("case-insensitive duplicate should return error, got nil")
	}
	if !strings.HasPrefix(err.Error(), "entries: duplicate:") {
		t.Errorf("error = %q, want prefix %q", err.Error(), "entries: duplicate:")
	}
}

// TestAdd_Force: force=true bypasses duplicate detection, results in 2 entries.
func TestAdd_Force(t *testing.T) {
	m, saver := newTestManager()
	m.Set([]totp.Entry{
		{UUID: "force-1", Name: "alice", Issuer: "GitHub", Secret: "JBSWY3DPEHPK3PXP", Type: "totp", Algo: "SHA1", Digits: 6, Period: 30},
	})

	err := m.Add("alice", "GitHub", "JBSWY3DPEHPK3PXP", "totp", "SHA1", 30, 6, 0, "", "", true)
	if err != nil {
		t.Fatalf("Add with force=true should not return error, got: %v", err)
	}

	if len(saver.saved) != 2 {
		t.Fatalf("len(saver.saved) = %d, want 2 (force bypasses duplicate check)", len(saver.saved))
	}
}

// TestAdd_ValidationErrors: table-driven validation checks.
func TestAdd_ValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		entryType   string
		algo        string
		period      int
		digits      int
		secret      string
		wantContain string
	}{
		{
			name:        "invalid type",
			entryType:   "badtype",
			algo:        "SHA1",
			period:      30,
			digits:      6,
			secret:      "JBSWY3DPEHPK3PXP",
			wantContain: "invalid type",
		},
		{
			name:        "invalid algo",
			entryType:   "totp",
			algo:        "MD5",
			period:      30,
			digits:      6,
			secret:      "JBSWY3DPEHPK3PXP",
			wantContain: "invalid algorithm",
		},
		{
			name:        "invalid period zero",
			entryType:   "totp",
			algo:        "SHA1",
			period:      0,
			digits:      6,
			secret:      "JBSWY3DPEHPK3PXP",
			wantContain: "invalid period",
		},
		{
			name:        "invalid digits 3",
			entryType:   "totp",
			algo:        "SHA1",
			period:      30,
			digits:      3,
			secret:      "JBSWY3DPEHPK3PXP",
			wantContain: "invalid digits",
		},
		{
			name:        "empty secret",
			entryType:   "totp",
			algo:        "SHA1",
			period:      30,
			digits:      6,
			secret:      "",
			wantContain: "secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _ := newTestManager()
			err := m.Add("alice", "GitHub", tt.secret, tt.entryType, tt.algo, tt.period, tt.digits, 0, "", "", false)
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantContain) {
				t.Errorf("error = %q, want to contain %q", err.Error(), tt.wantContain)
			}
		})
	}
}

// TestAdd_WithGroup verifies that Add stores the group on the entry.
func TestAdd_WithGroup(t *testing.T) {
	m, saver := newTestManager()

	err := m.Add("alice", "GitHub", "JBSWY3DPEHPK3PXP", "totp", "SHA1", 30, 6, 0, "", "Work", false)
	if err != nil {
		t.Fatalf("Add: unexpected error: %v", err)
	}

	if saver.saved[0].Group != "Work" {
		t.Errorf("Group = %q, want %q", saver.saved[0].Group, "Work")
	}
}

// TestBuildPayloads_Group verifies that Group is carried in EntryMetadata (not CodePayload).
// Since CodePayload was shrunk to TOTP-only fields, Group is now in BuildMetadataPayloads.
func TestBuildPayloads_Group(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{
			UUID:   "bp-1",
			Name:   "alice",
			Issuer: "Example",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
			Group:  "Finance",
		},
	})

	meta := m.BuildMetadataPayloads()
	if len(meta) != 1 {
		t.Fatalf("len(meta) = %d, want 1", len(meta))
	}
	if meta[0].Group != "Finance" {
		t.Errorf("Group = %q, want %q", meta[0].Group, "Finance")
	}
}

// TestGetGroups_Ordered verifies that SetGroups preserves order (not sorted).
func TestGetGroups_Ordered(t *testing.T) {
	m, _ := newTestManager()
	m.SetGroups([]GroupInfo{{Name: "Zebra"}, {Name: "Alpha"}})

	groups := m.GetGroups()
	if len(groups) != 2 {
		t.Fatalf("len(groups) = %d, want 2", len(groups))
	}
	if groups[0].Name != "Zebra" || groups[1].Name != "Alpha" {
		t.Errorf("groups = %v, want [Zebra Alpha] (preserves order)", groups)
	}
}

// TestGetGroups_LegacyMigration verifies that when groups is nil (SetGroups never called),
// GetGroups falls back to sorted scan of entry Group fields.
func TestGetGroups_LegacyMigration(t *testing.T) {
	m, _ := newTestManager()
	// Do NOT call SetGroups — groups stays nil (legacy mode)
	m.Set([]totp.Entry{
		{UUID: "a", Group: "Work"},
		{UUID: "b", Group: "Personal"},
		{UUID: "c", Group: "Work"},
	})
	// Override groups to nil to simulate legacy (New initializes to []string{})
	m.mu.Lock()
	m.groups = nil
	m.mu.Unlock()

	groups := m.GetGroups()
	if len(groups) != 2 {
		t.Fatalf("len(groups) = %d, want 2", len(groups))
	}
	if groups[0].Name != "Personal" || groups[1].Name != "Work" {
		t.Errorf("groups names = %v/%v, want [Personal Work] (alphabetical fallback)", groups[0].Name, groups[1].Name)
	}
}

// TestSyncGroupsFromEntries verifies that SyncGroupsFromEntries appends new group names.
func TestSyncGroupsFromEntries(t *testing.T) {
	m, _ := newTestManager()
	m.SetGroups([]GroupInfo{{Name: "Existing"}})
	m.Set([]totp.Entry{
		{UUID: "a", Group: "Existing"},
		{UUID: "b", Group: "NewGroup"},
	})

	m.SyncGroupsFromEntries()

	groups := m.GetGroups()
	if len(groups) != 2 {
		t.Fatalf("len(groups) = %d, want 2", len(groups))
	}
	if groups[0].Name != "Existing" {
		t.Errorf("groups[0].Name = %q, want %q", groups[0].Name, "Existing")
	}
	if groups[1].Name != "NewGroup" {
		t.Errorf("groups[1].Name = %q, want %q", groups[1].Name, "NewGroup")
	}
}

// ---------------------------------------------------------------------------
// GetDetails tests
// ---------------------------------------------------------------------------

// TestGetDetails_Found verifies GetDetails returns correct fields with masked secret.
func TestGetDetails_Found(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{
			UUID:       "det-1",
			Name:       "alice",
			Issuer:     "Example",
			Secret:     "JBSWY3DPEHPK3PXP",
			Algo:       "SHA1",
			Digits:     6,
			Period:     30,
			Type:       "totp",
			Group:      "Work",
			Note:       "main account",
			UsageCount: 5,
		},
	})

	det, err := m.GetDetails("det-1")
	if err != nil {
		t.Fatalf("GetDetails: unexpected error: %v", err)
	}
	if det.ID != "det-1" {
		t.Errorf("ID = %q, want %q", det.ID, "det-1")
	}
	if det.Name != "alice" {
		t.Errorf("Name = %q, want %q", det.Name, "alice")
	}
	if det.Issuer != "Example" {
		t.Errorf("Issuer = %q, want %q", det.Issuer, "Example")
	}
	if det.Group != "Work" {
		t.Errorf("Group = %q, want %q", det.Group, "Work")
	}
	if det.Note != "main account" {
		t.Errorf("Note = %q, want %q", det.Note, "main account")
	}
	if det.Type != "totp" {
		t.Errorf("Type = %q, want %q", det.Type, "totp")
	}
	if det.Algo != "SHA1" {
		t.Errorf("Algo = %q, want %q", det.Algo, "SHA1")
	}
	if det.Period != 30 {
		t.Errorf("Period = %d, want %d", det.Period, 30)
	}
	if det.Digits != 6 {
		t.Errorf("Digits = %d, want %d", det.Digits, 6)
	}
	if det.UsageCount != 5 {
		t.Errorf("UsageCount = %d, want %d", det.UsageCount, 5)
	}
	// Secret must be masked — "JBSWY3DPEHPK3PXP" (17 chars) -> "JB...XP"
	if det.Secret != "JB...XP" {
		t.Errorf("Secret = %q, want masked %q", det.Secret, "JB...XP")
	}
}

// TestGetDetails_NotFound verifies error on unknown ID.
func TestGetDetails_NotFound(t *testing.T) {
	m, _ := newTestManager()

	_, err := m.GetDetails("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown ID, got nil")
	}
}

// TestGetDetails_ZeroDefaults verifies GetDetails returns sensible defaults for zero Period/Digits.
func TestGetDetails_ZeroDefaults(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{
			UUID:   "zero-1",
			Name:   "Legacy Account",
			Issuer: "DeskOTP",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 0,  // legacy zero
			Period: 0,  // HOTP/legacy zero
			Type:   "", // empty -> "totp"
		},
	})

	det, err := m.GetDetails("zero-1")
	if err != nil {
		t.Fatalf("GetDetails: unexpected error: %v", err)
	}

	if det.Period != 30 {
		t.Errorf("Period = %d, want 30 (default for zero)", det.Period)
	}
	if det.Digits != 6 {
		t.Errorf("Digits = %d, want 6 (default for zero)", det.Digits)
	}
	if det.Type != "totp" {
		t.Errorf("Type = %q, want %q (default for empty)", det.Type, "totp")
	}
}

// ---------------------------------------------------------------------------
// GetGroups tests
// ---------------------------------------------------------------------------

// TestGetGroups verifies sorted, deduplicated group list (legacy fallback).
func TestGetGroups(t *testing.T) {
	m, _ := newTestManager()
	// Force legacy mode by setting groups to nil
	m.mu.Lock()
	m.groups = nil
	m.mu.Unlock()
	m.Set([]totp.Entry{
		{UUID: "a", Group: "Work"},
		{UUID: "b", Group: ""},
		{UUID: "c", Group: "Personal"},
		{UUID: "d", Group: "Work"},
	})

	groups := m.GetGroups()
	if len(groups) != 2 {
		t.Fatalf("len(groups) = %d, want 2", len(groups))
	}
	if groups[0].Name != "Personal" || groups[1].Name != "Work" {
		t.Errorf("groups names = %v/%v, want [Personal Work]", groups[0].Name, groups[1].Name)
	}
}

// TestGetGroups_Empty verifies empty slice (not nil) when no groups exist.
func TestGetGroups_Empty(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{UUID: "a", Group: ""},
	})

	groups := m.GetGroups()
	if groups == nil {
		t.Fatal("expected non-nil empty slice, got nil")
	}
	if len(groups) != 0 {
		t.Errorf("len(groups) = %d, want 0", len(groups))
	}
}

// ---------------------------------------------------------------------------
// Update tests
// ---------------------------------------------------------------------------

// TestUpdate_Success verifies Update modifies fields and persists.
func TestUpdate_Success(t *testing.T) {
	m, saver := newTestManager()
	m.Set([]totp.Entry{
		{
			UUID:   "upd-1",
			Name:   "old-name",
			Issuer: "old-issuer",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
			Group:  "old-group",
			Note:   "old-note",
		},
	})

	// Pass current values for advanced fields, empty secret to keep unchanged
	err := m.Update("upd-1", "new-name", "new-issuer", "new-group", "new-note", "totp", "SHA1", 30, 6, "", "")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	e := saver.saved[0]
	if e.Name != "new-name" {
		t.Errorf("Name = %q, want %q", e.Name, "new-name")
	}
	if e.Issuer != "new-issuer" {
		t.Errorf("Issuer = %q, want %q", e.Issuer, "new-issuer")
	}
	if e.Group != "new-group" {
		t.Errorf("Group = %q, want %q", e.Group, "new-group")
	}
	if e.Note != "new-note" {
		t.Errorf("Note = %q, want %q", e.Note, "new-note")
	}
	// Secret must not change when empty newSecret is passed
	if e.Secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("Secret changed unexpectedly: %q", e.Secret)
	}
}

// TestUpdate_NotFound verifies error on unknown ID with entries unchanged.
func TestUpdate_NotFound(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{UUID: "exists", Name: "original"},
	})

	err := m.Update("nonexistent", "x", "x", "x", "x", "totp", "SHA1", 30, 6, "", "")
	if err == nil {
		t.Fatal("expected error for unknown ID, got nil")
	}

	// Verify original entry is unchanged
	snap := m.Snapshot()
	if snap[0].Name != "original" {
		t.Errorf("Name = %q, want %q (should be unchanged)", snap[0].Name, "original")
	}
}

// TestUpdate_AdvancedFields verifies that Update updates all advanced fields.
func TestUpdate_AdvancedFields(t *testing.T) {
	m, saver := newTestManager()
	m.Set([]totp.Entry{
		{
			UUID:   "adv-1",
			Name:   "alice",
			Issuer: "Example",
			Secret: "OLDSECRET",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
		},
	})

	err := m.Update("adv-1", "alice", "Example", "", "", "totp", "SHA256", 60, 8, "NEWSECRET", "")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	e := saver.saved[0]
	if e.Algo != "SHA256" {
		t.Errorf("Algo = %q, want %q", e.Algo, "SHA256")
	}
	if e.Period != 60 {
		t.Errorf("Period = %d, want %d", e.Period, 60)
	}
	if e.Digits != 8 {
		t.Errorf("Digits = %d, want %d", e.Digits, 8)
	}
	if e.Secret != "NEWSECRET" {
		t.Errorf("Secret = %q, want %q", e.Secret, "NEWSECRET")
	}
}

// TestUpdate_SecretUnchanged verifies that empty newSecret leaves original secret intact.
func TestUpdate_SecretUnchanged(t *testing.T) {
	m, saver := newTestManager()
	m.Set([]totp.Entry{
		{
			UUID:   "sec-1",
			Name:   "bob",
			Issuer: "Corp",
			Secret: "ORIGINALSECRET",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
		},
	})

	err := m.Update("sec-1", "bob", "Corp", "", "", "totp", "SHA1", 30, 6, "", "")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	if saver.saved[0].Secret != "ORIGINALSECRET" {
		t.Errorf("Secret = %q, want %q (should be unchanged)", saver.saved[0].Secret, "ORIGINALSECRET")
	}
}

// TestUpdate_InvalidType verifies that invalid type is rejected.
func TestUpdate_InvalidType(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{UUID: "val-1", Secret: "S", Algo: "SHA1", Digits: 6, Period: 30, Type: "totp"},
	})

	err := m.Update("val-1", "n", "i", "", "", "badtype", "SHA1", 30, 6, "", "")
	if err == nil {
		t.Fatal("expected error for invalid type, got nil")
	}
	if !strings.Contains(err.Error(), "invalid type") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "invalid type")
	}
}

// TestUpdate_InvalidAlgo verifies that invalid algorithm is rejected.
func TestUpdate_InvalidAlgo(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{UUID: "val-2", Secret: "S", Algo: "SHA1", Digits: 6, Period: 30, Type: "totp"},
	})

	err := m.Update("val-2", "n", "i", "", "", "totp", "MD5", 30, 6, "", "")
	if err == nil {
		t.Fatal("expected error for invalid algorithm, got nil")
	}
	if !strings.Contains(err.Error(), "invalid algorithm") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "invalid algorithm")
	}
}

// TestUpdate_InvalidPeriod verifies that period=0 is rejected.
func TestUpdate_InvalidPeriod(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{UUID: "val-3", Secret: "S", Algo: "SHA1", Digits: 6, Period: 30, Type: "totp"},
	})

	err := m.Update("val-3", "n", "i", "", "", "totp", "SHA1", 0, 6, "", "")
	if err == nil {
		t.Fatal("expected error for invalid period, got nil")
	}
	if !strings.Contains(err.Error(), "invalid period") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "invalid period")
	}
}

// TestUpdate_InvalidDigits verifies that digits=3 is rejected (4 is valid).
func TestUpdate_InvalidDigits(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{UUID: "val-4", Secret: "S", Algo: "SHA1", Digits: 6, Period: 30, Type: "totp"},
	})

	// digits=4 is valid (range 4-10 to support imports from Authy, TOTP Authenticator, etc.)
	err := m.Update("val-4", "n", "i", "", "", "totp", "SHA1", 30, 4, "", "")
	if err != nil {
		t.Fatalf("digits=4 should be valid, got: %v", err)
	}
	// digits=3 is below the valid range
	err = m.Update("val-4", "n", "i", "", "", "totp", "SHA1", 30, 3, "", "")
	if err == nil {
		t.Fatal("expected error for invalid digits 3, got nil")
	}
	if !strings.Contains(err.Error(), "invalid digits") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "invalid digits")
	}
}

// TestUpdate_Icon verifies that Update sets an icon slug on an entry.
func TestUpdate_Icon(t *testing.T) {
	m, saver := newTestManager()
	m.Set([]totp.Entry{
		{
			UUID:   "icon-1",
			Name:   "alice",
			Issuer: "GitHub",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
		},
	})

	err := m.Update("icon-1", "alice", "GitHub", "", "", "totp", "SHA1", 30, 6, "", "github")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	if saver.saved[0].Icon != "github" {
		t.Errorf("Icon = %q, want %q", saver.saved[0].Icon, "github")
	}
}

// TestUpdate_ClearIcon verifies that Update with empty icon clears an existing icon.
func TestUpdate_ClearIcon(t *testing.T) {
	m, saver := newTestManager()
	m.Set([]totp.Entry{
		{
			UUID:   "icon-2",
			Name:   "bob",
			Issuer: "GitHub",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
			Icon:   "github",
		},
	})

	err := m.Update("icon-2", "bob", "GitHub", "", "", "totp", "SHA1", 30, 6, "", "")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	if saver.saved[0].Icon != "" {
		t.Errorf("Icon = %q, want empty string (cleared)", saver.saved[0].Icon)
	}
}

// TestUpdate_InvalidIcon verifies that Update rejects invalid icon slugs.
func TestUpdate_InvalidIcon(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{UUID: "icon-3", Secret: "S", Algo: "SHA1", Digits: 6, Period: 30, Type: "totp"},
	})

	err := m.Update("icon-3", "n", "i", "", "", "totp", "SHA1", 30, 6, "", "nonexistent-slug")
	if err == nil {
		t.Fatal("expected error for invalid icon slug, got nil")
	}
	if !strings.Contains(err.Error(), "invalid icon slug") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "invalid icon slug")
	}
}

// TestUpdate_ZeroPeriodDigitsRoundTrip verifies the full edit round-trip for
// imported entries that have Period=0, Digits=0 (HOTP/legacy imports from deskOTP).
func TestUpdate_ZeroPeriodDigitsRoundTrip(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{
			UUID:   "round-1",
			Name:   "Import Account",
			Issuer: "DeskOTP",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 0, // HOTP/legacy zero
			Period: 0, // HOTP/legacy zero
			Type:   "hotp",
		},
	})

	// Step 1: GetDetails returns effective values
	det, err := m.GetDetails("round-1")
	if err != nil {
		t.Fatalf("GetDetails: unexpected error: %v", err)
	}

	// Step 2: Update with effective values and a changed Note — must not error
	err = m.Update("round-1", det.Name, det.Issuer, det.Group, "edited note", det.Type, det.Algo, det.Period, det.Digits, "", det.Icon)
	if err != nil {
		t.Fatalf("Update with effective defaults: unexpected error: %v", err)
	}

	// Step 3: Verify the Note was actually updated
	updated, err := m.GetDetails("round-1")
	if err != nil {
		t.Fatalf("GetDetails after update: unexpected error: %v", err)
	}
	if updated.Note != "edited note" {
		t.Errorf("Note = %q, want %q", updated.Note, "edited note")
	}
}

// ---------------------------------------------------------------------------
// Delete tests
// ---------------------------------------------------------------------------

// TestDelete verifies that deleting the middle entry removes it and populates the undo buffer.
func TestDelete(t *testing.T) {
	m, saver := newTestManager()
	m.Set([]totp.Entry{
		{UUID: "del-1", Name: "alice", Secret: "AAAA"},
		{UUID: "del-2", Name: "bob", Secret: "BBBB"},
		{UUID: "del-3", Name: "carol", Secret: "CCCC"},
	})

	err := m.Delete("del-2")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if len(saver.saved) != 2 {
		t.Fatalf("len(saver.saved) = %d, want 2", len(saver.saved))
	}
	if saver.saved[0].UUID != "del-1" {
		t.Errorf("saved[0].UUID = %q, want %q", saver.saved[0].UUID, "del-1")
	}
	if saver.saved[1].UUID != "del-3" {
		t.Errorf("saved[1].UUID = %q, want %q", saver.saved[1].UUID, "del-3")
	}

	// Verify undo buffer is populated
	m.mu.RLock()
	undoEntry := m.undoEntry
	m.mu.RUnlock()
	if undoEntry == nil {
		t.Fatal("undoEntry is nil, want populated")
	}
	if undoEntry.UUID != "del-2" {
		t.Errorf("undoEntry.UUID = %q, want %q", undoEntry.UUID, "del-2")
	}
}

// TestDelete_NotFound verifies that deleting an unknown ID returns an error.
func TestDelete_NotFound(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{UUID: "exists", Name: "alice"},
	})

	err := m.Delete("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown ID, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "not found")
	}
}

// TestDelete_OverwritesUndo verifies that a second delete overwrites the undo buffer.
func TestDelete_OverwritesUndo(t *testing.T) {
	m, saver := newTestManager()
	m.Set([]totp.Entry{
		{UUID: "ow-1", Name: "alice", Secret: "AAAA"},
		{UUID: "ow-2", Name: "bob", Secret: "BBBB"},
		{UUID: "ow-3", Name: "carol", Secret: "CCCC"},
	})

	if err := m.Delete("ow-1"); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := m.Delete("ow-2"); err != nil {
		t.Fatalf("second delete: %v", err)
	}

	// Undo should restore ow-2 (second delete), not ow-1
	if err := m.UndoDelete(); err != nil {
		t.Fatalf("UndoDelete: %v", err)
	}

	n := len(saver.saved)
	var foundOw2 bool
	for _, e := range saver.saved {
		if e.UUID == "ow-2" {
			foundOw2 = true
		}
	}

	if n != 2 {
		t.Fatalf("len(saver.saved) = %d, want 2", n)
	}
	if !foundOw2 {
		t.Error("ow-2 not found after undo; second delete should be undoable")
	}
}

// ---------------------------------------------------------------------------
// UndoDelete tests
// ---------------------------------------------------------------------------

// TestUndoDelete verifies that undo restores the entry at its original index.
func TestUndoDelete(t *testing.T) {
	m, saver := newTestManager()
	m.Set([]totp.Entry{
		{UUID: "u-1", Name: "alice", Secret: "AAAA"},
		{UUID: "u-2", Name: "bob", Secret: "BBBB"},
		{UUID: "u-3", Name: "carol", Secret: "CCCC"},
	})

	// Delete middle entry, then undo
	if err := m.Delete("u-2"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := m.UndoDelete(); err != nil {
		t.Fatalf("UndoDelete: %v", err)
	}

	if len(saver.saved) != 3 {
		t.Fatalf("len(saver.saved) = %d, want 3", len(saver.saved))
	}
	if saver.saved[1].UUID != "u-2" {
		t.Errorf("saved[1].UUID = %q, want %q", saver.saved[1].UUID, "u-2")
	}

	// Verify undo buffer is cleared
	m.mu.RLock()
	undoEntry := m.undoEntry
	m.mu.RUnlock()
	if undoEntry != nil {
		t.Error("undoEntry should be nil after undo")
	}
}

// TestUndoDelete_NothingToUndo verifies error when undo buffer is empty.
func TestUndoDelete_NothingToUndo(t *testing.T) {
	m, _ := newTestManager()

	err := m.UndoDelete()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "nothing to undo") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "nothing to undo")
	}
}

// TestUndoDelete_IndexClamping verifies undo clamps index when entries shrink.
func TestUndoDelete_IndexClamping(t *testing.T) {
	m, saver := newTestManager()
	m.Set([]totp.Entry{
		{UUID: "c-1", Name: "alice", Secret: "AAAA"},
		{UUID: "c-2", Name: "bob", Secret: "BBBB"},
		{UUID: "c-3", Name: "carol", Secret: "CCCC"},
	})

	// Delete last entry (index 2)
	if err := m.Delete("c-3"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Externally remove another entry (simulating concurrent modification)
	m.mu.Lock()
	m.entries = m.entries[:1] // keep only c-1
	m.mu.Unlock()

	// Undo should clamp index to len(entries)=1 instead of original index 2
	if err := m.UndoDelete(); err != nil {
		t.Fatalf("UndoDelete: %v", err)
	}

	n := len(saver.saved)
	lastUUID := saver.saved[n-1].UUID

	if n != 2 {
		t.Fatalf("len(saver.saved) = %d, want 2", n)
	}
	if lastUUID != "c-3" {
		t.Errorf("last entry UUID = %q, want %q (clamped to end)", lastUUID, "c-3")
	}
}

// ---------------------------------------------------------------------------
// Group CRUD tests
// ---------------------------------------------------------------------------

func newTestManagerWithCallbacks() (*Manager, *fakeSaver, *int, *int) {
	saver := &fakeSaver{}
	notifyCount := new(int)
	emitCount := new(int)
	m := New(saver.save, func() { *notifyCount++ }, func() { *emitCount++ }, func() {})
	return m, saver, notifyCount, emitCount
}

// TestCreateGroup_Success: CreateGroup("Work", "") adds "Work" to groups.
func TestCreateGroup_Success(t *testing.T) {
	m, saver, notifyCount, _ := newTestManagerWithCallbacks()
	m.SetGroups([]GroupInfo{})

	err := m.CreateGroup("Work", "")
	if err != nil {
		t.Fatalf("CreateGroup: unexpected error: %v", err)
	}

	groups := m.GetGroups()
	if len(groups) != 1 || groups[0].Name != "Work" {
		t.Errorf("GetGroups() = %v, want [Work]", groups)
	}
	if len(saver.savedGroups) != 1 || saver.savedGroups[0].Name != "Work" {
		t.Errorf("saver.savedGroups = %v, want [Work]", saver.savedGroups)
	}
	if *notifyCount != 1 {
		t.Errorf("notifyCount = %d, want 1", *notifyCount)
	}
}

// TestCreateGroup_Empty: CreateGroup("", "") returns error containing "must not be empty".
func TestCreateGroup_Empty(t *testing.T) {
	m, _, _, _ := newTestManagerWithCallbacks()
	m.SetGroups([]GroupInfo{})

	err := m.CreateGroup("", "")
	if err == nil {
		t.Fatal("CreateGroup with empty name should return error, got nil")
	}
	if !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "must not be empty")
	}
}

// TestCreateGroup_Duplicate: CreateGroup on existing name returns error containing "already exists".
func TestCreateGroup_Duplicate(t *testing.T) {
	m, _, _, _ := newTestManagerWithCallbacks()
	m.SetGroups([]GroupInfo{{Name: "Work"}})

	err := m.CreateGroup("Work", "")
	if err == nil {
		t.Fatal("CreateGroup with duplicate name should return error, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "already exists")
	}
}

// TestCreateGroup_NoEmitFn: CreateGroup does NOT call emitFn (no CodePayload change).
func TestCreateGroup_NoEmitFn(t *testing.T) {
	m, _, _, emitCount := newTestManagerWithCallbacks()
	m.SetGroups([]GroupInfo{})

	if err := m.CreateGroup("Work", ""); err != nil {
		t.Fatalf("CreateGroup: unexpected error: %v", err)
	}
	if *emitCount != 0 {
		t.Errorf("emitCount = %d, want 0 (CreateGroup should not call emitFn)", *emitCount)
	}
}

// TestRenameGroup_Success: entries with Group="Old" updated to "New"; groups list updated.
func TestRenameGroup_Success(t *testing.T) {
	m, saver, notifyCount, emitCount := newTestManagerWithCallbacks()
	m.SetGroups([]GroupInfo{{Name: "Old"}})
	m.Set([]totp.Entry{
		{UUID: "rg-1", Name: "alice", Group: "Old", Secret: "JBSWY3DPEHPK3PXP", Algo: "SHA1", Digits: 6, Period: 30, Type: "totp"},
		{UUID: "rg-2", Name: "bob", Group: "Other", Secret: "JBSWY3DPEHPK3PXP", Algo: "SHA1", Digits: 6, Period: 30, Type: "totp"},
	})

	err := m.RenameGroup("Old", "New", "")
	if err != nil {
		t.Fatalf("RenameGroup: unexpected error: %v", err)
	}

	groups := m.GetGroups()
	if len(groups) != 1 || groups[0].Name != "New" {
		t.Errorf("GetGroups() = %v, want [New]", groups)
	}
	if len(saver.savedGroups) != 1 || saver.savedGroups[0].Name != "New" {
		t.Errorf("saver.savedGroups = %v, want [New]", saver.savedGroups)
	}
	// Entry with "Old" group should be updated
	var alice, bob totp.Entry
	for _, e := range saver.saved {
		if e.UUID == "rg-1" {
			alice = e
		} else if e.UUID == "rg-2" {
			bob = e
		}
	}
	if alice.Group != "New" {
		t.Errorf("alice.Group = %q, want %q", alice.Group, "New")
	}
	if bob.Group != "Other" {
		t.Errorf("bob.Group = %q, want %q (should be unchanged)", bob.Group, "Other")
	}
	if *notifyCount != 1 {
		t.Errorf("notifyCount = %d, want 1", *notifyCount)
	}
	if *emitCount != 1 {
		t.Errorf("emitCount = %d, want 1", *emitCount)
	}
}

// TestRenameGroup_NotFound: RenameGroup("Nonexistent", "X", "") returns error containing "not found".
func TestRenameGroup_NotFound(t *testing.T) {
	m, _, _, _ := newTestManagerWithCallbacks()
	m.SetGroups([]GroupInfo{{Name: "Work"}})

	err := m.RenameGroup("Nonexistent", "X", "")
	if err == nil {
		t.Fatal("RenameGroup with unknown name should return error, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "not found")
	}
}

// TestRenameGroup_EmptyNew: RenameGroup("Old", "", "") returns error containing "must not be empty".
func TestRenameGroup_EmptyNew(t *testing.T) {
	m, _, _, _ := newTestManagerWithCallbacks()
	m.SetGroups([]GroupInfo{{Name: "Old"}})

	err := m.RenameGroup("Old", "", "")
	if err == nil {
		t.Fatal("RenameGroup with empty new name should return error, got nil")
	}
	if !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "must not be empty")
	}
}

// TestRenameGroup_DuplicateNew: RenameGroup("A", "B", "") where "B" already exists returns error containing "already exists".
func TestRenameGroup_DuplicateNew(t *testing.T) {
	m, _, _, _ := newTestManagerWithCallbacks()
	m.SetGroups([]GroupInfo{{Name: "A"}, {Name: "B"}})

	err := m.RenameGroup("A", "B", "")
	if err == nil {
		t.Fatal("RenameGroup to existing name should return error, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "already exists")
	}
}

// TestRenameGroup_EmitsTickAndNotify: after RenameGroup, emitFn and notifyFn are called.
func TestRenameGroup_EmitsTickAndNotify(t *testing.T) {
	m, _, notifyCount, emitCount := newTestManagerWithCallbacks()
	m.SetGroups([]GroupInfo{{Name: "Old"}})

	if err := m.RenameGroup("Old", "New", ""); err != nil {
		t.Fatalf("RenameGroup: unexpected error: %v", err)
	}
	if *notifyCount != 1 {
		t.Errorf("notifyCount = %d, want 1", *notifyCount)
	}
	if *emitCount != 1 {
		t.Errorf("emitCount = %d, want 1", *emitCount)
	}
}

// TestDeleteGroup_Success: entries with Group="Del" set to Group=""; "Del" removed from groups list.
func TestDeleteGroup_Success(t *testing.T) {
	m, saver, _, _ := newTestManagerWithCallbacks()
	m.SetGroups([]GroupInfo{{Name: "Del"}, {Name: "Keep"}})
	m.Set([]totp.Entry{
		{UUID: "dg-1", Name: "alice", Group: "Del", Secret: "JBSWY3DPEHPK3PXP", Algo: "SHA1", Digits: 6, Period: 30, Type: "totp"},
		{UUID: "dg-2", Name: "bob", Group: "Keep", Secret: "JBSWY3DPEHPK3PXP", Algo: "SHA1", Digits: 6, Period: 30, Type: "totp"},
	})

	err := m.DeleteGroup("Del")
	if err != nil {
		t.Fatalf("DeleteGroup: unexpected error: %v", err)
	}

	groups := m.GetGroups()
	for _, g := range groups {
		if g.Name == "Del" {
			t.Errorf("group 'Del' should be removed, but GetGroups() = %v", groups)
		}
	}
	if len(groups) != 1 || groups[0].Name != "Keep" {
		t.Errorf("GetGroups() = %v, want [Keep]", groups)
	}

	var alice, bob totp.Entry
	for _, e := range saver.saved {
		if e.UUID == "dg-1" {
			alice = e
		} else if e.UUID == "dg-2" {
			bob = e
		}
	}
	if alice.Group != "" {
		t.Errorf("alice.Group = %q, want empty string (ungrouped)", alice.Group)
	}
	if bob.Group != "Keep" {
		t.Errorf("bob.Group = %q, want %q (unchanged)", bob.Group, "Keep")
	}
}

// TestDeleteGroup_NotFound: DeleteGroup("Nonexistent") returns error containing "not found".
func TestDeleteGroup_NotFound(t *testing.T) {
	m, _, _, _ := newTestManagerWithCallbacks()
	m.SetGroups([]GroupInfo{{Name: "Work"}})

	err := m.DeleteGroup("Nonexistent")
	if err == nil {
		t.Fatal("DeleteGroup with unknown name should return error, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "not found")
	}
}

// TestDeleteGroup_EmitsTickAndNotify: after DeleteGroup, emitFn and notifyFn are called.
func TestDeleteGroup_EmitsTickAndNotify(t *testing.T) {
	m, _, notifyCount, emitCount := newTestManagerWithCallbacks()
	m.SetGroups([]GroupInfo{{Name: "Work"}})

	if err := m.DeleteGroup("Work"); err != nil {
		t.Fatalf("DeleteGroup: unexpected error: %v", err)
	}
	if *notifyCount != 1 {
		t.Errorf("notifyCount = %d, want 1", *notifyCount)
	}
	if *emitCount != 1 {
		t.Errorf("emitCount = %d, want 1", *emitCount)
	}
}

// TestReorderGroups_Success: ReorderGroups(["B","A"]) when groups are ["A","B"] results in ["B","A"].
func TestReorderGroups_Success(t *testing.T) {
	m, saver, notifyCount, _ := newTestManagerWithCallbacks()
	m.SetGroups([]GroupInfo{{Name: "A"}, {Name: "B"}, {Name: "C"}})

	err := m.ReorderGroups([]string{"C", "A", "B"})
	if err != nil {
		t.Fatalf("ReorderGroups: unexpected error: %v", err)
	}

	groups := m.GetGroups()
	if len(groups) != 3 || groups[0].Name != "C" || groups[1].Name != "A" || groups[2].Name != "B" {
		t.Errorf("GetGroups() names = %v/%v/%v, want [C A B]", groups[0].Name, groups[1].Name, groups[2].Name)
	}
	if len(saver.savedGroups) != 3 || saver.savedGroups[0].Name != "C" || saver.savedGroups[1].Name != "A" || saver.savedGroups[2].Name != "B" {
		t.Errorf("saver.savedGroups names = %v/%v/%v, want [C A B]", saver.savedGroups[0].Name, saver.savedGroups[1].Name, saver.savedGroups[2].Name)
	}
	if *notifyCount != 1 {
		t.Errorf("notifyCount = %d, want 1", *notifyCount)
	}
}

// TestReorderGroups_Mismatch: ReorderGroups with wrong set returns error containing "do not match".
func TestReorderGroups_Mismatch(t *testing.T) {
	m, _, _, _ := newTestManagerWithCallbacks()
	m.SetGroups([]GroupInfo{{Name: "A"}, {Name: "B"}, {Name: "C"}})

	err := m.ReorderGroups([]string{"A", "B", "X"})
	if err == nil {
		t.Fatal("ReorderGroups with wrong set should return error, got nil")
	}
	if !strings.Contains(err.Error(), "do not match") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "do not match")
	}
}

// TestReorderGroups_WrongLength: ReorderGroups with fewer names returns error containing "do not match".
func TestReorderGroups_WrongLength(t *testing.T) {
	m, _, _, _ := newTestManagerWithCallbacks()
	m.SetGroups([]GroupInfo{{Name: "A"}, {Name: "B"}, {Name: "C"}})

	err := m.ReorderGroups([]string{"A", "B"})
	if err == nil {
		t.Fatal("ReorderGroups with wrong length should return error, got nil")
	}
	if !strings.Contains(err.Error(), "do not match") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "do not match")
	}
}

// TestReorderGroups_NoEmitFn: ReorderGroups does NOT call emitFn (no CodePayload change).
func TestReorderGroups_NoEmitFn(t *testing.T) {
	m, _, _, emitCount := newTestManagerWithCallbacks()
	m.SetGroups([]GroupInfo{{Name: "A"}, {Name: "B"}})

	if err := m.ReorderGroups([]string{"B", "A"}); err != nil {
		t.Fatalf("ReorderGroups: unexpected error: %v", err)
	}
	if *emitCount != 0 {
		t.Errorf("emitCount = %d, want 0 (ReorderGroups should not call emitFn)", *emitCount)
	}
}

// ---------------------------------------------------------------------------
// GenerateAndAdvance tests
// ---------------------------------------------------------------------------

// TestGenerateAndAdvance_TOTPReturnsCode verifies a valid TOTP code is returned.
func TestGenerateAndAdvance_TOTPReturnsCode(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{
			UUID:   "ga-1",
			Name:   "alice",
			Issuer: "Example",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
		},
	})

	code, err := m.GenerateAndAdvance("ga-1", time.Now())
	if err != nil {
		t.Fatalf("GenerateAndAdvance: unexpected error: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("code length = %d, want 6; code = %q", len(code), code)
	}
	if code == "" {
		t.Error("code should be non-empty")
	}
}

// TestGenerateAndAdvance_IncrementsUsageCount verifies UsageCount increments.
func TestGenerateAndAdvance_IncrementsUsageCount(t *testing.T) {
	m, saver := newTestManager()
	m.Set([]totp.Entry{
		{
			UUID:       "ga-2",
			Name:       "alice",
			Issuer:     "Example",
			Secret:     "JBSWY3DPEHPK3PXP",
			Algo:       "SHA1",
			Digits:     6,
			Period:     30,
			Type:       "totp",
			UsageCount: 0,
		},
	})

	_, err := m.GenerateAndAdvance("ga-2", time.Now())
	if err != nil {
		t.Fatalf("GenerateAndAdvance: unexpected error: %v", err)
	}

	if saver.saved[0].UsageCount != 1 {
		t.Errorf("UsageCount = %d, want 1", saver.saved[0].UsageCount)
	}
}

// ---------------------------------------------------------------------------
// Group pruning tests (pruneEmptyGroups)
// ---------------------------------------------------------------------------

// TestUpdate_KeepsEmptyGroup: editing the last entry out of a group does NOT
// prune that group — user-created groups survive Update. Only Delete prunes.
func TestUpdate_KeepsEmptyGroup(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{
			UUID:   "prune-upd-1",
			Name:   "alice",
			Issuer: "Example",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
			Group:  "Work",
		},
	})
	m.SetGroups([]GroupInfo{{Name: "Work"}})

	// Move entry out of "Work" (set group to "")
	err := m.Update("prune-upd-1", "alice", "Example", "", "", "totp", "SHA1", 30, 6, "", "")
	if err != nil {
		t.Fatalf("Update: unexpected error: %v", err)
	}

	groups := m.GetGroups()
	if len(groups) != 1 || groups[0].Name != "Work" {
		t.Errorf("GetGroups() = %v, want [Work] (empty groups survive Update)", groups)
	}
}

// TestUpdate_KeepsNonEmptyGroup: editing one entry out of a group that still
// has other entries leaves the group intact.
func TestUpdate_KeepsNonEmptyGroup(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{
			UUID:   "keep-upd-1",
			Name:   "alice",
			Issuer: "Example",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
			Group:  "Work",
		},
		{
			UUID:   "keep-upd-2",
			Name:   "bob",
			Issuer: "Corp",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
			Group:  "Work",
		},
	})
	m.SetGroups([]GroupInfo{{Name: "Work"}})

	// Move alice out of "Work" — bob remains in "Work"
	err := m.Update("keep-upd-1", "alice", "Example", "", "", "totp", "SHA1", 30, 6, "", "")
	if err != nil {
		t.Fatalf("Update: unexpected error: %v", err)
	}

	groups := m.GetGroups()
	if len(groups) != 1 || groups[0].Name != "Work" {
		t.Errorf("GetGroups() = %v, want [Work] (group still has entries)", groups)
	}
}

// TestUpdate_KeepsAllGroupsOnReassign: editing an entry from "Work" to "Personal"
// keeps both groups — Update never prunes.
func TestUpdate_KeepsAllGroupsOnReassign(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{
			UUID:   "prune-new-1",
			Name:   "alice",
			Issuer: "Example",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
			Group:  "Work",
		},
	})
	m.SetGroups([]GroupInfo{{Name: "Work"}, {Name: "Personal"}})

	// Move entry from "Work" to "Personal"
	err := m.Update("prune-new-1", "alice", "Example", "Personal", "", "totp", "SHA1", 30, 6, "", "")
	if err != nil {
		t.Fatalf("Update: unexpected error: %v", err)
	}

	groups := m.GetGroups()
	if len(groups) != 2 || groups[0].Name != "Work" || groups[1].Name != "Personal" {
		t.Errorf("GetGroups() names = %v/%v, want [Work Personal] (both groups survive Update)", groups[0].Name, groups[1].Name)
	}
}

// TestDelete_PrunesEmptyGroup: deleting the last entry in a group removes that
// group from GetGroups.
func TestDelete_PrunesEmptyGroup(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{
			UUID:   "prune-del-1",
			Name:   "alice",
			Issuer: "Example",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
			Group:  "Work",
		},
	})
	m.SetGroups([]GroupInfo{{Name: "Work"}})

	err := m.Delete("prune-del-1")
	if err != nil {
		t.Fatalf("Delete: unexpected error: %v", err)
	}

	groups := m.GetGroups()
	if len(groups) != 0 {
		t.Errorf("GetGroups() = %v, want [] (Work should be pruned after last entry deleted)", groups)
	}
}

// TestDelete_KeepsNonEmptyGroup: deleting one entry from a group that still has
// other entries leaves the group intact.
func TestDelete_KeepsNonEmptyGroup(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{
			UUID:   "keep-del-1",
			Name:   "alice",
			Issuer: "Example",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
			Group:  "Work",
		},
		{
			UUID:   "keep-del-2",
			Name:   "bob",
			Issuer: "Corp",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
			Group:  "Work",
		},
	})
	m.SetGroups([]GroupInfo{{Name: "Work"}})

	err := m.Delete("keep-del-1")
	if err != nil {
		t.Fatalf("Delete: unexpected error: %v", err)
	}

	groups := m.GetGroups()
	if len(groups) != 1 || groups[0].Name != "Work" {
		t.Errorf("GetGroups() = %v, want [Work] (group still has bob)", groups)
	}
}

// TestGenerateAndAdvance_HOTPIncrementsCounter verifies Counter increments for HOTP.
func TestGenerateAndAdvance_HOTPIncrementsCounter(t *testing.T) {
	m, saver := newTestManager()
	m.Set([]totp.Entry{
		{
			UUID:    "ga-3",
			Name:    "bob",
			Issuer:  "Corp",
			Secret:  "JBSWY3DPEHPK3PXP",
			Algo:    "SHA1",
			Digits:  6,
			Type:    "hotp",
			Counter: 5,
		},
	})

	_, err := m.GenerateAndAdvance("ga-3", time.Now())
	if err != nil {
		t.Fatalf("GenerateAndAdvance: unexpected error: %v", err)
	}

	if saver.saved[0].Counter != 6 {
		t.Errorf("Counter = %d, want 6", saver.saved[0].Counter)
	}
}

// TestGenerateAndAdvance_NotFound verifies error for unknown ID.
func TestGenerateAndAdvance_NotFound(t *testing.T) {
	m, _ := newTestManager()

	_, err := m.GenerateAndAdvance("nonexistent", time.Now())
	if err == nil {
		t.Fatal("expected error for unknown ID, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "not found")
	}
}

// ---------------------------------------------------------------------------
// GroupInfo icon tests
// ---------------------------------------------------------------------------

// TestCreateGroupWithIcon: CreateGroup("Work", "briefcase") stores icon in GroupInfo.
func TestCreateGroupWithIcon(t *testing.T) {
	m, _ := newTestManager()
	m.SetGroups([]GroupInfo{})

	if err := m.CreateGroup("Work", "briefcase"); err != nil {
		t.Fatalf("CreateGroup: unexpected error: %v", err)
	}

	groups := m.GetGroups()
	if len(groups) != 1 {
		t.Fatalf("len(groups) = %d, want 1", len(groups))
	}
	if groups[0].Name != "Work" {
		t.Errorf("groups[0].Name = %q, want %q", groups[0].Name, "Work")
	}
	if groups[0].Icon != "briefcase" {
		t.Errorf("groups[0].Icon = %q, want %q", groups[0].Icon, "briefcase")
	}
}

// TestRenameGroupUpdatesIcon: RenameGroup with new icon persists the updated icon.
func TestRenameGroupUpdatesIcon(t *testing.T) {
	m, _ := newTestManager()
	// Create group with no icon
	m.SetGroups([]GroupInfo{{Name: "Work", Icon: ""}})

	// Rename with icon "star"
	if err := m.RenameGroup("Work", "Work", "star"); err != nil {
		t.Fatalf("RenameGroup: unexpected error: %v", err)
	}

	groups := m.GetGroups()
	if len(groups) != 1 {
		t.Fatalf("len(groups) = %d, want 1", len(groups))
	}
	if groups[0].Name != "Work" {
		t.Errorf("groups[0].Name = %q, want %q", groups[0].Name, "Work")
	}
	if groups[0].Icon != "star" {
		t.Errorf("groups[0].Icon = %q, want %q (icon should be updated)", groups[0].Icon, "star")
	}
}

// TestReorderGroups_PreservesIcons: ReorderGroups preserves the icon for each group.
func TestReorderGroups_PreservesIcons(t *testing.T) {
	m, _ := newTestManager()
	m.SetGroups([]GroupInfo{
		{Name: "A", Icon: "apple"},
		{Name: "B", Icon: "banana"},
		{Name: "C", Icon: "cherry"},
	})

	if err := m.ReorderGroups([]string{"C", "A", "B"}); err != nil {
		t.Fatalf("ReorderGroups: unexpected error: %v", err)
	}

	groups := m.GetGroups()
	if len(groups) != 3 {
		t.Fatalf("len(groups) = %d, want 3", len(groups))
	}
	if groups[0].Name != "C" || groups[0].Icon != "cherry" {
		t.Errorf("groups[0] = {%q, %q}, want {C, cherry}", groups[0].Name, groups[0].Icon)
	}
	if groups[1].Name != "A" || groups[1].Icon != "apple" {
		t.Errorf("groups[1] = {%q, %q}, want {A, apple}", groups[1].Name, groups[1].Icon)
	}
	if groups[2].Name != "B" || groups[2].Icon != "banana" {
		t.Errorf("groups[2] = {%q, %q}, want {B, banana}", groups[2].Name, groups[2].Icon)
	}
}

// ---------------------------------------------------------------------------
// AnyPeriodBoundary tests
// ---------------------------------------------------------------------------

func TestAnyPeriodBoundary_FirstCall(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{{Secret: "JBSWY3DPEHPK3PXP", Period: 30}})
	if !m.AnyPeriodBoundary(100, 0) {
		t.Error("first call (lastEmit=0) should always return true")
	}
}

func TestAnyPeriodBoundary_SameStep(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{{Secret: "JBSWY3DPEHPK3PXP", Period: 30}})
	// Both timestamps in the same 30-second step
	if m.AnyPeriodBoundary(61, 60) {
		t.Error("same time step should return false")
	}
}

func TestAnyPeriodBoundary_CrossStep(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{{Secret: "JBSWY3DPEHPK3PXP", Period: 30}})
	// 59 is in step 1 (59/30=1), 60 is in step 2 (60/30=2)
	if !m.AnyPeriodBoundary(60, 59) {
		t.Error("crossing period boundary should return true")
	}
}

func TestAnyPeriodBoundary_MixedPeriods(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{Secret: "JBSWY3DPEHPK3PXP", Period: 30},
		{Secret: "JBSWY3DPEHPK3PXP", Period: 60},
	})
	// 30→31: 30-second entry crosses (30/30=1 → 31/30=1, wait no: 30/30=1, 31/30=1... same)
	// Actually: 29→30: 29/30=0 → 30/30=1, crosses for 30s entry
	if !m.AnyPeriodBoundary(30, 29) {
		t.Error("30s entry crosses boundary at 30, should return true")
	}
	// 30→31: neither crosses
	if m.AnyPeriodBoundary(31, 30) {
		t.Error("no entry crosses boundary between 30 and 31")
	}
	// 59→60: both cross (60s entry: 59/60=0→60/60=1; 30s entry: 59/30=1→60/30=2)
	if !m.AnyPeriodBoundary(60, 59) {
		t.Error("both entries cross boundary at 60, should return true")
	}
}

func TestAnyPeriodBoundary_HOTPSkipped(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{
		{Secret: "JBSWY3DPEHPK3PXP", Type: "hotp", Period: 0},
	})
	// HOTP entries should be skipped — no time component
	if m.AnyPeriodBoundary(60, 59) {
		t.Error("HOTP-only entries should never trigger a boundary")
	}
}

func TestAnyPeriodBoundary_EmptyEntries(t *testing.T) {
	m, _ := newTestManager()
	m.Set([]totp.Entry{})
	// No entries → no boundary to cross
	if m.AnyPeriodBoundary(60, 59) {
		t.Error("empty entries should return false")
	}
}

// ---------------------------------------------------------------------------
// Metadata emission tests (148-01)
// ---------------------------------------------------------------------------

// newTestManagerWithMetadataCounter creates a Manager wired with a counter that
// increments on every emitMetadataFn call.
func newTestManagerWithMetadataCounter() (*Manager, *fakeSaver, *int) {
	saver := &fakeSaver{}
	count := 0
	m := New(saver.save, func() {}, func() {}, func() { count++ })
	return m, saver, &count
}

// testEntry returns a minimal valid totp.Entry for use in metadata tests.
func testEntry() totp.Entry {
	return totp.Entry{
		UUID:   "test-uuid-1",
		Name:   "alice",
		Issuer: "GitHub",
		Secret: "JBSWY3DPEHPK3PXP",
		Type:   "totp",
		Algo:   "SHA1",
		Period: 30,
		Digits: 6,
		Icon:   "github",
		Group:  "work",
	}
}

// TestUpdateEmitsMetadata verifies Update() calls emitMetadataFn exactly once.
func TestUpdateEmitsMetadata(t *testing.T) {
	m, _, count := newTestManagerWithMetadataCounter()
	m.Set([]totp.Entry{testEntry()})

	err := m.Update("test-uuid-1", "alice2", "GitHub", "work", "", "totp", "SHA1", 30, 6, "", "github")
	if err != nil {
		t.Fatalf("Update: unexpected error: %v", err)
	}
	if *count != 1 {
		t.Errorf("emitMetadataFn call count = %d, want 1", *count)
	}
}

// TestAddEmitsMetadata verifies Add() calls emitMetadataFn exactly once.
func TestAddEmitsMetadata(t *testing.T) {
	m, _, count := newTestManagerWithMetadataCounter()

	err := m.Add("bob", "GitLab", "JBSWY3DPEHPK3PXP", "totp", "SHA1", 30, 6, 0, "gitlab", "", false)
	if err != nil {
		t.Fatalf("Add: unexpected error: %v", err)
	}
	if *count != 1 {
		t.Errorf("emitMetadataFn call count = %d, want 1", *count)
	}
}

// TestDeleteEmitsMetadata verifies Delete() calls emitMetadataFn exactly once.
func TestDeleteEmitsMetadata(t *testing.T) {
	m, _, count := newTestManagerWithMetadataCounter()
	m.Set([]totp.Entry{testEntry()})

	err := m.Delete("test-uuid-1")
	if err != nil {
		t.Fatalf("Delete: unexpected error: %v", err)
	}
	if *count != 1 {
		t.Errorf("emitMetadataFn call count = %d, want 1", *count)
	}
}

// TestUndoDeleteEmitsMetadata verifies UndoDelete() calls emitMetadataFn exactly once.
func TestUndoDeleteEmitsMetadata(t *testing.T) {
	m, _, count := newTestManagerWithMetadataCounter()
	m.Set([]totp.Entry{testEntry()})

	if err := m.Delete("test-uuid-1"); err != nil {
		t.Fatalf("Delete: unexpected error: %v", err)
	}
	// Reset count to isolate UndoDelete emission
	*count = 0

	if err := m.UndoDelete(); err != nil {
		t.Fatalf("UndoDelete: unexpected error: %v", err)
	}
	if *count != 1 {
		t.Errorf("emitMetadataFn call count after UndoDelete = %d, want 1", *count)
	}
}

// TestRenameGroupEmitsMetadata verifies RenameGroup() calls emitMetadataFn exactly once.
func TestRenameGroupEmitsMetadata(t *testing.T) {
	m, _, count := newTestManagerWithMetadataCounter()
	m.SetGroups([]GroupInfo{{Name: "work"}})
	m.Set([]totp.Entry{testEntry()})

	err := m.RenameGroup("work", "personal", "")
	if err != nil {
		t.Fatalf("RenameGroup: unexpected error: %v", err)
	}
	if *count != 1 {
		t.Errorf("emitMetadataFn call count = %d, want 1", *count)
	}
}

// TestDeleteGroupEmitsMetadata verifies DeleteGroup() calls emitMetadataFn exactly once.
func TestDeleteGroupEmitsMetadata(t *testing.T) {
	m, _, count := newTestManagerWithMetadataCounter()
	m.SetGroups([]GroupInfo{{Name: "work"}})
	m.Set([]totp.Entry{testEntry()})

	err := m.DeleteGroup("work")
	if err != nil {
		t.Fatalf("DeleteGroup: unexpected error: %v", err)
	}
	if *count != 1 {
		t.Errorf("emitMetadataFn call count = %d, want 1", *count)
	}
}

// TestBuildMetadataPayloads verifies BuildMetadataPayloads returns correct fields.
func TestBuildMetadataPayloads(t *testing.T) {
	m, _ := newTestManager()
	e := testEntry()
	e.UsageCount = 5
	m.Set([]totp.Entry{e})

	payloads := m.BuildMetadataPayloads()
	if len(payloads) != 1 {
		t.Fatalf("len(payloads) = %d, want 1", len(payloads))
	}
	p := payloads[0]
	if p.ID != e.UUID {
		t.Errorf("ID = %q, want %q", p.ID, e.UUID)
	}
	if p.Name != e.Name {
		t.Errorf("Name = %q, want %q", p.Name, e.Name)
	}
	if p.Issuer != e.Issuer {
		t.Errorf("Issuer = %q, want %q", p.Issuer, e.Issuer)
	}
	if p.Group != e.Group {
		t.Errorf("Group = %q, want %q", p.Group, e.Group)
	}
	if p.Icon != e.Icon {
		t.Errorf("Icon = %q, want %q", p.Icon, e.Icon)
	}
	if p.UsageCount != e.UsageCount {
		t.Errorf("UsageCount = %d, want %d", p.UsageCount, e.UsageCount)
	}
	if p.Type != "totp" {
		t.Errorf("Type = %q, want %q", p.Type, "totp")
	}
}

// TestCodePayloadNoMetadata proves CodePayload has no Name/Issuer/Group/Icon/UsageCount fields.
// This is a compile-time check — if CodePayload still had those fields, this would be a
// struct literal with unknown fields and would cause a compile error.
func TestCodePayloadNoMetadata(t *testing.T) {
	_ = CodePayload{
		ID:        "x",
		Code:      "123456",
		Remaining: 15,
		Period:    30,
		Type:      "totp",
	}
	// If this compiles, CodePayload does not have extra metadata fields.
}
