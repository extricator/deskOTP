// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package totp

import (
	"encoding/base32"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// rfcVectors contains all 18 RFC 6238 Appendix B test vectors.
// Codes are 8-digit (DigitsEight) per the RFC test specification.
// Each algorithm uses a distinct secret per RFC 6238 errata EID 2866.
var rfcVectors = []struct {
	unixTS   int64
	algo     string
	secret   []byte // raw ASCII bytes from RFC
	expected string // 8-digit code
}{
	{59, "SHA1", []byte("12345678901234567890"), "94287082"},
	{59, "SHA256", []byte("12345678901234567890123456789012"), "46119246"},
	{59, "SHA512", []byte("1234567890123456789012345678901234567890123456789012345678901234"), "90693936"},
	{1111111109, "SHA1", []byte("12345678901234567890"), "07081804"},
	{1111111109, "SHA256", []byte("12345678901234567890123456789012"), "68084774"},
	{1111111109, "SHA512", []byte("1234567890123456789012345678901234567890123456789012345678901234"), "25091201"},
	{1111111111, "SHA1", []byte("12345678901234567890"), "14050471"},
	{1111111111, "SHA256", []byte("12345678901234567890123456789012"), "67062674"},
	{1111111111, "SHA512", []byte("1234567890123456789012345678901234567890123456789012345678901234"), "99943326"},
	{1234567890, "SHA1", []byte("12345678901234567890"), "89005924"},
	{1234567890, "SHA256", []byte("12345678901234567890123456789012"), "91819424"},
	{1234567890, "SHA512", []byte("1234567890123456789012345678901234567890123456789012345678901234"), "93441116"},
	{2000000000, "SHA1", []byte("12345678901234567890"), "69279037"},
	{2000000000, "SHA256", []byte("12345678901234567890123456789012"), "90698825"},
	{2000000000, "SHA512", []byte("1234567890123456789012345678901234567890123456789012345678901234"), "38618901"},
	{20000000000, "SHA1", []byte("12345678901234567890"), "65353130"},
	{20000000000, "SHA256", []byte("12345678901234567890123456789012"), "77737706"},
	{20000000000, "SHA512", []byte("1234567890123456789012345678901234567890123456789012345678901234"), "47863826"},
}

func TestGenerateCode_RFC6238Vectors(t *testing.T) {
	for _, v := range rfcVectors {
		// pquerna/otp requires base32-encoded secrets; RFC vectors provide raw ASCII bytes.
		secret := base32.StdEncoding.EncodeToString(v.secret)
		entry := Entry{
			Secret: secret,
			Algo:   v.algo,
			Digits: 8,  // RFC vectors use 8-digit codes
			Period: 30,
		}
		code, _, err := GenerateCode(entry, time.Unix(v.unixTS, 0).UTC())
		if err != nil {
			t.Errorf("ts=%d algo=%s: unexpected error: %v", v.unixTS, v.algo, err)
			continue
		}
		if code != v.expected {
			t.Errorf("ts=%d algo=%s: got %q, want %q", v.unixTS, v.algo, code, v.expected)
		}
	}
}

func TestGenerateCode_RemainingSeconds(t *testing.T) {
	entry := Entry{
		Secret: base32.StdEncoding.EncodeToString([]byte("12345678901234567890")),
		Algo:   "SHA1",
		Digits: 6,
		Period: 30,
	}

	tests := []struct {
		name          string
		unixTS        int64
		wantRemaining int
	}{
		// At period boundary (ts % period == 0): remaining = period (NOT 0)
		{"start of period (t=0 mod 30)", 0, 30},   // 0%30=0, remaining=30
		{"second 1 of period", 1, 29},             // 1%30=1, remaining=29
		{"second 29 of period (penultimate)", 29, 1}, // 29%30=29, remaining=1
		{"second 30 (new period start)", 30, 30},  // 30%30=0, remaining=30
		// 1234567890 % 30 = 0, so remaining=30
		{"mid period (1234567890 % 30 == 0)", 1234567890, 30},
	}

	for _, tt := range tests {
		_, remaining, err := GenerateCode(entry, time.Unix(tt.unixTS, 0).UTC())
		if err != nil {
			t.Errorf("%s: unexpected error: %v", tt.name, err)
			continue
		}
		if remaining != tt.wantRemaining {
			t.Errorf("%s: remaining=%d, want %d", tt.name, remaining, tt.wantRemaining)
		}
	}
}

func TestGenerateCode_6Digit(t *testing.T) {
	// Verify 6-digit codes are correctly formatted (zero-padded, exactly 6 chars).
	// NOTE: 6-digit code is NOT the last 6 digits of the 8-digit RFC code.
	// pquerna/otp uses different modulo for digit count; this is by design.
	entry := Entry{
		Secret: base32.StdEncoding.EncodeToString([]byte("12345678901234567890")),
		Algo:   "SHA1",
		Digits: 6,
		Period: 30,
	}
	code, _, err := GenerateCode(entry, time.Unix(59, 0).UTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("expected 6-digit code, got %q (len=%d)", code, len(code))
	}
}

func TestGenerateCode_60sPeriod(t *testing.T) {
	entry := Entry{
		Secret: base32.StdEncoding.EncodeToString([]byte("12345678901234567890")),
		Algo:   "SHA1",
		Digits: 6,
		Period: 60,
	}
	// At t=59 with period=60: 59%60=59, remaining=60-59=1
	_, remaining, err := GenerateCode(entry, time.Unix(59, 0).UTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if remaining != 1 {
		t.Errorf("60s period: remaining=%d, want 1", remaining)
	}
}

func TestGenerateCode_InvalidAlgorithm(t *testing.T) {
	entry := Entry{
		Secret: base32.StdEncoding.EncodeToString([]byte("12345678901234567890")),
		Algo:   "MD5", // not supported per project requirements
		Digits: 6,
		Period: 30,
	}
	_, _, err := GenerateCode(entry, time.Now())
	if err == nil {
		t.Error("expected error for unsupported algorithm MD5, got nil")
	}
}

func TestGenerateCode_DefaultAlgo(t *testing.T) {
	// Empty Algo should be treated as SHA1 — no error should be returned.
	entry := Entry{
		Secret: base32.StdEncoding.EncodeToString([]byte("12345678901234567890")),
		Algo:   "", // empty — default to SHA1
		Digits: 6,
		Period: 30,
	}
	_, _, err := GenerateCode(entry, time.Unix(59, 0).UTC())
	if err != nil {
		t.Errorf("expected no error for empty algo (defaults to SHA1), got: %v", err)
	}
}

func TestGenerateCode_DefaultPeriod(t *testing.T) {
	// Period=0 should default to 30 seconds — no divide-by-zero or wrong result.
	entry := Entry{
		Secret: base32.StdEncoding.EncodeToString([]byte("12345678901234567890")),
		Algo:   "SHA1",
		Digits: 6,
		Period: 0, // default to 30
	}
	// At ts=1 with period=30 (default): remaining = 30 - 1%30 = 29
	_, remaining, err := GenerateCode(entry, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatalf("unexpected error for zero period: %v", err)
	}
	// Default period of 30: remaining should be 29 at ts=1
	if remaining != 29 {
		t.Errorf("default period (0->30): remaining=%d at ts=1, want 29", remaining)
	}
}

// --- Phase 7: New tests for HOTP, Steam, backward compat, and EffectiveType ---

// TestEffectiveType verifies the backward-compat helper returns correct defaults.
func TestEffectiveType(t *testing.T) {
	tests := []struct {
		entryType string
		want      string
	}{
		{"", "totp"},        // empty string (v1.0 accounts.json) defaults to "totp"
		{"totp", "totp"},   // explicit totp passes through
		{"hotp", "hotp"},   // hotp passes through
		{"steam", "steam"}, // steam passes through
	}

	for _, tt := range tests {
		e := Entry{Type: tt.entryType}
		got := e.EffectiveType()
		if got != tt.want {
			t.Errorf("Entry{Type:%q}.EffectiveType() = %q, want %q", tt.entryType, got, tt.want)
		}
	}
}

// TestGenerateCode_BackwardCompat_EmptyType verifies that existing accounts.json entries
// (Type="" from v1.0, before Type field was added) produce the same code as Type="totp".
// This is the critical backward-compatibility guarantee for the v1.1 schema change.
func TestGenerateCode_BackwardCompat_EmptyType(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	at := time.Unix(59, 0).UTC()

	// Entry as it would appear in existing accounts.json (no Type field -> Type="")
	entryEmpty := Entry{
		Type:   "",
		Secret: secret,
		Algo:   "SHA1",
		Digits: 8,
		Period: 30,
	}

	// Entry with explicit Type="totp"
	entryExplicit := Entry{
		Type:   "totp",
		Secret: secret,
		Algo:   "SHA1",
		Digits: 8,
		Period: 30,
	}

	codeEmpty, remainingEmpty, err := GenerateCode(entryEmpty, at)
	if err != nil {
		t.Fatalf("empty Type: unexpected error: %v", err)
	}

	codeExplicit, remainingExplicit, err := GenerateCode(entryExplicit, at)
	if err != nil {
		t.Fatalf("explicit totp Type: unexpected error: %v", err)
	}

	if codeEmpty != codeExplicit {
		t.Errorf("backward compat: empty Type produced %q, explicit totp produced %q — must be identical", codeEmpty, codeExplicit)
	}
	if remainingEmpty != remainingExplicit {
		t.Errorf("backward compat: remaining mismatch: empty=%d, explicit=%d", remainingEmpty, remainingExplicit)
	}
}

// TestGenerateCode_UnsupportedType verifies that an unrecognized OTP type returns a clear error.
func TestGenerateCode_UnsupportedType(t *testing.T) {
	entry := Entry{
		Type:   "yandex",
		Secret: base32.StdEncoding.EncodeToString([]byte("12345678901234567890")),
		Algo:   "SHA1",
		Digits: 6,
		Period: 30,
	}
	_, _, err := GenerateCode(entry, time.Now())
	if err == nil {
		t.Fatal("expected error for unsupported type 'yandex', got nil")
	}
	if !strings.Contains(err.Error(), "unsupported OTP type") {
		t.Errorf("error %q does not contain 'unsupported OTP type'", err.Error())
	}
}

// TestGenerateCode_HOTP_RFC4226Vectors validates HOTP generation against all 10 RFC 4226
// Appendix D test vectors (counter 0–9, SHA1, 6-digit codes).
// Secret: base32("12345678901234567890") = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
func TestGenerateCode_HOTP_RFC4226Vectors(t *testing.T) {
	// RFC 4226 test secret: raw bytes "12345678901234567890"
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	vectors := []struct {
		counter  uint64
		expected string
	}{
		{0, "755224"},
		{1, "287082"},
		{2, "359152"},
		{3, "969429"},
		{4, "338314"},
		{5, "254676"},
		{6, "287922"},
		{7, "162583"},
		{8, "399871"},
		{9, "520489"},
	}

	for _, v := range vectors {
		entry := Entry{
			Type:    "hotp",
			Secret:  secret,
			Algo:    "SHA1",
			Digits:  6,
			Counter: v.counter,
		}
		// time.Now() is irrelevant for HOTP — pass it to satisfy the signature
		code, remaining, err := GenerateCode(entry, time.Now())
		if err != nil {
			t.Errorf("counter=%d: unexpected error: %v", v.counter, err)
			continue
		}
		if code != v.expected {
			t.Errorf("counter=%d: got %q, want %q", v.counter, code, v.expected)
		}
		// HOTP has no time expiry — remaining must always be 0
		if remaining != 0 {
			t.Errorf("counter=%d: remaining=%d, want 0 (HOTP has no time expiry)", v.counter, remaining)
		}
	}
}

// TestGenerateCode_Steam verifies Steam Guard code generation produces valid output.
// Validates: code length is 5, all characters are in Steam alphabet, remaining is in [1,30].
func TestGenerateCode_Steam(t *testing.T) {
	const steamAlphabet = "23456789BCDFGHJKMNPQRTVWXY"

	entry := Entry{
		Type:   "steam",
		Secret: "JRZCL47CMXVOQMNPZR2F7J4RGI", // from Aegis test fixture (Sophia/Boeing)
		Algo:   "SHA1",
		Digits: 5,
		Period: 30,
	}

	// Use a fixed time so the test is deterministic.
	// t=1000000000 is 2001-09-08T21:46:40Z, well within 30s period boundaries.
	at := time.Unix(1000000000, 0).UTC()

	code, remaining, err := GenerateCode(entry, at)
	if err != nil {
		t.Fatalf("generateSteam: unexpected error: %v", err)
	}

	// Steam codes are always 5 characters
	if len(code) != 5 {
		t.Errorf("Steam code length = %d, want 5; code = %q", len(code), code)
	}

	// Every character must be in the Steam alphabet
	for i, ch := range code {
		if !strings.ContainsRune(steamAlphabet, ch) {
			t.Errorf("Steam code[%d] = %q is not in Steam alphabet %q (full code: %q)", i, ch, steamAlphabet, code)
		}
	}

	// remaining must be in [1, 30] for a 30s period
	if remaining < 1 || remaining > 30 {
		t.Errorf("Steam remaining=%d, want [1, 30]", remaining)
	}
}

// --- Phase 32: JSON round-trip tests for new Entry fields (Group, Note, UsageCount) ---

// TestEntryJSONNewFields covers JSON serialization for Group, Note, and UsageCount fields.
func TestEntryJSONNewFields(t *testing.T) {
	t.Run("round-trip preserves all fields", func(t *testing.T) {
		original := Entry{
			UUID:       "abc-123",
			Name:       "alice@example.com",
			Issuer:     "Example",
			Secret:     "JBSWY3DPEHPK3PXP",
			Algo:       "SHA1",
			Digits:     6,
			Period:     30,
			Type:       "totp",
			Counter:    0,
			Group:      "Work",
			Note:       "test note",
			UsageCount: 5,
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		var decoded Entry
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		if decoded.Group != "Work" {
			t.Errorf("Group = %q, want %q", decoded.Group, "Work")
		}
		if decoded.Note != "test note" {
			t.Errorf("Note = %q, want %q", decoded.Note, "test note")
		}
		if decoded.UsageCount != 5 {
			t.Errorf("UsageCount = %d, want 5", decoded.UsageCount)
		}
	})

	t.Run("backward compat: missing fields deserialize to zero values", func(t *testing.T) {
		// JSON from older versions without Group/Note/UsageCount
		oldJSON := `{"UUID":"old-1","Name":"bob","Issuer":"OldCorp","Secret":"JBSWY3DPEHPK3PXP","Algo":"SHA1","Digits":6,"Period":30}`

		var e Entry
		if err := json.Unmarshal([]byte(oldJSON), &e); err != nil {
			t.Fatalf("unmarshal old JSON: %v", err)
		}

		if e.Group != "" {
			t.Errorf("Group = %q, want empty string", e.Group)
		}
		if e.Note != "" {
			t.Errorf("Note = %q, want empty string", e.Note)
		}
		if e.UsageCount != 0 {
			t.Errorf("UsageCount = %d, want 0", e.UsageCount)
		}
		// Verify existing fields still work
		if e.UUID != "old-1" {
			t.Errorf("UUID = %q, want %q", e.UUID, "old-1")
		}
	})

	t.Run("omitempty: zero values omitted from JSON", func(t *testing.T) {
		e := Entry{
			UUID:   "test-1",
			Name:   "test",
			Secret: "JBSWY3DPEHPK3PXP",
			// Group, Note, UsageCount all zero
		}

		data, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		jsonStr := string(data)
		if strings.Contains(jsonStr, "Group") {
			t.Errorf("JSON should not contain 'Group' when empty, got: %s", jsonStr)
		}
		if strings.Contains(jsonStr, "Note") {
			t.Errorf("JSON should not contain 'Note' when empty, got: %s", jsonStr)
		}
		if strings.Contains(jsonStr, "UsageCount") {
			t.Errorf("JSON should not contain 'UsageCount' when zero, got: %s", jsonStr)
		}
	})

	t.Run("key casing: uppercase field names in JSON", func(t *testing.T) {
		e := Entry{
			UUID:       "test-2",
			Group:      "Personal",
			Note:       "my note",
			UsageCount: 1,
		}

		data, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		jsonStr := string(data)
		if !strings.Contains(jsonStr, `"Group"`) {
			t.Errorf("JSON should contain uppercase 'Group', got: %s", jsonStr)
		}
		if !strings.Contains(jsonStr, `"Note"`) {
			t.Errorf("JSON should contain uppercase 'Note', got: %s", jsonStr)
		}
		if !strings.Contains(jsonStr, `"UsageCount"`) {
			t.Errorf("JSON should contain uppercase 'UsageCount', got: %s", jsonStr)
		}
	})
}

// --- Phase 65-03: EffectivePeriod and EffectiveDigits ---

// TestEffectivePeriod verifies that EffectivePeriod returns 30 for Period=0 and passthrough otherwise.
func TestEffectivePeriod(t *testing.T) {
	tests := []struct {
		period uint
		want   uint
	}{
		{0, 30},  // HOTP/legacy zero defaults to 30
		{30, 30}, // explicit 30 passes through
		{60, 60}, // explicit 60 passes through
	}
	for _, tt := range tests {
		e := Entry{Period: tt.period}
		got := e.EffectivePeriod()
		if got != tt.want {
			t.Errorf("Entry{Period:%d}.EffectivePeriod() = %d, want %d", tt.period, got, tt.want)
		}
	}
}

// TestEffectiveDigits verifies that EffectiveDigits returns 6 for Digits=0 and passthrough otherwise.
func TestEffectiveDigits(t *testing.T) {
	tests := []struct {
		digits int
		want   int
	}{
		{0, 6}, // legacy zero defaults to 6
		{6, 6}, // explicit 6 passes through
		{8, 8}, // explicit 8 passes through
		{5, 5}, // explicit 5 passes through
	}
	for _, tt := range tests {
		e := Entry{Digits: tt.digits}
		got := e.EffectiveDigits()
		if got != tt.want {
			t.Errorf("Entry{Digits:%d}.EffectiveDigits() = %d, want %d", tt.digits, got, tt.want)
		}
	}
}

// --- Phase 36: Icon field JSON round-trip and backward compatibility ---

func TestIconField(t *testing.T) {
	t.Run("round-trip with Icon set", func(t *testing.T) {
		original := Entry{
			UUID:   "icon-1",
			Name:   "alice@github.com",
			Issuer: "GitHub",
			Secret: "JBSWY3DPEHPK3PXP",
			Algo:   "SHA1",
			Digits: 6,
			Period: 30,
			Type:   "totp",
			Icon:   "github",
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		var decoded Entry
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		if decoded.Icon != "github" {
			t.Errorf("Icon = %q, want %q", decoded.Icon, "github")
		}
	})

	t.Run("backward compat: JSON without Icon field", func(t *testing.T) {
		// Simulates pre-v2.6 data that has no Icon field
		oldJSON := `{"UUID":"old-icon","Name":"bob","Issuer":"OldCorp","Secret":"JBSWY3DPEHPK3PXP","Algo":"SHA1","Digits":6,"Period":30}`

		var e Entry
		if err := json.Unmarshal([]byte(oldJSON), &e); err != nil {
			t.Fatalf("unmarshal old JSON: %v", err)
		}

		if e.Icon != "" {
			t.Errorf("Icon = %q, want empty string for old data", e.Icon)
		}
		// Existing fields still work
		if e.UUID != "old-icon" {
			t.Errorf("UUID = %q, want %q", e.UUID, "old-icon")
		}
	})

	t.Run("omitempty: empty Icon omitted from JSON", func(t *testing.T) {
		e := Entry{
			UUID:   "icon-empty",
			Name:   "test",
			Secret: "JBSWY3DPEHPK3PXP",
			Icon:   "", // empty — should be omitted
		}

		data, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		jsonStr := string(data)
		if strings.Contains(jsonStr, "Icon") {
			t.Errorf("JSON should not contain 'Icon' when empty, got: %s", jsonStr)
		}
	})
}
