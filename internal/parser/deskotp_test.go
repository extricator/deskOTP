// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func loadDeskOTPFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("cannot read fixture %s: %v", name, err)
	}
	return data
}

func TestDeskOTPParser_Name(t *testing.T) {
	p := &DeskOTPParser{}
	if got := p.Name(); got != "deskOTP Backup" {
		t.Errorf("Name() = %q, want %q", got, "deskOTP Backup")
	}
}

func TestDeskOTPParser_CanParse(t *testing.T) {
	p := &DeskOTPParser{}
	data := loadDeskOTPFixture(t, "deskotp_plain.json")
	if !p.CanParse(data) {
		t.Error("CanParse(deskotp_plain.json) = false, want true")
	}
}

func TestDeskOTPParser_CanParse_RejectsAegis(t *testing.T) {
	p := &DeskOTPParser{}
	data := loadDeskOTPFixture(t, "aegis_plain.json")
	if p.CanParse(data) {
		t.Error("CanParse(aegis_plain.json) = true, want false (aegis has no deskotp_version)")
	}
}

func TestDeskOTPParser_Parse(t *testing.T) {
	p := &DeskOTPParser{}
	data := loadDeskOTPFixture(t, "deskotp_plain.json")
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(entries) < 1 {
		t.Fatalf("Parse() returned %d entries, want at least 1", len(entries))
	}

	first := entries[0]
	// Verify x-deskotp fields restored for entry 1 (GitHub/Alice)
	if first.Icon != "github" {
		t.Errorf("entries[0].Icon = %q, want %q", first.Icon, "github")
	}
	if first.UsageCount != 42 {
		t.Errorf("entries[0].UsageCount = %d, want 42", first.UsageCount)
	}
	if first.Group != "Work" {
		t.Errorf("entries[0].Group = %q, want %q", first.Group, "Work")
	}
	if first.Note != "work account" {
		t.Errorf("entries[0].Note = %q, want %q", first.Note, "work account")
	}
}

func TestDeskOTPParser_Parse_NoExtension(t *testing.T) {
	p := &DeskOTPParser{}
	data := loadDeskOTPFixture(t, "deskotp_plain.json")
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(entries) < 2 {
		t.Fatalf("Parse() returned %d entries, want at least 2", len(entries))
	}

	second := entries[1]
	// Entry 2 has empty x-deskotp object — expect zero values, no error
	if second.Icon != "" {
		t.Errorf("entries[1].Icon = %q, want empty string", second.Icon)
	}
	if second.UsageCount != 0 {
		t.Errorf("entries[1].UsageCount = %d, want 0", second.UsageCount)
	}
	if second.Group != "" {
		t.Errorf("entries[1].Group = %q, want empty string", second.Group)
	}
}

// --- DeskOTPEncryptedParser tests ---

func TestDeskOTPEncryptedParser_Name(t *testing.T) {
	p := &DeskOTPEncryptedParser{}
	if got := p.Name(); got != "deskOTP Backup (Encrypted)" {
		t.Errorf("Name() = %q, want %q", got, "deskOTP Backup (Encrypted)")
	}
}

func TestDeskOTPEncryptedParser_CanParse(t *testing.T) {
	p := &DeskOTPEncryptedParser{}
	data := loadDeskOTPFixture(t, "deskotp_encrypted.json")
	if !p.CanParse(data) {
		t.Error("CanParse(deskotp_encrypted.json) = false, want true")
	}
}

func TestDeskOTPEncryptedParser_CanParse_RejectsAegisEncrypted(t *testing.T) {
	p := &DeskOTPEncryptedParser{}
	data := loadDeskOTPFixture(t, "aegis_encrypted.json")
	if p.CanParse(data) {
		t.Error("CanParse(aegis_encrypted.json) = true, want false (aegis encrypted uses 'db' key, not 'data')")
	}
}

func TestDeskOTPEncryptedParser_Parse(t *testing.T) {
	p := &DeskOTPEncryptedParser{}
	data := loadDeskOTPFixture(t, "deskotp_encrypted.json")
	entries, err := p.Parse(data, "testpassword")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(entries) < 1 {
		t.Fatalf("Parse() returned %d entries, want at least 1", len(entries))
	}

	first := entries[0]
	// Verify x-deskotp fields restored for entry 1 (GitHub/Alice)
	if first.Icon != "github" {
		t.Errorf("entries[0].Icon = %q, want %q", first.Icon, "github")
	}
	if first.UsageCount != 42 {
		t.Errorf("entries[0].UsageCount = %d, want 42", first.UsageCount)
	}
	if first.Group != "Work" {
		t.Errorf("entries[0].Group = %q, want %q", first.Group, "Work")
	}
	if first.Note != "work account" {
		t.Errorf("entries[0].Note = %q, want %q", first.Note, "work account")
	}
}

func TestDeskOTPEncryptedParser_Parse_NoPassword(t *testing.T) {
	p := &DeskOTPEncryptedParser{}
	data := loadDeskOTPFixture(t, "deskotp_encrypted.json")
	_, err := p.Parse(data, "")
	if !errors.Is(err, ErrPasswordRequired) {
		t.Errorf("Parse() error = %v, want ErrPasswordRequired", err)
	}
}

func TestDeskOTPEncryptedParser_Parse_WrongPassword(t *testing.T) {
	p := &DeskOTPEncryptedParser{}
	data := loadDeskOTPFixture(t, "deskotp_encrypted.json")
	_, err := p.Parse(data, "wrongpassword")
	if !errors.Is(err, ErrWrongPassword) {
		t.Errorf("Parse() error = %v, want ErrWrongPassword", err)
	}
}

func TestDeskOTPParser_Parse_OTPFields(t *testing.T) {
	p := &DeskOTPParser{}
	data := loadDeskOTPFixture(t, "deskotp_plain.json")
	entries, err := p.Parse(data, "")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(entries) < 2 {
		t.Fatalf("Parse() returned %d entries, want 2", len(entries))
	}

	// Entry 1: GitHub/Alice — SHA1, 6 digits, 30s period
	e1 := entries[0]
	if e1.Name != "Alice" {
		t.Errorf("entries[0].Name = %q, want %q", e1.Name, "Alice")
	}
	if e1.Issuer != "GitHub" {
		t.Errorf("entries[0].Issuer = %q, want %q", e1.Issuer, "GitHub")
	}
	if e1.Secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("entries[0].Secret = %q, want %q", e1.Secret, "JBSWY3DPEHPK3PXP")
	}
	if e1.Algo != "SHA1" {
		t.Errorf("entries[0].Algo = %q, want %q", e1.Algo, "SHA1")
	}
	if e1.Digits != 6 {
		t.Errorf("entries[0].Digits = %d, want 6", e1.Digits)
	}
	if e1.Period != 30 {
		t.Errorf("entries[0].Period = %d, want 30", e1.Period)
	}

	// Entry 2: Google/Bob — SHA256, 8 digits, 60s period
	e2 := entries[1]
	if e2.Name != "Bob" {
		t.Errorf("entries[1].Name = %q, want %q", e2.Name, "Bob")
	}
	if e2.Issuer != "Google" {
		t.Errorf("entries[1].Issuer = %q, want %q", e2.Issuer, "Google")
	}
	if e2.Secret != "4SJHB4GSD43FZBAI7C2HLRJGPQ" {
		t.Errorf("entries[1].Secret = %q, want %q", e2.Secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ")
	}
	if e2.Algo != "SHA256" {
		t.Errorf("entries[1].Algo = %q, want %q", e2.Algo, "SHA256")
	}
	if e2.Digits != 8 {
		t.Errorf("entries[1].Digits = %d, want 8", e2.Digits)
	}
	if e2.Period != 60 {
		t.Errorf("entries[1].Period = %d, want 60", e2.Period)
	}
}
