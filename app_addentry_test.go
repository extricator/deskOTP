// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

import (
	"testing"

	"deskotp/internal/settings"
	"deskotp/internal/vault"
)

// ---------------------------------------------------------------------------
// TestGetIconSuggestion: "GitHub" returns "github".
// ---------------------------------------------------------------------------

func TestGetIconSuggestion(t *testing.T) {
	app := &App{
		settings: settings.New(),
		keyCache: vault.NewKeyCache(),
	}

	got := app.GetIconSuggestion("GitHub")
	if got != "github" {
		t.Errorf("GetIconSuggestion(%q) = %q, want %q", "GitHub", got, "github")
	}
}

// ---------------------------------------------------------------------------
// TestGetIconSuggestion_Unknown: unrecognized issuer returns "".
// ---------------------------------------------------------------------------

func TestGetIconSuggestion_Unknown(t *testing.T) {
	app := &App{
		settings: settings.New(),
		keyCache: vault.NewKeyCache(),
	}

	got := app.GetIconSuggestion("Some Random Corp")
	if got != "" {
		t.Errorf("GetIconSuggestion(%q) = %q, want %q", "Some Random Corp", got, "")
	}
}

// ---------------------------------------------------------------------------
// TestParseAndPreviewURI_Valid: valid otpauth:// URI returns populated URIPreview.
// ---------------------------------------------------------------------------

func TestParseAndPreviewURI_Valid(t *testing.T) {
	app := &App{
		settings: settings.New(),
		keyCache: vault.NewKeyCache(),
	}

	uri := "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
	preview, err := app.ParseAndPreviewURI(uri)
	if err != nil {
		t.Fatalf("ParseAndPreviewURI: unexpected error: %v", err)
	}

	if preview.Type != "totp" {
		t.Errorf("Type = %q, want %q", preview.Type, "totp")
	}
	if preview.Issuer != "GitHub" {
		t.Errorf("Issuer = %q, want %q", preview.Issuer, "GitHub")
	}
	if preview.Name != "alice" {
		t.Errorf("Name = %q, want %q", preview.Name, "alice")
	}
	if preview.Secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("Secret = %q, want %q", preview.Secret, "JBSWY3DPEHPK3PXP")
	}
	if preview.Algo != "SHA1" {
		t.Errorf("Algo = %q, want %q", preview.Algo, "SHA1")
	}
	if preview.Digits != 6 {
		t.Errorf("Digits = %d, want %d", preview.Digits, 6)
	}
	if preview.Period != 30 {
		t.Errorf("Period = %d, want %d", preview.Period, 30)
	}
}

// ---------------------------------------------------------------------------
// TestParseAndPreviewURI_Invalid: non-URI returns error.
// ---------------------------------------------------------------------------

func TestParseAndPreviewURI_Invalid(t *testing.T) {
	app := &App{
		settings: settings.New(),
		keyCache: vault.NewKeyCache(),
	}

	_, err := app.ParseAndPreviewURI("not-a-uri")
	if err == nil {
		t.Fatal("ParseAndPreviewURI with invalid URI should return error, got nil")
	}
}

// ---------------------------------------------------------------------------
// TestParseAndPreviewURI_Whitespace: leading/trailing whitespace is trimmed.
// ---------------------------------------------------------------------------

func TestParseAndPreviewURI_Whitespace(t *testing.T) {
	app := &App{
		settings: settings.New(),
		keyCache: vault.NewKeyCache(),
	}

	uri := "  otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub  "
	preview, err := app.ParseAndPreviewURI(uri)
	if err != nil {
		t.Fatalf("ParseAndPreviewURI with whitespace: unexpected error: %v", err)
	}
	if preview.Type != "totp" {
		t.Errorf("Type = %q, want %q (whitespace should be trimmed)", preview.Type, "totp")
	}
}
