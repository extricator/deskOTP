// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

//go:build !linux

package main

import (
	"strings"
	"testing"
)

// TestScanQRScreen_StubReturnsError validates QRSC-04:
// On non-Linux platforms, ScanQRScreen returns a non-nil error with "not supported"
// in the message. The stub is active on non-Linux via the //go:build !linux tag.
func TestScanQRScreen_StubReturnsError(t *testing.T) {
	app := setupTestApp(t)

	_, err := app.ScanQRScreen()

	if err == nil {
		t.Fatal("ScanQRScreen() error = nil, want non-nil on non-Linux stub")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Errorf("ScanQRScreen() error = %q, want message containing \"not supported\"", err.Error())
	}
}

// TestScanQRScreen_StubReturnsEmptyPreview validates QRSC-04:
// On non-Linux platforms, ScanQRScreen returns a zero-value URIPreview.
func TestScanQRScreen_StubReturnsEmptyPreview(t *testing.T) {
	app := setupTestApp(t)

	preview, _ := app.ScanQRScreen()

	if preview.Issuer != "" {
		t.Errorf("ScanQRScreen() preview.Issuer = %q, want empty", preview.Issuer)
	}
	if preview.Name != "" {
		t.Errorf("ScanQRScreen() preview.Name = %q, want empty", preview.Name)
	}
	if preview.Secret != "" {
		t.Errorf("ScanQRScreen() preview.Secret = %q, want empty", preview.Secret)
	}
}
