// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

//go:build !linux

package main

import "fmt"

// ScanQRScreen is a no-op stub for macOS and Windows.
// The "Scan screen" tile is hidden on non-Linux platforms via AddTokenPage.tsx
// (Phase 52). This stub returns a descriptive error as a belt-and-suspenders
// defense in case the method is called anyway.
func (a *App) ScanQRScreen() (URIPreview, error) {
	return URIPreview{}, fmt.Errorf("screen capture not supported on this platform")
}
