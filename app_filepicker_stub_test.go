// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

//go:build !linux

package main

import (
	"testing"
)

// TestPickFile_StubCallable validates PLAT-01:
// PickFile method exists on App and is callable on non-Linux.
// Without a Wails context, runtime.OpenFileDialog returns an error — that's expected.
// The test proves the method compiles and doesn't panic.
func TestPickFile_StubCallable(t *testing.T) {
	app := setupTestApp(t)
	// Will error because no Wails runtime context, but must not panic
	_, _ = app.PickFile()
}

// TestPickAndScanQRFile_StubCallable validates PLAT-01:
// PickAndScanQRFile method exists on App and is callable on non-Linux.
func TestPickAndScanQRFile_StubCallable(t *testing.T) {
	app := setupTestApp(t)
	_, _ = app.PickAndScanQRFile()
}

// TestPickBackupDir_StubCallable validates PLAT-01:
// PickBackupDir method exists on App and is callable on non-Linux.
func TestPickBackupDir_StubCallable(t *testing.T) {
	app := setupTestApp(t)
	_, _ = app.PickBackupDir()
}
