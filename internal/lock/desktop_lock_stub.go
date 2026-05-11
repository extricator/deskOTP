// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

//go:build !linux

package lock

import "context"

// Watch is a no-op stub for macOS and Windows.
// DSKL-03: no-op stub for macOS and Windows. Future: DSKL-04, DSKL-05
// On non-Linux platforms, desktop lock detection is not implemented.
// The function returns immediately without calling onLock.
func Watch(ctx context.Context, onLock func()) {
	_ = ctx
	_ = onLock
}
