// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

//go:build linux

package lock_test

import (
	"context"
	"testing"
	"time"

	"deskotp/internal/lock"
)

// TestWatchCompiles verifies that the Watch function signature is correct
// and the package compiles. D-Bus is not available in the dev container,
// so we test the no-crash contract with a pre-cancelled context.
func TestWatchCompiles(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately -- Watch goroutines should exit quickly

	called := false
	onLock := func() { called = true }

	// Watch should not block (it launches goroutines and returns)
	done := make(chan struct{})
	go func() {
		lock.Watch(ctx, onLock)
		close(done)
	}()

	select {
	case <-done:
		// good -- returned promptly
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return promptly with cancelled context")
	}

	// Give goroutines a moment to exit (they see ctx.Done())
	time.Sleep(100 * time.Millisecond)

	// With a pre-cancelled context and no real D-Bus, onLock should not be called
	// (goroutines may fail to connect or exit immediately on ctx.Done())
	if called {
		t.Errorf("onLock was called unexpectedly when context was pre-cancelled")
	}
}

// TestWatchContextCancellation verifies graceful shutdown when ctx is cancelled.
func TestWatchContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	onLock := func() {}

	// Watch must not panic or block beyond context deadline
	// (goroutines will fail to connect to D-Bus and return, or exit on ctx.Done())
	lock.Watch(ctx, onLock)

	// Wait for context to expire + small buffer
	<-ctx.Done()
	time.Sleep(50 * time.Millisecond)
	// No panic = pass
}

// TestStubWatchDoesNotCallOnLock is validated by TestWatchCompiles for linux:
// on linux, the Watch may attempt D-Bus connections. The stub is tested on
// non-linux platforms by the build tag mechanism itself (compilation is the test).
// This test ensures the package function reference is callable.
func TestWatchFunctionReference(t *testing.T) {
	// Just verify the function can be referenced and called without panic
	// when context is immediately cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var fn func() = func() {}
	// Should not panic
	lock.Watch(ctx, fn)
}
