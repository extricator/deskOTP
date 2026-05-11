// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package backup_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"deskotp/internal/backup"
	"deskotp/internal/settings"
)

// fakeStore creates a temporary settings.Store for testing.
// It sets the config dir override so Store writes to a temp directory.
func fakeStore(t *testing.T) *settings.Store {
	t.Helper()
	dir := t.TempDir()
	restore := settings.SetConfigDirOverride(dir)
	t.Cleanup(restore)
	store := settings.New()
	if err := store.Load(); err != nil {
		t.Fatalf("fakeStore: Load: %v", err)
	}
	return store
}

// TestManager_DebounceCoalesces verifies that 50 rapid NotifyChanged calls
// with a short debounce duration produce exactly 1 writeFn call.
func TestManager_DebounceCoalesces(t *testing.T) {
	store := fakeStore(t)
	// Enable debounce by setting schedule to something other than "off"/"".
	if err := store.Set("backup_schedule", "daily"); err != nil {
		t.Fatalf("Set schedule: %v", err)
	}

	var writeCount atomic.Int32
	writeFn := func() error {
		writeCount.Add(1)
		return nil
	}

	m := backup.NewWithDuration(writeFn, store, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); m.Wait() })
	m.Start(ctx)

	for i := 0; i < 50; i++ {
		m.NotifyChanged()
	}

	// Wait for debounce to fire + write to complete.
	time.Sleep(200 * time.Millisecond)

	if got := writeCount.Load(); got != 1 {
		t.Errorf("want 1 writeFn call, got %d", got)
	}
}

// TestManager_GoroutineExitsOnCancel verifies the writer goroutine exits within
// 1 second of context cancellation.
func TestManager_GoroutineExitsOnCancel(t *testing.T) {
	store := fakeStore(t)
	writeFn := func() error { return nil }

	baseline := runtime.NumGoroutine()
	m := backup.NewWithDuration(writeFn, store, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)

	// Cancel and wait up to 1 second for goroutine to exit.
	cancel()
	time.Sleep(200 * time.Millisecond)
	m.Wait()

	after := runtime.NumGoroutine()
	// Allow ±1 goroutine for runtime variance.
	if after > baseline+1 {
		t.Errorf("goroutine leak: before Start=%d, after cancel=%d", baseline, after)
	}
}

// TestManager_FlushOnShutdown verifies that a pending debounce write is flushed
// on shutdown (not discarded) even when cancel is called immediately after NotifyChanged.
func TestManager_FlushOnShutdown(t *testing.T) {
	store := fakeStore(t)
	if err := store.Set("backup_schedule", "daily"); err != nil {
		t.Fatalf("Set schedule: %v", err)
	}

	var writeCount atomic.Int32
	writeFn := func() error {
		writeCount.Add(1)
		return nil
	}

	m := backup.NewWithDuration(writeFn, store, 500*time.Millisecond) // long debounce
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)

	m.NotifyChanged()
	// Cancel before debounce fires — flush must still run writeFn.
	cancel()
	m.Wait()

	if got := writeCount.Load(); got != 1 {
		t.Errorf("want 1 writeFn call on shutdown flush, got %d", got)
	}
}

// TestManager_FlushTimeout verifies that a slow writeFn (10s) during shutdown
// is terminated after the 5s timeout and the error is persisted to settings.
func TestManager_FlushTimeout(t *testing.T) {
	store := fakeStore(t)
	if err := store.Set("backup_schedule", "daily"); err != nil {
		t.Fatalf("Set schedule: %v", err)
	}

	writeFn := func() error {
		time.Sleep(10 * time.Second) // Deliberately slow.
		return nil
	}

	m := backup.NewWithDuration(writeFn, store, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)

	m.NotifyChanged()
	time.Sleep(100 * time.Millisecond) // Let debounce fire and writeFn start.
	cancel()

	// Wait for flush to time out (5s) plus margin.
	time.Sleep(6 * time.Second)
	m.Wait()

	errVal := store.Get("backup_last_error")
	if errVal == "" {
		t.Error("want backup_last_error set after flush timeout, got empty")
	}
}

// TestManager_IsFlushing verifies IsFlushing returns true during flush and false after.
func TestManager_IsFlushing(t *testing.T) {
	store := fakeStore(t)
	if err := store.Set("backup_schedule", "daily"); err != nil {
		t.Fatalf("Set schedule: %v", err)
	}

	started := make(chan struct{})
	proceed := make(chan struct{})
	writeFn := func() error {
		close(started)
		<-proceed
		return nil
	}

	m := backup.NewWithDuration(writeFn, store, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)

	m.NotifyChanged()
	// Cancel before debounce — triggers flush.
	cancel()
	t.Cleanup(func() { m.Wait() })

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("writeFn not called within 2 seconds")
	}

	if !m.IsFlushing() {
		t.Error("want IsFlushing()=true during flush, got false")
	}

	close(proceed) // Let writeFn complete.
	time.Sleep(100 * time.Millisecond)

	if m.IsFlushing() {
		t.Error("want IsFlushing()=false after flush, got true")
	}
}

// TestManager_TimestampPersistedAfterWrite verifies that after a successful
// writeFn call, backup_last_backup contains a recent Unix timestamp.
func TestManager_TimestampPersistedAfterWrite(t *testing.T) {
	store := fakeStore(t)
	if err := store.Set("backup_schedule", "daily"); err != nil {
		t.Fatalf("Set schedule: %v", err)
	}

	done := make(chan struct{})
	writeFn := func() error {
		defer close(done)
		return nil
	}

	m := backup.NewWithDuration(writeFn, store, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); m.Wait() })
	m.Start(ctx)

	before := time.Now().Unix()
	m.NotifyChanged()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("writeFn not called within 2 seconds")
	}
	time.Sleep(50 * time.Millisecond) // Let timestamp persist.

	ts := store.Get("backup_last_backup")
	if ts == "" {
		t.Fatal("want backup_last_backup set, got empty")
	}

	var tsInt int64
	if _, err := fmt.Sscan(ts, &tsInt); err != nil {
		t.Fatalf("backup_last_backup not a valid int64: %q", ts)
	}
	after := time.Now().Unix()
	if tsInt < before || tsInt > after+1 {
		t.Errorf("timestamp %d out of range [%d, %d]", tsInt, before, after+1)
	}
}

// TestManager_ErrorPersistedAfterFailure verifies that when writeFn returns an
// error, it is persisted to backup_last_error.
func TestManager_ErrorPersistedAfterFailure(t *testing.T) {
	store := fakeStore(t)
	if err := store.Set("backup_schedule", "daily"); err != nil {
		t.Fatalf("Set schedule: %v", err)
	}

	done := make(chan struct{})
	writeFn := func() error {
		defer close(done)
		return errors.New("disk full")
	}

	m := backup.NewWithDuration(writeFn, store, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); m.Wait() })
	m.Start(ctx)

	m.NotifyChanged()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("writeFn not called within 2 seconds")
	}
	time.Sleep(50 * time.Millisecond)

	errVal := store.Get("backup_last_error")
	if errVal == "" {
		t.Error("want backup_last_error set after writeFn failure, got empty")
	}
}

// newForTest creates a Manager with configurable debounce, tick, and init-delay
// durations. This allows tests to use short intervals and verify schedule/overdue
// behavior without waiting for production-scale timers.
func newForTest(writeFn func() error, store *settings.Store, debounceDuration, tickInterval, initDelay time.Duration) *backup.Manager {
	return backup.NewForTest(writeFn, store, debounceDuration, tickInterval, initDelay)
}

// TestManager_IsOverdue_Daily verifies that with daily schedule and a timestamp
// 25 hours ago, isOverdue returns true.
func TestManager_IsOverdue_Daily(t *testing.T) {
	store := fakeStore(t)
	if err := store.Set("backup_schedule", "daily"); err != nil {
		t.Fatalf("Set schedule: %v", err)
	}
	// 25 hours ago is overdue for daily (24h interval).
	ts := time.Now().Add(-25 * time.Hour).Unix()
	if err := store.Set("backup_last_backup", strconv.FormatInt(ts, 10)); err != nil {
		t.Fatalf("Set last_backup: %v", err)
	}

	m := newForTest(func() error { return nil }, store, 50*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)
	if !m.IsOverdue() {
		t.Error("want IsOverdue()=true for daily with 25h-ago timestamp, got false")
	}
}

// TestManager_IsOverdue_NotYet verifies that with daily schedule and a timestamp
// 1 hour ago, isOverdue returns false.
func TestManager_IsOverdue_NotYet(t *testing.T) {
	store := fakeStore(t)
	if err := store.Set("backup_schedule", "daily"); err != nil {
		t.Fatalf("Set schedule: %v", err)
	}
	ts := time.Now().Add(-1 * time.Hour).Unix()
	if err := store.Set("backup_last_backup", strconv.FormatInt(ts, 10)); err != nil {
		t.Fatalf("Set last_backup: %v", err)
	}

	m := newForTest(func() error { return nil }, store, 50*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)
	if m.IsOverdue() {
		t.Error("want IsOverdue()=false for daily with 1h-ago timestamp, got true")
	}
}

// TestManager_IsOverdue_Weekly verifies that with weekly schedule and a timestamp
// 169 hours ago, isOverdue returns true.
func TestManager_IsOverdue_Weekly(t *testing.T) {
	store := fakeStore(t)
	if err := store.Set("backup_schedule", "weekly"); err != nil {
		t.Fatalf("Set schedule: %v", err)
	}
	ts := time.Now().Add(-169 * time.Hour).Unix()
	if err := store.Set("backup_last_backup", strconv.FormatInt(ts, 10)); err != nil {
		t.Fatalf("Set last_backup: %v", err)
	}

	m := newForTest(func() error { return nil }, store, 50*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)
	if !m.IsOverdue() {
		t.Error("want IsOverdue()=true for weekly with 169h-ago timestamp, got false")
	}
}

// TestManager_IsOverdue_NeverBackedUp verifies that with daily schedule and an
// empty backup_last_backup, isOverdue returns true (never backed up = overdue).
func TestManager_IsOverdue_NeverBackedUp(t *testing.T) {
	store := fakeStore(t)
	if err := store.Set("backup_schedule", "daily"); err != nil {
		t.Fatalf("Set schedule: %v", err)
	}
	// backup_last_backup is empty (default for new store).

	m := newForTest(func() error { return nil }, store, 50*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)
	if !m.IsOverdue() {
		t.Error("want IsOverdue()=true when never backed up (empty timestamp), got false")
	}
}

// TestManager_IsOverdue_ScheduleOff verifies that with schedule="off", isOverdue
// always returns false regardless of the timestamp.
func TestManager_IsOverdue_ScheduleOff(t *testing.T) {
	store := fakeStore(t)
	if err := store.Set("backup_schedule", "off"); err != nil {
		t.Fatalf("Set schedule: %v", err)
	}
	// Even with an ancient timestamp, off schedule means not overdue.
	ts := time.Now().Add(-365 * 24 * time.Hour).Unix()
	if err := store.Set("backup_last_backup", strconv.FormatInt(ts, 10)); err != nil {
		t.Fatalf("Set last_backup: %v", err)
	}

	m := newForTest(func() error { return nil }, store, 50*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)
	if m.IsOverdue() {
		t.Error("want IsOverdue()=false when schedule=off, got true")
	}
}

// TestManager_StartupOverdue verifies that when overdue on startup, writeFn is
// called once after the init delay.
func TestManager_StartupOverdue(t *testing.T) {
	store := fakeStore(t)
	if err := store.Set("backup_schedule", "daily"); err != nil {
		t.Fatalf("Set schedule: %v", err)
	}
	ts := time.Now().Add(-25 * time.Hour).Unix()
	if err := store.Set("backup_last_backup", strconv.FormatInt(ts, 10)); err != nil {
		t.Fatalf("Set last_backup: %v", err)
	}

	var writeCount atomic.Int32
	done := make(chan struct{}, 1)
	writeFn := func() error {
		if writeCount.Add(1) == 1 {
			select {
			case done <- struct{}{}:
			default:
			}
		}
		return nil
	}

	m := newForTest(writeFn, store, 50*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	t.Cleanup(func() { cancel(); m.Wait() })

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("writeFn not called within 500ms for startup overdue check")
	}

	if got := writeCount.Load(); got != 1 {
		t.Errorf("want 1 writeFn call for startup overdue, got %d", got)
	}
}

// TestManager_StartupNotOverdue verifies that when not overdue on startup, writeFn
// is NOT called during startup.
func TestManager_StartupNotOverdue(t *testing.T) {
	store := fakeStore(t)
	if err := store.Set("backup_schedule", "daily"); err != nil {
		t.Fatalf("Set schedule: %v", err)
	}
	ts := time.Now().Add(-1 * time.Hour).Unix()
	if err := store.Set("backup_last_backup", strconv.FormatInt(ts, 10)); err != nil {
		t.Fatalf("Set last_backup: %v", err)
	}

	var writeCount atomic.Int32
	writeFn := func() error {
		writeCount.Add(1)
		return nil
	}

	m := newForTest(writeFn, store, 50*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	t.Cleanup(func() { cancel(); m.Wait() })

	// Wait for init delay plus margin; writeFn should NOT have been called.
	time.Sleep(300 * time.Millisecond)

	if got := writeCount.Load(); got != 0 {
		t.Errorf("want 0 writeFn calls when not overdue on startup, got %d", got)
	}
}

// TestManager_ScheduleTick verifies that when overdue, the schedule ticker calls
// writeFn without any NotifyChanged call.
func TestManager_ScheduleTick(t *testing.T) {
	store := fakeStore(t)
	if err := store.Set("backup_schedule", "daily"); err != nil {
		t.Fatalf("Set schedule: %v", err)
	}
	ts := time.Now().Add(-25 * time.Hour).Unix()
	if err := store.Set("backup_last_backup", strconv.FormatInt(ts, 10)); err != nil {
		t.Fatalf("Set last_backup: %v", err)
	}

	var writeCount atomic.Int32
	done := make(chan struct{}, 1)
	writeFn := func() error {
		if writeCount.Add(1) == 1 {
			select {
			case done <- struct{}{}:
			default:
			}
		}
		return nil
	}

	// Use a very long init delay (10s) so only the ticker fires, not startup check.
	m := newForTest(writeFn, store, 50*time.Millisecond, 100*time.Millisecond, 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	t.Cleanup(func() { cancel(); m.Wait() })

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("writeFn not called within 500ms via schedule ticker")
	}

	if got := writeCount.Load(); got < 1 {
		t.Errorf("want at least 1 writeFn call from schedule tick, got %d", got)
	}
}

// TestManager_ScheduleOffDisablesDebounce verifies that when backup_schedule is
// "off", NotifyChanged does not trigger writeFn.
func TestManager_ScheduleOffDisablesDebounce(t *testing.T) {
	store := fakeStore(t)
	if err := store.Set("backup_schedule", "off"); err != nil {
		t.Fatalf("Set schedule: %v", err)
	}

	var writeCount atomic.Int32
	writeFn := func() error {
		writeCount.Add(1)
		return nil
	}

	m := backup.NewWithDuration(writeFn, store, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); m.Wait() })
	m.Start(ctx)

	for i := 0; i < 10; i++ {
		m.NotifyChanged()
	}

	time.Sleep(200 * time.Millisecond)

	if got := writeCount.Load(); got != 0 {
		t.Errorf("want 0 writeFn calls when schedule=off, got %d", got)
	}
}
