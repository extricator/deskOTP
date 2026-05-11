// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

// Package backup serializes totp.Entry slices into Aegis-compatible backup JSON.
// Manager handles debounced writes and goroutine lifecycle.
package backup

import (
	"context"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/bep/debounce"

	"deskotp/internal/settings"
)

const (
	// flushTimeout is the maximum time allowed for a writeFn call during shutdown.
	flushTimeout = 5 * time.Second

	// productionDebounce is the debounce duration used in production.
	productionDebounce = 30 * time.Second

	// productionTickInterval is how often the schedule checker fires in production.
	productionTickInterval = 15 * time.Minute

	// productionInitDelay is the startup delay before the first overdue check.
	productionInitDelay = 5 * time.Second

	settingsKeySchedule   = "backup_schedule"
	settingsKeyLastBackup = "backup_last_backup"
	settingsKeyLastError  = "backup_last_error"
)

// Manager manages debounced backup writes with goroutine lifecycle management.
// The writer goroutine owns all writeFn calls; trigger paths (debounce, schedule)
// send signals via a buffered channel.
type Manager struct {
	writeFn      func() error
	store        *settings.Store
	writeCh      chan struct{}
	flushing     atomic.Bool
	pending      atomic.Bool // true when NotifyChanged was called but write not yet dispatched
	debounced    func(f func())
	done         chan struct{}
	tickInterval time.Duration // defaults to 15min; configurable for tests
	initDelay    time.Duration // defaults to 5s; configurable for tests
}

// New constructs a Manager with a 30-second debounce duration.
func New(writeFn func() error, store *settings.Store) *Manager {
	return newWithDuration(writeFn, store, productionDebounce)
}

// NewWithDuration constructs a Manager with a custom debounce duration.
// Exported for use in tests in package backup_test.
func NewWithDuration(writeFn func() error, store *settings.Store, duration time.Duration) *Manager {
	return newWithDuration(writeFn, store, duration)
}

// NewForTest constructs a Manager with fully configurable intervals for testing.
// This allows tests to use short tick and init-delay durations.
func NewForTest(writeFn func() error, store *settings.Store, debounceDuration, tickInterval, initDelay time.Duration) *Manager {
	m := newWithDuration(writeFn, store, debounceDuration)
	m.tickInterval = tickInterval
	m.initDelay = initDelay
	return m
}

// newWithDuration is the internal constructor shared by New and NewWithDuration.
func newWithDuration(writeFn func() error, store *settings.Store, duration time.Duration) *Manager {
	m := &Manager{
		writeFn:      writeFn,
		store:        store,
		writeCh:      make(chan struct{}, 1),
		done:         make(chan struct{}),
		tickInterval: productionTickInterval,
		initDelay:    productionInitDelay,
	}
	m.debounced = debounce.New(duration)
	return m
}

// Start launches the writer goroutine, startup overdue check goroutine, and
// schedule ticker goroutine. All goroutines exit when ctx is cancelled.
func (m *Manager) Start(ctx context.Context) {
	// Writer goroutine: owns all writeFn calls.
	go func() {
		defer close(m.done)
		for {
			select {
			case <-m.writeCh:
				m.doWrite(ctx)
			case <-ctx.Done():
				m.flushOnShutdown()
				return
			}
		}
	}()

	// Startup overdue check: fires once after initDelay if schedule is overdue.
	go func() {
		select {
		case <-time.After(m.initDelay):
			if m.isOverdue() {
				m.enqueue()
			}
		case <-ctx.Done():
			return
		}
	}()

	// Schedule ticker: fires every tickInterval to check for overdue backups.
	go func() {
		ticker := time.NewTicker(m.tickInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if m.isOverdue() {
					m.enqueue()
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// isOverdue reports whether a backup is overdue according to the schedule and
// the last backup timestamp stored in settings.
//
// Rules:
//   - schedule "off" or "" → never overdue
//   - empty or unparseable backup_last_backup → overdue (treat as never backed up)
//   - "daily" → overdue when time.Since(last) > 24h
//   - "weekly" → overdue when time.Since(last) > 168h
func (m *Manager) isOverdue() bool {
	sched := m.store.Get(settingsKeySchedule)
	if sched == "off" || sched == "" {
		return false
	}

	var interval time.Duration
	switch sched {
	case "daily":
		interval = 24 * time.Hour
	case "weekly":
		interval = 168 * time.Hour
	default:
		return false
	}

	raw := m.store.Get(settingsKeyLastBackup)
	if raw == "" {
		return true // never backed up
	}
	ts, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return true // unparseable → treat as never backed up
	}
	last := time.Unix(ts, 0)
	return time.Since(last) > interval
}

// IsOverdue is the exported form of isOverdue for use in tests.
func (m *Manager) IsOverdue() bool {
	return m.isOverdue()
}

// NotifyChanged signals that vault data has changed and a backup may be needed.
// If backup_schedule is "off" or empty, this is a no-op.
func (m *Manager) NotifyChanged() {
	sched := m.store.Get(settingsKeySchedule)
	if sched == "off" || sched == "" {
		return
	}
	m.pending.Store(true)
	m.debounced(m.enqueue)
}

// IsFlushing returns true when the manager is performing a shutdown flush.
func (m *Manager) IsFlushing() bool {
	return m.flushing.Load()
}

// Wait blocks until the writer goroutine has exited. Call after cancelling the
// context passed to Start. Useful in tests to ensure goroutines exit before
// TempDir cleanup runs.
//
// Wait gates only on the writer goroutine (via the done channel). The startup
// overdue-check and schedule ticker goroutines exit independently via ctx.Done
// and are not tracked by Wait.
func (m *Manager) Wait() {
	<-m.done
}

// enqueue sends a non-blocking signal to writeCh.
// If a signal is already pending, the new one is dropped (idempotent).
func (m *Manager) enqueue() {
	select {
	case m.writeCh <- struct{}{}:
	default:
	}
}

// doWrite calls writeFn and persists the result to settings.
// It accepts ctx so that a mid-flight writeFn is bounded on shutdown:
// if ctx is cancelled while writeFn is running, a flushTimeout grace window
// is applied and backup_last_error is persisted if the timeout fires.
//
// On success: persists Unix timestamp to backup_last_backup and clears backup_last_error.
// On error: persists error message to backup_last_error.
func (m *Manager) doWrite(ctx context.Context) {
	m.pending.Store(false)

	type result struct{ err error }
	// Buffered (cap 1) so the goroutine can send even if the parent select
	// takes the ctx.Done branch. Without the buffer the goroutine would block
	// on the send forever, leaking.
	ch := make(chan result, 1)
	go func() { ch <- result{m.writeFn()} }()

	select {
	case r := <-ch:
		if r.err != nil {
			_ = m.store.Set(settingsKeyLastError, r.err.Error())
			return
		}
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		_ = m.store.Set(settingsKeyLastBackup, ts)
		_ = m.store.Set(settingsKeyLastError, "")
	case <-ctx.Done():
		// Context cancelled while writeFn is mid-flight.
		// Apply the flush timeout to give writeFn a grace window.
		m.flushing.Store(true)
		select {
		case r := <-ch:
			m.flushing.Store(false)
			if r.err != nil {
				_ = m.store.Set(settingsKeyLastError, r.err.Error())
				return
			}
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			_ = m.store.Set(settingsKeyLastBackup, ts)
			_ = m.store.Set(settingsKeyLastError, "")
		case <-time.After(flushTimeout):
			m.flushing.Store(false)
			msg := fmt.Sprintf("backup: flush timed out after %s", flushTimeout)
			_ = m.store.Set(settingsKeyLastError, msg)
		}
	}
}

// flushOnShutdown runs any pending writeFn with a 5-second timeout.
// It sets flushing=true for the duration so callers can surface an exit dialog.
// A write is "pending" if NotifyChanged was called but writeFn hasn't run yet
// (the debounce may not have fired yet when shutdown is requested).
func (m *Manager) flushOnShutdown() {
	// Check for pending work: either writeCh has a signal or pending flag is set
	// (the debounce hasn't fired yet but NotifyChanged was called).
	hasPending := false
	select {
	case <-m.writeCh:
		hasPending = true
	default:
		if m.pending.Load() {
			hasPending = true
		}
	}
	if !hasPending {
		return
	}

	m.pending.Store(false)
	m.flushing.Store(true)
	defer m.flushing.Store(false)

	type result struct{ err error }
	// Buffered (cap 1) so the goroutine can send even if the parent select
	// takes the time.After branch. Without the buffer the goroutine would
	// block on the send forever, leaking.
	ch := make(chan result, 1)
	go func() {
		ch <- result{m.writeFn()}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			_ = m.store.Set(settingsKeyLastError, r.err.Error())
		} else {
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			_ = m.store.Set(settingsKeyLastBackup, ts)
			_ = m.store.Set(settingsKeyLastError, "")
		}
	case <-time.After(flushTimeout):
		msg := fmt.Sprintf("backup: flush timed out after %s", flushTimeout)
		_ = m.store.Set(settingsKeyLastError, msg)
	}
}
