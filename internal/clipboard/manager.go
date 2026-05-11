// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package clipboard

import (
	"strconv"
	"sync"
	"time"
)

// Manager owns the clipboard auto-clear timer, identity-check state, and mutex.
// All Wails runtime calls are replaced by injected function fields so the
// package has zero Wails imports and is independently testable.
type Manager struct {
	mu        sync.Mutex
	timer     *time.Timer
	code      string
	getTextFn func() (string, error)
	setTextFn func(string) error
	emitFn    func(string)
}

// New creates a Manager with the provided function fields wired.
// All three function arguments must be non-nil.
func New(getTextFn func() (string, error), setTextFn func(string) error, emitFn func(string)) *Manager {
	return &Manager{
		getTextFn: getTextFn,
		setTextFn: setTextFn,
		emitFn:    emitFn,
	}
}

// Start starts (or resets) the clipboard auto-clear timer.
// If a previous timer is active, it is stopped before the new one is created.
// Locks mu internally — caller must NOT hold mu.
func (m *Manager) Start(code string, dur time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.timer != nil {
		m.timer.Stop()
	}
	m.code = code
	m.timer = time.AfterFunc(dur, m.clear)
}

// ParseTimeout is the exported wrapper for parseClipTimeout.
// Returns the duration and whether to skip timer creation entirely.
func ParseTimeout(val string) (time.Duration, bool) {
	return parseClipTimeout(val)
}

// parseClipTimeout parses the clipboard_clear_timeout setting value.
// "never" returns skip=true; "" defaults to 30s; numeric converts to seconds;
// invalid or non-positive values default to 30s.
func parseClipTimeout(val string) (time.Duration, bool) {
	if val == "never" {
		return 0, true
	}
	if val == "" {
		return 30 * time.Second, false
	}
	secs, err := strconv.Atoi(val)
	if err != nil || secs <= 0 {
		return 30 * time.Second, false
	}
	return time.Duration(secs) * time.Second, false
}

// clear is the timer callback. It reads the current clipboard content,
// compares it to the expected code (identity check), and clears the clipboard
// only if the content matches. Emits a "clipboard:cleared" event on success.
// Uses a two-phase lock pattern: acquire mu to read expected + nil timer,
// then perform I/O outside the lock.
func (m *Manager) clear() {
	m.mu.Lock()
	expected := m.code
	m.timer = nil
	m.mu.Unlock()

	current, err := m.getTextFn()
	if err != nil {
		return
	}

	// Identity check: don't wipe if user replaced clipboard content.
	if current != expected {
		return
	}

	if err := m.setTextFn(""); err != nil {
		return
	}

	m.emitFn("clipboard:cleared")
}
