// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package clipboard

import (
	"fmt"
	"testing"
	"time"
)

// fakeClip simulates clipboard read/write for testing.
type fakeClip struct {
	text          string
	err           error
	setCalled     bool
	setCalledWith string
	emitCalled    bool
	emitEvent     string
}

func (fc *fakeClip) getText() (string, error) {
	return fc.text, fc.err
}

func (fc *fakeClip) setText(s string) error {
	fc.setCalled = true
	fc.setCalledWith = s
	return nil
}

// newTestManager creates a Manager wired to a fakeClip for testing.
func newTestManager(fc *fakeClip) *Manager {
	return New(
		fc.getText,
		fc.setText,
		func(event string) {
			fc.emitCalled = true
			fc.emitEvent = event
		},
	)
}

// TestClipboardClearTimerManagement verifies clipboard clear timer field management.
func TestClipboardClearTimerManagement(t *testing.T) {
	t.Run("Start sets timer and code", func(t *testing.T) {
		fc := &fakeClip{}
		m := newTestManager(fc)

		m.Start("123456", 10*time.Second)

		m.mu.Lock()
		hasTimer := m.timer != nil
		code := m.code
		m.mu.Unlock()

		if !hasTimer {
			t.Error("timer should not be nil after Start")
		}
		if code != "123456" {
			t.Errorf("code = %q, want %q", code, "123456")
		}
	})

	t.Run("Start resets previous timer (only one active)", func(t *testing.T) {
		fc := &fakeClip{}
		m := newTestManager(fc)

		// Start first timer
		m.Start("111111", 1*time.Hour)
		m.mu.Lock()
		firstTimer := m.timer
		m.mu.Unlock()

		// Start second timer — should cancel the first
		m.Start("222222", 1*time.Hour)
		m.mu.Lock()
		secondTimer := m.timer
		code := m.code
		m.mu.Unlock()

		if secondTimer == firstTimer {
			t.Error("second Start should create a new timer, not reuse the old one")
		}
		if code != "222222" {
			t.Errorf("code = %q, want %q", code, "222222")
		}
	})

	t.Run("clear nils timer", func(t *testing.T) {
		// fakeClip.text must match code so clear() proceeds past identity check
		fc := &fakeClip{text: "123456"}
		m := newTestManager(fc)

		m.mu.Lock()
		m.code = "123456"
		m.timer = time.AfterFunc(1*time.Hour, func() {})
		m.mu.Unlock()

		// Call clear() directly — it should nil the timer and clear clipboard
		m.clear()

		m.mu.Lock()
		hasTimer := m.timer != nil
		m.mu.Unlock()

		if hasTimer {
			t.Error("timer should be nil after clear")
		}
	})
}

// TestClipboardClearSettingsParsing verifies the parseClipTimeout helper.
func TestClipboardClearSettingsParsing(t *testing.T) {
	t.Run("empty setting defaults to 30s", func(t *testing.T) {
		d, skip := parseClipTimeout("")
		if skip {
			t.Fatal("empty setting should not skip (should default to 30s)")
		}
		if d != 30*time.Second {
			t.Errorf("duration = %v, want %v", d, 30*time.Second)
		}
	})

	t.Run("never setting returns skip=true", func(t *testing.T) {
		_, skip := parseClipTimeout("never")
		if !skip {
			t.Fatal("'never' setting should return skip=true")
		}
	})

	t.Run("10 setting returns 10s", func(t *testing.T) {
		d, skip := parseClipTimeout("10")
		if skip {
			t.Fatal("'10' setting should not skip")
		}
		if d != 10*time.Second {
			t.Errorf("duration = %v, want %v", d, 10*time.Second)
		}
	})

	t.Run("60 setting returns 60s", func(t *testing.T) {
		d, skip := parseClipTimeout("60")
		if skip {
			t.Fatal("'60' setting should not skip")
		}
		if d != 60*time.Second {
			t.Errorf("duration = %v, want %v", d, 60*time.Second)
		}
	})

	t.Run("invalid setting defaults to 30s", func(t *testing.T) {
		d, skip := parseClipTimeout("abc")
		if skip {
			t.Fatal("invalid setting should not skip (should default to 30s)")
		}
		if d != 30*time.Second {
			t.Errorf("duration = %v, want %v", d, 30*time.Second)
		}
	})

	t.Run("negative value defaults to 30s", func(t *testing.T) {
		d, skip := parseClipTimeout("-5")
		if skip {
			t.Fatal("negative value should not skip (should default to 30s)")
		}
		if d != 30*time.Second {
			t.Errorf("duration = %v, want %v", d, 30*time.Second)
		}
	})
}

// TestClear_DoesNotClearWhenContentChanged verifies identity check: if clipboard
// content has changed since the code was set, clear() does not wipe it.
func TestClear_DoesNotClearWhenContentChanged(t *testing.T) {
	fc := &fakeClip{text: "different-code"}
	m := newTestManager(fc)

	m.mu.Lock()
	m.code = "123456"
	m.mu.Unlock()

	m.clear()

	if fc.setCalled {
		t.Error("setText should NOT be called when clipboard content has changed")
	}
}

// TestClear_ClearsWhenContentMatches verifies clear() wipes clipboard when
// the current content matches the expected code.
func TestClear_ClearsWhenContentMatches(t *testing.T) {
	fc := &fakeClip{text: "123456"}
	m := newTestManager(fc)

	m.mu.Lock()
	m.code = "123456"
	m.mu.Unlock()

	m.clear()

	if !fc.setCalled {
		t.Error("setText should be called when clipboard content matches")
	}
	if fc.setCalledWith != "" {
		t.Errorf("setText called with %q, want empty string", fc.setCalledWith)
	}
}

// TestClear_EmitsEventOnSuccess verifies that clear() emits "clipboard:cleared"
// after successfully clearing the clipboard.
func TestClear_EmitsEventOnSuccess(t *testing.T) {
	fc := &fakeClip{text: "123456"}
	m := newTestManager(fc)

	m.mu.Lock()
	m.code = "123456"
	m.mu.Unlock()

	m.clear()

	if !fc.emitCalled {
		t.Error("emitFn should be called after successful clear")
	}
	if fc.emitEvent != "clipboard:cleared" {
		t.Errorf("emitEvent = %q, want %q", fc.emitEvent, "clipboard:cleared")
	}
}

// TestClear_DoesNotClearOnGetTextError verifies that clear() does not wipe
// clipboard if getTextFn returns an error.
func TestClear_DoesNotClearOnGetTextError(t *testing.T) {
	fc := &fakeClip{err: fmt.Errorf("clipboard unavailable")}
	m := newTestManager(fc)

	m.mu.Lock()
	m.code = "123456"
	m.mu.Unlock()

	m.clear()

	if fc.setCalled {
		t.Error("setText should NOT be called when getTextFn returns an error")
	}
}
