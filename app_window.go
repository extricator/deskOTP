// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

import (
	"strconv"

	"deskotp/internal/settings"
	"github.com/wailsapp/wails/v2/pkg/options"
)

// windowGeometry holds the persisted window state used at startup.
type windowGeometry struct {
	Width      int
	Height     int
	StartState options.WindowStartState
	X          int
	Y          int
	RestorePos bool // whether position should be restored
}

// isOffScreen returns true if the position is far enough off-screen that
// restoring it would leave the window inaccessible. Small negative values
// are allowed because window decorations can push y slightly negative.
// Threshold: x < -100 or y < -100.
func isOffScreen(x, y int) bool {
	return x < -100 || y < -100
}

// loadGeometry reads window geometry from the settings store.
// Falls back to defaults (420x680, Normal state) on missing or corrupt values.
// Width/height are clamped to a minimum of 400x400.
// If the window was maximized, StartState is set to options.Maximised and
// RestorePos is false (position is irrelevant when maximized).
// If the window was not maximized and a valid, on-screen position was saved,
// RestorePos is true.
func loadGeometry(s *settings.Store) windowGeometry {
	const (
		defaultWidth  = 420
		defaultHeight = 680
		minWidth      = 400
		minHeight     = 400
	)

	geo := windowGeometry{
		Width:  defaultWidth,
		Height: defaultHeight,
	}

	// Parse width
	if v := s.Get("window_width"); v != "" {
		if w, err := strconv.Atoi(v); err == nil {
			if w < minWidth {
				w = minWidth
			}
			geo.Width = w
		}
		// On parse error: keep default
	}

	// Parse height
	if v := s.Get("window_height"); v != "" {
		if h, err := strconv.Atoi(v); err == nil {
			if h < minHeight {
				h = minHeight
			}
			geo.Height = h
		}
		// On parse error: keep default
	}

	// Parse maximized state
	if s.Get("window_maximized") == "true" {
		geo.StartState = options.Maximised
		geo.RestorePos = false
		return geo
	}

	// Parse position — only restore if both keys present, parseable, and on-screen
	xStr := s.Get("window_x")
	yStr := s.Get("window_y")
	if xStr != "" && yStr != "" {
		x, xErr := strconv.Atoi(xStr)
		y, yErr := strconv.Atoi(yStr)
		if xErr == nil && yErr == nil && !isOffScreen(x, y) {
			geo.X = x
			geo.Y = y
			geo.RestorePos = true
		}
	}

	return geo
}

// saveGeometry persists window geometry to the settings store.
// If maximized is true, only the window_maximized key is updated — width/height/x/y
// are intentionally NOT overwritten to preserve the last normal-size values
// (avoids saving full-screen dimensions as the "normal" window size).
// If maximized is false, all five keys are written.
func saveGeometry(s *settings.Store, maximized bool, w, h, x, y int) {
	if maximized {
		_ = s.Set("window_maximized", "true")
		return
	}
	_ = s.Set("window_width", strconv.Itoa(w))
	_ = s.Set("window_height", strconv.Itoa(h))
	_ = s.Set("window_x", strconv.Itoa(x))
	_ = s.Set("window_y", strconv.Itoa(y))
	_ = s.Set("window_maximized", "false")
}
