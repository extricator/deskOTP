// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

import (
	"testing"

	"github.com/wailsapp/wails/v2/pkg/options"
)

func TestIsOffScreen(t *testing.T) {
	tests := []struct {
		name string
		x, y int
		want bool
	}{
		{"both positive", 100, 100, false},
		{"x slightly negative", -50, 200, false},
		{"x at threshold", -100, 0, false},
		{"x just over threshold", -101, 0, true},
		{"y at threshold", 0, -100, false},
		{"y just over threshold", 0, -101, true},
		{"both very negative", -200, -200, true},
		{"zero zero", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isOffScreen(tt.x, tt.y)
			if got != tt.want {
				t.Errorf("isOffScreen(%d, %d) = %v, want %v", tt.x, tt.y, got, tt.want)
			}
		})
	}
}

func TestLoadGeometry_Defaults(t *testing.T) {
	app := setupTestApp(t)
	// No settings written — should return defaults
	geo := loadGeometry(app.settings)
	if geo.Width != 420 {
		t.Errorf("Width = %d, want 420", geo.Width)
	}
	if geo.Height != 680 {
		t.Errorf("Height = %d, want 680", geo.Height)
	}
	if geo.StartState != options.Normal {
		t.Errorf("StartState = %v, want options.Normal", geo.StartState)
	}
	if geo.X != 0 {
		t.Errorf("X = %d, want 0", geo.X)
	}
	if geo.Y != 0 {
		t.Errorf("Y = %d, want 0", geo.Y)
	}
	if geo.RestorePos {
		t.Error("RestorePos = true, want false (no saved position)")
	}
}

func TestLoadGeometry_SavedValues(t *testing.T) {
	app := setupTestApp(t)
	_ = app.settings.Set("window_width", "800")
	_ = app.settings.Set("window_height", "600")
	_ = app.settings.Set("window_x", "100")
	_ = app.settings.Set("window_y", "200")
	_ = app.settings.Set("window_maximized", "false")

	geo := loadGeometry(app.settings)
	if geo.Width != 800 {
		t.Errorf("Width = %d, want 800", geo.Width)
	}
	if geo.Height != 600 {
		t.Errorf("Height = %d, want 600", geo.Height)
	}
	if geo.StartState != options.Normal {
		t.Errorf("StartState = %v, want options.Normal", geo.StartState)
	}
	if geo.X != 100 {
		t.Errorf("X = %d, want 100", geo.X)
	}
	if geo.Y != 200 {
		t.Errorf("Y = %d, want 200", geo.Y)
	}
	if !geo.RestorePos {
		t.Error("RestorePos = false, want true (valid saved position)")
	}
}

func TestLoadGeometry_Maximized(t *testing.T) {
	app := setupTestApp(t)
	_ = app.settings.Set("window_maximized", "true")
	_ = app.settings.Set("window_x", "100")
	_ = app.settings.Set("window_y", "200")

	geo := loadGeometry(app.settings)
	if geo.StartState != options.Maximised {
		t.Errorf("StartState = %v, want options.Maximised", geo.StartState)
	}
	if geo.RestorePos {
		t.Error("RestorePos = true, want false (position not restored when maximized)")
	}
}

func TestLoadGeometry_ClampMin(t *testing.T) {
	app := setupTestApp(t)
	_ = app.settings.Set("window_width", "200")
	_ = app.settings.Set("window_height", "150")

	geo := loadGeometry(app.settings)
	if geo.Width != 400 {
		t.Errorf("Width = %d, want 400 (clamped to MinWidth)", geo.Width)
	}
	if geo.Height != 400 {
		t.Errorf("Height = %d, want 400 (clamped to MinHeight)", geo.Height)
	}
}

func TestLoadGeometry_CorruptValues(t *testing.T) {
	app := setupTestApp(t)
	_ = app.settings.Set("window_width", "abc")
	_ = app.settings.Set("window_height", "")

	geo := loadGeometry(app.settings)
	if geo.Width != 420 {
		t.Errorf("Width = %d, want 420 (default on corrupt value)", geo.Width)
	}
	if geo.Height != 680 {
		t.Errorf("Height = %d, want 680 (default on empty value)", geo.Height)
	}
}

func TestLoadGeometry_OffScreenPosition(t *testing.T) {
	app := setupTestApp(t)
	_ = app.settings.Set("window_x", "-500")
	_ = app.settings.Set("window_y", "100")
	_ = app.settings.Set("window_maximized", "false")

	geo := loadGeometry(app.settings)
	if geo.RestorePos {
		t.Error("RestorePos = true, want false (off-screen position should be ignored)")
	}
}

func TestSaveGeometry(t *testing.T) {
	app := setupTestApp(t)
	saveGeometry(app.settings, false, 800, 600, 150, 250)

	if got := app.settings.Get("window_width"); got != "800" {
		t.Errorf("window_width = %q, want %q", got, "800")
	}
	if got := app.settings.Get("window_height"); got != "600" {
		t.Errorf("window_height = %q, want %q", got, "600")
	}
	if got := app.settings.Get("window_x"); got != "150" {
		t.Errorf("window_x = %q, want %q", got, "150")
	}
	if got := app.settings.Get("window_y"); got != "250" {
		t.Errorf("window_y = %q, want %q", got, "250")
	}
	if got := app.settings.Get("window_maximized"); got != "false" {
		t.Errorf("window_maximized = %q, want %q", got, "false")
	}
}

func TestSaveGeometry_Maximized(t *testing.T) {
	app := setupTestApp(t)
	// First save a normal geometry to establish baseline values
	_ = app.settings.Set("window_width", "800")
	_ = app.settings.Set("window_height", "600")
	_ = app.settings.Set("window_x", "150")
	_ = app.settings.Set("window_y", "250")

	// Now save with maximized=true — should NOT overwrite width/height/x/y
	saveGeometry(app.settings, true, 0, 0, 0, 0)

	if got := app.settings.Get("window_maximized"); got != "true" {
		t.Errorf("window_maximized = %q, want %q", got, "true")
	}
	// Width/height/x/y must be preserved from before the maximized save
	if got := app.settings.Get("window_width"); got != "800" {
		t.Errorf("window_width = %q, want %q (should not be overwritten when maximized)", got, "800")
	}
	if got := app.settings.Get("window_height"); got != "600" {
		t.Errorf("window_height = %q, want %q (should not be overwritten when maximized)", got, "600")
	}
	if got := app.settings.Get("window_x"); got != "150" {
		t.Errorf("window_x = %q, want %q (should not be overwritten when maximized)", got, "150")
	}
	if got := app.settings.Get("window_y"); got != "250" {
		t.Errorf("window_y = %q, want %q (should not be overwritten when maximized)", got, "250")
	}
}
