// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/appicon.png
var appIcon []byte

func main() {
	app := NewApp()

	// Load settings before wails.Run to read persisted window geometry.
	// Safe to call again in startup() — Load() is idempotent.
	_ = app.settings.Load()
	geo := loadGeometry(app.settings)

	err := wails.Run(&options.App{
		Title:            "deskOTP",
		Width:            geo.Width,
		Height:           geo.Height,
		MinWidth:         400,
		MinHeight:                400,
		WindowStartState: geo.StartState,
		EnableDefaultContextMenu: true,
		AssetServer:              &assetserver.Options{Assets: assets},
		BackgroundColour: &options.RGBA{R: 17, G: 19, B: 23, A: 1},
		OnStartup:        app.startup,
		OnBeforeClose:    app.beforeClose,
		OnShutdown:       app.shutdown,
		Linux: &linux.Options{
			Icon: appIcon,
		},
		Bind: []interface{}{app},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
