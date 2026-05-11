// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

import (
	"context"
	"strconv"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"deskotp/internal/backup"
	"deskotp/internal/clipboard"
	"deskotp/internal/entries"
	"deskotp/internal/lock"
	"deskotp/internal/storage"
	"deskotp/internal/totp"
	"deskotp/internal/vaultctrl"
)

// startup is called by Wails when the app window is ready and the runtime context is available.
// Goroutine lifecycle is pinned to OnStartup — never start goroutines from bound methods.
func (a *App) startup(ctx context.Context) {
	// First line: ctx must be set before any runtime.* calls.
	a.ctx = ctx

	a.clipMgr = clipboard.New(
		func() (string, error) { return runtime.ClipboardGetText(a.ctx) },
		func(s string) error   { return runtime.ClipboardSetText(a.ctx, s) },
		func(event string)     { runtime.EventsEmit(a.ctx, event) },
	)

	if err := a.settings.Load(); err != nil {
		runtime.LogError(ctx, "startup: load settings: "+err.Error())
	}

	// Restore window position (size/maximized already set via options.App in main).
	// Position cannot be set via options.App — requires runtime context.
	// Best-effort: off-screen and maximized cases are skipped.
	if a.settings.Get("window_maximized") != "true" {
		xStr := a.settings.Get("window_x")
		yStr := a.settings.Get("window_y")
		if xStr != "" && yStr != "" {
			x, xErr := strconv.Atoi(xStr)
			y, yErr := strconv.Atoi(yStr)
			if xErr == nil && yErr == nil && !isOffScreen(x, y) {
				runtime.WindowSetPosition(a.ctx, x, y)
			}
		}
	}

	// Pre-populate backup directory default (XDG data dir)
	if a.settings.Get("backup_dir") == "" {
		if dir := backup.DefaultDir(); dir != "" {
			_ = a.settings.Set("backup_dir", dir)
		}
	}

	// Wire entry manager with injected callbacks.
	a.entryMgr = entries.New(
		a.saveEntries,
		a.notifyBackupChanged,
		a.emitTick,
		a.emitMetadata,
	)

	// Wire vault controller with injected dependencies.
	a.vaultCtrl = vaultctrl.New(
		a.keyCache,
		a.settings,
		a.entryMgr.Snapshot,
		a.entryMgr.GetGroups,
		a.entryMgr.Set,
		a.entryMgr.SetGroups,
	)

	if a.settings.Get("vault_enabled") == "true" {
		// Vault is encrypted — don't load entries. Frontend must call UnlockVault first.
		// Groups will be populated from the vault payload on UnlockVault.
		a.entryMgr.Set([]totp.Entry{})
		a.entryMgr.SetGroups([]entries.GroupInfo{})
	} else {
		loaded, groups, err := storage.Load()
		if err != nil {
			// Log but don't fatal — app can still run and accept new imports
			// even if the persisted data file is missing or corrupted.
			runtime.LogError(ctx, "startup: load accounts: "+err.Error())
			loaded = []totp.Entry{}
		}
		a.entryMgr.Set(loaded)
		a.entryMgr.SetGroups(groups)
	}

	go a.tickLoop()
	go lock.Watch(ctx, func() {
		a.performLock()
	})

	// Start backup manager with child context for clean shutdown
	mCtx, mCancel := context.WithCancel(ctx)
	a.managerCancel = mCancel
	a.manager = backup.New(a.doBackupWrite, a.settings)
	a.manager.Start(mCtx)
}

// beforeClose is called by Wails via OnBeforeClose while the window is still alive.
// This is the correct place to read window geometry — OnShutdown fires AFTER the
// GTK window is destroyed, causing runtime.WindowGet* calls to fail.
func (a *App) beforeClose(ctx context.Context) (prevent bool) {
	isMax := runtime.WindowIsMaximised(ctx)
	if !isMax {
		w, h := runtime.WindowGetSize(ctx)
		x, y := runtime.WindowGetPosition(ctx)
		saveGeometry(a.settings, false, w, h, x, y)
	} else {
		saveGeometry(a.settings, true, 0, 0, 0, 0)
	}
	return false // don't prevent close
}

// shutdown is called by Wails when the app is about to quit.
func (a *App) shutdown(ctx context.Context) {
	if a.managerCancel != nil {
		a.managerCancel()
	}
	if a.manager != nil {
		a.manager.Wait()
	}
}

// emitTick builds the current TOTP code payloads and emits a codes:tick event.
// Used by tickLoop (periodic) and after mutations (DeleteEntry, UndoDelete) to
// push updated entries to the frontend immediately.
func (a *App) emitTick() {
	// Suppress code emission while vault is locked -- secrets must not flow to frontend.
	// Only block when vault is enabled (encrypted); plain vaults have no masterKey
	// so IsUnlocked() would always return false, starving the frontend of ticks.
	if a.settings.Get("vault_enabled") == "true" && !a.keyCache.IsUnlocked() {
		return
	}
	// Guard against nil context (no Wails runtime, e.g. in tests).
	if a.ctx == nil {
		return
	}
	payloads := a.entryMgr.BuildPayloads(time.Now())
	runtime.EventsEmit(a.ctx, "codes:tick", payloads)
}

// emitMetadata builds entry metadata payloads and emits an entries:changed event.
// Called by Manager's emitMetadataFn callback after any data mutation.
// Guards on vault lock and nil ctx (same pattern as emitTick).
func (a *App) emitMetadata() {
	if a.settings.Get("vault_enabled") == "true" && !a.keyCache.IsUnlocked() {
		return
	}
	if a.ctx == nil {
		return
	}
	payloads := a.entryMgr.BuildMetadataPayloads()
	runtime.EventsEmit(a.ctx, "entries:changed", payloads)
}

// tickLoop emits codes immediately on launch, then checks every second whether
// any TOTP code has rolled over before emitting again. For typical 30-second
// entries this reduces crypto + IPC work from 1/s to 1/30s after the initial emit.
// Runs as a goroutine launched from startup. Exits when ctx is cancelled (app shutdown).
func (a *App) tickLoop() {
	// Emit immediately so the frontend gets codes on launch without waiting for
	// the first ticker tick (1 second delay).
	a.emitTick()
	lastEmitUnix := time.Now().Unix()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now().Unix()
			if a.entryMgr.AnyPeriodBoundary(now, lastEmitUnix) {
				a.emitTick()
				lastEmitUnix = now
			}
		case <-a.ctx.Done():
			return
		}
	}
}

// performLock executes the lock sequence: checks idempotency, clears key,
// clears entries, emits vault:locked event. Returns false if already locked
// (idempotent no-op -- no event emitted). Safe to call from any goroutine.
// All lock trigger paths (manual button, idle timer, desktop lock) converge here.
func (a *App) performLock() bool {
	if !a.keyCache.IsUnlocked() {
		return false // already locked -- idempotent no-op
	}
	a.keyCache.Lock()
	a.entryMgr.Clear()
	// Emit AFTER clearing entries — EventsEmit may block internally.
	runtime.EventsEmit(a.ctx, "vault:locked")
	return true
}

// LockVault locks the vault, clearing the cached encryption key and in-memory
// entries. Future lock-trigger paths (NavBar button, idle timer, desktop session
// lock) all converge here. Safe to call when already locked -- no event is
// re-emitted, no panic occurs.
func (a *App) LockVault() {
	a.performLock()
}
