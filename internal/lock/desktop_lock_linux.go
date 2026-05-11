// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

//go:build linux

package lock

import (
	"context"
	"log"
	"os"

	"github.com/godbus/dbus/v5"
)

// Watch subscribes to desktop lock signals on Linux and calls onLock when the
// desktop is locked. It launches two goroutines (ScreenSaver + login1) and
// returns immediately without blocking. The goroutines exit when ctx is cancelled.
//
// DSKL-01: org.freedesktop.ScreenSaver.ActiveChanged(true) covers GNOME, KDE, XFCE, etc.
// DSKL-02: org.freedesktop.login1.Session.Lock covers loginctl lock-session and VT switching.
// D-Bus connection failures degrade gracefully: errors are logged and the goroutine returns.
func Watch(ctx context.Context, onLock func()) {
	go watchScreenSaver(ctx, onLock)
	go watchLogin1(ctx, onLock)
}

// watchScreenSaver subscribes to org.freedesktop.ScreenSaver.ActiveChanged on the
// session bus. Calls onLock when the screen saver activates (active=true).
func watchScreenSaver(ctx context.Context, onLock func()) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		log.Printf("lock: ScreenSaver watcher: connect session bus: %v", err)
		return
	}
	defer conn.Close()

	if err := conn.AddMatchSignal(
		dbus.WithMatchInterface("org.freedesktop.ScreenSaver"),
		dbus.WithMatchMember("ActiveChanged"),
	); err != nil {
		log.Printf("lock: ScreenSaver watcher: add match signal: %v", err)
		return
	}

	ch := make(chan *dbus.Signal, 10)
	conn.Signal(ch)
	defer conn.RemoveSignal(ch)

	for {
		select {
		case sig, ok := <-ch:
			if !ok {
				return
			}
			if sig == nil {
				continue
			}
			if len(sig.Body) > 0 {
				if active, ok := sig.Body[0].(bool); ok && active {
					onLock()
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

// watchLogin1 subscribes to org.freedesktop.login1.Session.Lock on the system bus.
// This signal is sent when the session is locked via loginctl, Super+L on some DEs,
// or when the display manager locks the session. Calls onLock on any valid signal.
func watchLogin1(ctx context.Context, onLock func()) {
	sysConn, err := dbus.ConnectSystemBus()
	if err != nil {
		log.Printf("lock: login1 watcher: connect system bus: %v", err)
		return
	}
	defer sysConn.Close()

	// Resolve this process's session path so we only subscribe to our own session.
	var sessionPath dbus.ObjectPath
	obj := sysConn.Object("org.freedesktop.login1", "/org/freedesktop/login1")
	if err := obj.Call("org.freedesktop.login1.Manager.GetSessionByPID", 0, uint32(os.Getpid())).Store(&sessionPath); err != nil {
		log.Printf("lock: login1 watcher: get session by PID: %v", err)
		return
	}

	if err := sysConn.AddMatchSignal(
		dbus.WithMatchInterface("org.freedesktop.login1.Session"),
		dbus.WithMatchMember("Lock"),
		dbus.WithMatchObjectPath(sessionPath),
	); err != nil {
		log.Printf("lock: login1 watcher: add match signal: %v", err)
		return
	}

	ch := make(chan *dbus.Signal, 10)
	sysConn.Signal(ch)
	defer sysConn.RemoveSignal(ch)

	for {
		select {
		case sig, ok := <-ch:
			if !ok {
				return
			}
			if sig == nil {
				continue
			}
			// Lock signal has no body -- any valid signal means lock.
			onLock()
		case <-ctx.Done():
			return
		}
	}
}
