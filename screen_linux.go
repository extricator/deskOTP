// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

//go:build linux

package main

import (
	"fmt"
	"image"
	_ "image/png"
	"net/url"
	"os"
	"time"

	"github.com/rymdport/portal/screenshot"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"deskotp/internal/qr"
)

// ScanQRScreen minimizes the app, invokes the xdg-desktop-portal screenshot
// dialog, restores the app, and decodes the QR code in the captured image.
// Returns a URIPreview on success. Returns empty URIPreview with nil error
// when the user cancels (screenshot.Screenshot returns "" on cancel).
// Returns an error when the portal is unavailable or QR decode fails.
//
// IMPORTANT: screenshot.Screenshot() blocks synchronously on
// request.OnSignalResponse(). It MUST run in a goroutine to avoid
// deadlocking the Wails IPC bridge. The goroutine+channel pattern
// preserves synchronous semantics for the bound method caller.
func (a *App) ScanQRScreen() (URIPreview, error) {
	type result struct {
		preview URIPreview
		err     error
	}
	ch := make(chan result, 1)

	go func() {
		// Minimize before capture so the app window is not in the screenshot.
		runtime.WindowMinimise(a.ctx)
		// Guarantee window restore on ALL exit paths (error, cancel, success).
		defer runtime.WindowUnminimise(a.ctx)

		// Brief pause to allow the window manager to finish minimizing before
		// the portal dialog opens. Without this, the window may still be
		// visible when the screenshot is captured.
		time.Sleep(200 * time.Millisecond)

		uri, err := screenshot.Screenshot("", &screenshot.ScreenshotOptions{
			Interactive: true, // Hint to portal to show region-selection UI
		})
		if err != nil {
			ch <- result{err: fmt.Errorf("scan screen: portal: %w", err)}
			return
		}
		// Context guard: if context was cancelled while screenshot.Screenshot() was
		// blocked on D-Bus, exit early — skip image decode and QR processing.
		if a.ctx.Err() != nil {
			ch <- result{}
			return
		}
		if uri == "" {
			// User cancelled the screenshot dialog.
			ch <- result{}
			return
		}

		// Portal returns a file:// URI; extract the filesystem path.
		u, err := url.Parse(uri)
		if err != nil {
			ch <- result{err: fmt.Errorf("scan screen: parse uri: %w", err)}
			return
		}
		path := u.Path

		// Open and decode the screenshot image.
		f, err := os.Open(path)
		if err != nil {
			ch <- result{err: fmt.Errorf("scan screen: open: %w", err)}
			return
		}

		img, _, err := image.Decode(f)
		f.Close() // Close before remove to be tidy on all platforms.
		if err != nil {
			os.Remove(path) // Best-effort cleanup on image decode failure.
			ch <- result{err: fmt.Errorf("scan screen: decode image: %w", err)}
			return
		}

		// Delete the temp screenshot file (QRSC-05).
		// This runs regardless of whether QR decode succeeds or fails.
		os.Remove(path)

		// Decode the QR code from the image.
		otpURI, err := qr.Decode(img)
		if err != nil {
			ch <- result{err: fmt.Errorf("scan screen: %w", err)}
			return
		}

		// Build the preview from the otpauth URI.
		preview, err := a.ParseAndPreviewURI(otpURI)
		if err != nil {
			ch <- result{err: fmt.Errorf("scan screen: preview: %w", err)}
			return
		}

		ch <- result{preview: preview}
	}()

	r := <-ch
	return r.preview, r.err
}
