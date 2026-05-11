// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"strings"
	"testing"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// encodeQRtoPNG generates a QR code PNG for the given URI and returns the bytes.
func encodeQRtoPNG(t *testing.T, uri string, size int) []byte {
	t.Helper()
	writer := qrcode.NewQRCodeWriter()
	bm, err := writer.EncodeWithoutHint(uri, gozxing.BarcodeFormat_QR_CODE, size, size)
	if err != nil {
		t.Fatalf("encodeQRtoPNG: encode QR: %v", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, bm); err != nil {
		t.Fatalf("encodeQRtoPNG: png.Encode: %v", err)
	}
	return buf.Bytes()
}

// writeTempFile writes data to a temp file and returns the path.
func writeTempFile(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "qr-*.png")
	if err != nil {
		t.Fatalf("writeTempFile: CreateTemp: %v", err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		t.Fatalf("writeTempFile: Write: %v", err)
	}
	return f.Name()
}

const scanQRTestURI = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30"

// TestScanQRFile_ValidQR verifies that a valid QR PNG file is decoded into a
// populated URIPreview with the expected issuer, name, and secret.
func TestScanQRFile_ValidQR(t *testing.T) {
	app := setupTestApp(t)

	pngBytes := encodeQRtoPNG(t, scanQRTestURI, 200)
	path := writeTempFile(t, pngBytes)

	preview, err := app.ScanQRFile(path)
	if err != nil {
		t.Fatalf("ScanQRFile: unexpected error: %v", err)
	}
	if preview.Issuer != "Example" {
		t.Errorf("Issuer = %q, want %q", preview.Issuer, "Example")
	}
	if preview.Name != "alice@example.com" {
		t.Errorf("Name = %q, want %q", preview.Name, "alice@example.com")
	}
	if preview.Secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("Secret = %q, want %q", preview.Secret, "JBSWY3DPEHPK3PXP")
	}
	if preview.Type != "totp" {
		t.Errorf("Type = %q, want %q", preview.Type, "totp")
	}
}

// TestScanQRFile_NonQRImage verifies that a plain PNG with no QR code returns
// an error whose message contains "scan qr".
func TestScanQRFile_NonQRImage(t *testing.T) {
	app := setupTestApp(t)

	// Create a plain red 100x100 PNG with no QR code.
	img := image.NewRGBA(image.Rect(0, 0, 100, 100))
	for y := 0; y < 100; y++ {
		for x := 0; x < 100; x++ {
			img.Set(x, y, color.RGBA{R: 255, G: 0, B: 0, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	path := writeTempFile(t, buf.Bytes())

	_, err := app.ScanQRFile(path)
	if err == nil {
		t.Fatal("ScanQRFile with non-QR image: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "scan qr") {
		t.Errorf("error %q does not contain %q", err.Error(), "scan qr")
	}
}

// TestScanQRFile_NonexistentFile verifies that a missing file path returns an
// error containing both "scan qr" and "open".
func TestScanQRFile_NonexistentFile(t *testing.T) {
	app := setupTestApp(t)

	_, err := app.ScanQRFile("/nonexistent/path/qr.png")
	if err == nil {
		t.Fatal("ScanQRFile with nonexistent path: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "scan qr") {
		t.Errorf("error %q does not contain %q", err.Error(), "scan qr")
	}
	if !strings.Contains(err.Error(), "open") {
		t.Errorf("error %q does not contain %q", err.Error(), "open")
	}
}

// TestScanQRFile_GarbageBytes verifies that a file with garbage (non-image) bytes
// returns an error containing both "scan qr" and "decode image".
func TestScanQRFile_GarbageBytes(t *testing.T) {
	app := setupTestApp(t)

	garbage := []byte("this is not an image at all \x00\x01\x02\x03")
	path := writeTempFile(t, garbage)

	_, err := app.ScanQRFile(path)
	if err == nil {
		t.Fatal("ScanQRFile with garbage bytes: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "scan qr") {
		t.Errorf("error %q does not contain %q", err.Error(), "scan qr")
	}
	if !strings.Contains(err.Error(), "decode image") {
		t.Errorf("error %q does not contain %q", err.Error(), "decode image")
	}
}
