// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package qr

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"image/jpeg"
	"image/png"
	"testing"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

const testURI = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"

// encodeQRImage generates a QR code image of the given URI at the given pixel size.
// Uses gozxing's own QRCodeWriter — BitMatrix implements image.Image directly.
func encodeQRImage(t *testing.T, uri string, size int) *gozxing.BitMatrix {
	t.Helper()
	writer := qrcode.NewQRCodeWriter()
	bm, err := writer.EncodeWithoutHint(uri, gozxing.BarcodeFormat_QR_CODE, size, size)
	if err != nil {
		t.Fatalf("encode QR: %v", err)
	}
	return bm
}

// decodeImageBytes round-trips raw bytes through image.Decode and calls Decode.
func decodeImageBytes(t *testing.T, data []byte) string {
	t.Helper()
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("image.Decode: %v", err)
	}
	result, err := Decode(img)
	if err != nil {
		t.Fatalf("qr.Decode: %v", err)
	}
	return result
}

func TestDecode_PNG(t *testing.T) {
	bm := encodeQRImage(t, testURI, 200)
	var buf bytes.Buffer
	if err := png.Encode(&buf, bm); err != nil {
		t.Fatal(err)
	}
	if got := decodeImageBytes(t, buf.Bytes()); got != testURI {
		t.Errorf("got %q, want %q", got, testURI)
	}
}

func TestDecode_JPEG(t *testing.T) {
	bm := encodeQRImage(t, testURI, 200)
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, bm, &jpeg.Options{Quality: 95}); err != nil {
		t.Fatal(err)
	}
	if got := decodeImageBytes(t, buf.Bytes()); got != testURI {
		t.Errorf("got %q, want %q", got, testURI)
	}
}

func TestDecode_GIF(t *testing.T) {
	bm := encodeQRImage(t, testURI, 200)
	palette := color.Palette{color.White, color.Black}
	paletted := image.NewPaletted(bm.Bounds(), palette)
	draw.Draw(paletted, paletted.Bounds(), bm, bm.Bounds().Min, draw.Src)
	var buf bytes.Buffer
	if err := gif.Encode(&buf, paletted, &gif.Options{NumColors: 2}); err != nil {
		t.Fatal(err)
	}
	if got := decodeImageBytes(t, buf.Bytes()); got != testURI {
		t.Errorf("got %q, want %q", got, testURI)
	}
}

func TestDecode_SmallQRInLargeImage(t *testing.T) {
	// Simulate a QR code occupying a small area of a full-screen screenshot
	bm := encodeQRImage(t, testURI, 200)
	large := image.NewRGBA(image.Rect(0, 0, 1920, 1080))
	draw.Draw(large, large.Bounds(), &image.Uniform{color.White}, image.Point{}, draw.Src)
	offset := image.Pt(860, 440)
	draw.Draw(large, bm.Bounds().Add(offset), bm, bm.Bounds().Min, draw.Src)

	var buf bytes.Buffer
	if err := png.Encode(&buf, large); err != nil {
		t.Fatal(err)
	}
	if got := decodeImageBytes(t, buf.Bytes()); got != testURI {
		t.Errorf("got %q, want %q", got, testURI)
	}
}

func TestDecode_InvalidImage_ReturnsError(t *testing.T) {
	// Blank white image — no QR code
	blank := image.NewRGBA(image.Rect(0, 0, 200, 200))
	_, err := Decode(blank)
	if err == nil {
		t.Fatal("expected error for image with no QR code, got nil")
	}
}

func TestDecode_NonOtpauthQR_ReturnsError(t *testing.T) {
	bm := encodeQRImage(t, "https://example.com", 200)
	_, err := Decode(bm)
	if err == nil {
		t.Fatal("expected error for non-otpauth QR code, got nil")
	}
}
