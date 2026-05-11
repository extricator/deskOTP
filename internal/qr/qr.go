// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package qr

import (
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"strings"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// Decode reads a QR code from img and returns the otpauth:// URI it encodes.
// Returns an error if no QR code is found, the image cannot be binarized,
// or the decoded text is not an otpauth:// URI.
// TryHarder is always enabled to handle QR codes in large screenshot images.
func Decode(img image.Image) (string, error) {
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("qr: failed to create bitmap: %w", err)
	}

	hints := map[gozxing.DecodeHintType]interface{}{
		gozxing.DecodeHintType_TRY_HARDER: true,
	}

	reader := qrcode.NewQRCodeReader()
	result, err := reader.Decode(bmp, hints)
	if err != nil {
		return "", fmt.Errorf("qr: no QR code found: %w", err)
	}

	text := result.GetText()
	if !strings.HasPrefix(text, "otpauth://") {
		return "", fmt.Errorf("qr: decoded text is not an otpauth:// URI: %q", text)
	}

	return text, nil
}
