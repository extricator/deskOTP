// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"

	"deskotp/internal/totp"
)

// Magic header constants for Stratum (Authenticator Pro) encrypted backup formats.
// Both headers are exactly 16 bytes — the full stratumHeaderSize.
//
//	Current format: Argon2id + AES-256-GCM (used in recent app versions)
//	Legacy format:  PBKDF2-SHA1 + AES-256-CBC (used in older app versions)
const stratumMagicCurrent = "AUTHENTICATORPRO" // 16 bytes, all uppercase
const stratumMagicLegacy = "AuthenticatorPro"  // 16 bytes, mixed case

const stratumHeaderSize = 16 // length of both magic headers

// pkcs7Unpad strips PKCS7 padding from data and returns the unpadded bytes.
//
// It is a package-level unexported helper shared by StratumEncryptedParser (AES-CBC)
// and future Phase 15 parsers that also use AES-CBC (AuthyEncryptedParser,
// TotpAuthenticatorEncryptedParser).
//
// Errors are returned for:
//   - empty input
//   - length not a multiple of blockSize
//   - pad byte of 0 (PKCS7 requires pad >= 1)
//   - pad byte greater than blockSize
//   - inconsistent pad bytes (any of the padLen bytes differs from padLen)
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("pkcs7unpad: empty input")
	}
	if len(data)%blockSize != 0 {
		return nil, fmt.Errorf("pkcs7unpad: length %d is not a multiple of block size %d", len(data), blockSize)
	}

	padLen := int(data[len(data)-1])
	if padLen == 0 {
		return nil, fmt.Errorf("pkcs7unpad: invalid pad byte 0x00")
	}
	if padLen > blockSize {
		return nil, fmt.Errorf("pkcs7unpad: pad byte %d exceeds block size %d", padLen, blockSize)
	}

	// Verify all padding bytes are consistent.
	for i := len(data) - padLen; i < len(data); i++ {
		if int(data[i]) != padLen {
			return nil, fmt.Errorf("pkcs7unpad: inconsistent padding at index %d", i)
		}
	}

	return data[:len(data)-padLen], nil
}

// StratumEncryptedParser implements BackupParser for Stratum (Authenticator Pro)
// encrypted backup files. It supports two binary formats distinguished by a 16-byte
// magic header:
//
//   - Current format ("AUTHENTICATORPRO"): Argon2id + AES-256-GCM
//   - Legacy format  ("AuthenticatorPro"): PBKDF2-SHA1 + AES-256-CBC
//
// Decrypted plaintext is delegated to StratumParser.Parse for entry conversion,
// reusing existing field-mapping logic (Type codes, Algorithm codes, Steam overrides).
type StratumEncryptedParser struct{}

func (p *StratumEncryptedParser) Name() string { return "Stratum (Encrypted)" }

// CanParse returns true if data starts with either Stratum encrypted magic header.
// Both headers are exactly 16 bytes. Returns false if data is shorter than 16 bytes.
func (p *StratumEncryptedParser) CanParse(data []byte) bool {
	if len(data) < stratumHeaderSize {
		return false
	}
	header := string(data[:stratumHeaderSize])
	return header == stratumMagicCurrent || header == stratumMagicLegacy
}

// Parse decrypts a Stratum encrypted backup and returns the parsed OTP entries.
//
// Decryption flow:
//  1. Reject empty password with ErrPasswordRequired.
//  2. Dispatch to decryptStratumCurrent or decryptStratumLegacy based on magic header.
//  3. Delegate decrypted JSON to StratumParser.Parse for entry conversion.
//
// Returns ErrWrongPassword if decryption fails (wrong password or corrupted file).
func (p *StratumEncryptedParser) Parse(data []byte, password string) ([]totp.Entry, error) {
	if password == "" {
		return nil, ErrPasswordRequired
	}
	if len(data) < stratumHeaderSize {
		return nil, fmt.Errorf("stratum encrypted: data too short (%d bytes)", len(data))
	}

	switch string(data[:stratumHeaderSize]) {
	case stratumMagicCurrent:
		return decryptStratumCurrent(data, password)
	case stratumMagicLegacy:
		return decryptStratumLegacy(data, password)
	default:
		return nil, fmt.Errorf("stratum encrypted: unrecognised header %q", string(data[:stratumHeaderSize]))
	}
}

// decryptStratumCurrent decrypts a current-format Stratum encrypted file.
//
// Binary layout:
//
//	[0:16]  16 bytes — "AUTHENTICATORPRO" magic
//	[16:32] 16 bytes — Argon2id salt
//	[32:44] 12 bytes — AES-GCM IV
//	[44:]   ciphertext + 16-byte GCM tag
//
// KDF: Argon2id, time=3, memory=65536 KiB (1<<16 = 64 MiB), threads=4, keyLen=32.
//
// CRITICAL: The memory parameter is 1<<16 (65536 KiB = 64 MiB), not 16 or 64.
// Using any other value will cause all real Stratum encrypted files to fail decryption.
func decryptStratumCurrent(data []byte, password string) ([]totp.Entry, error) {
	const saltSize = 16
	const ivSizeGCM = 12
	const minLen = stratumHeaderSize + saltSize + ivSizeGCM + 1 // at least 1 byte of ciphertext

	if len(data) < minLen {
		return nil, fmt.Errorf("stratum encrypted current: data too short (%d bytes)", len(data))
	}

	salt := data[stratumHeaderSize : stratumHeaderSize+saltSize]
	iv := data[stratumHeaderSize+saltSize : stratumHeaderSize+saltSize+ivSizeGCM]
	ctWithTag := data[stratumHeaderSize+saltSize+ivSizeGCM:]

	// Argon2id key derivation.
	// Parameters: time=3, memory=65536 KiB (1<<16), threads=4, keyLen=32.
	key := argon2.IDKey([]byte(password), salt, 3, 1<<16, 4, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("stratum encrypted current: AES cipher init failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("stratum encrypted current: GCM init failed: %w", err)
	}

	plaintext, err := gcm.Open(nil, iv, ctWithTag, nil)
	if err != nil {
		// GCM authentication failure means wrong password or corrupted file.
		return nil, ErrWrongPassword
	}

	plainParser := &StratumParser{}
	return plainParser.Parse(plaintext, "")
}

// decryptStratumLegacy decrypts a legacy-format Stratum encrypted file.
//
// Binary layout:
//
//	[0:16]  16 bytes — "AuthenticatorPro" magic
//	[16:36] 20 bytes — PBKDF2 salt
//	[36:52] 16 bytes — AES-CBC IV
//	[52:]   PKCS7-padded AES-CBC ciphertext
//
// KDF: PBKDF2-SHA1, 64000 iterations, 32-byte key.
func decryptStratumLegacy(data []byte, password string) ([]totp.Entry, error) {
	const saltSizeLegacy = 20
	const ivSizeCBC = 16
	const minLen = stratumHeaderSize + saltSizeLegacy + ivSizeCBC + 1 // at least 1 byte of ciphertext

	if len(data) < minLen {
		return nil, fmt.Errorf("stratum encrypted legacy: data too short (%d bytes)", len(data))
	}

	salt := data[stratumHeaderSize : stratumHeaderSize+saltSizeLegacy]
	iv := data[stratumHeaderSize+saltSizeLegacy : stratumHeaderSize+saltSizeLegacy+ivSizeCBC]
	ct := data[stratumHeaderSize+saltSizeLegacy+ivSizeCBC:]

	// PBKDF2-SHA1 key derivation.
	key := pbkdf2.Key([]byte(password), salt, 64000, 32, sha1.New)

	// Block-alignment check: AES-CBC requires ciphertext length to be a multiple of block size.
	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("stratum encrypted legacy: ciphertext length %d is not a multiple of block size", len(ct))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("stratum encrypted legacy: AES cipher init failed: %w", err)
	}

	plaintext := make([]byte, len(ct))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ct)

	unpadded, err := pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		// PKCS7 unpad failure means wrong password produced garbled plaintext.
		return nil, ErrWrongPassword
	}

	plainParser := &StratumParser{}
	return plainParser.Parse(unpadded, "")
}
