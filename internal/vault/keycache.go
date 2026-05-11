// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package vault

import "sync"

// KeyCache holds the decrypted master key in memory after unlock,
// avoiding costly scrypt re-derivation on every encrypt/decrypt operation.
// All methods are safe for concurrent use.
type KeyCache struct {
	mu        sync.RWMutex
	masterKey []byte
}

// NewKeyCache returns a new KeyCache in the locked state.
func NewKeyCache() *KeyCache {
	return &KeyCache{}
}

// Unlock stores a defensive copy of the provided master key, making it
// available via Key(). If the cache already holds a key, it is zeroed
// and replaced.
func (kc *KeyCache) Unlock(masterKey []byte) {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	// Zero any existing key before replacing.
	kc.zeroKey()

	// Defensive copy so the caller cannot mutate the cached key.
	copied := make([]byte, len(masterKey))
	copy(copied, masterKey)
	kc.masterKey = copied
}

// Key returns a defensive copy of the cached master key. If the cache is
// locked, it returns (nil, ErrVaultLocked).
func (kc *KeyCache) Key() ([]byte, error) {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	if kc.masterKey == nil {
		return nil, ErrVaultLocked
	}

	// Defensive copy so the caller cannot mutate the cached key.
	out := make([]byte, len(kc.masterKey))
	copy(out, kc.masterKey)
	return out, nil
}

// Lock zeroes the cached master key and marks the cache as locked.
// It is safe to call Lock on an already-locked cache.
func (kc *KeyCache) Lock() {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	kc.zeroKey()
	kc.masterKey = nil
}

// IsUnlocked reports whether the cache holds a master key.
func (kc *KeyCache) IsUnlocked() bool {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	return kc.masterKey != nil
}

// zeroKey overwrites every byte of the cached key with zero.
// Must be called with kc.mu held.
func (kc *KeyCache) zeroKey() {
	for i := range kc.masterKey {
		kc.masterKey[i] = 0
	}
}
