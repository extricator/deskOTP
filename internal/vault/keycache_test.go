// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package vault_test

import (
	"bytes"
	"sync"
	"testing"

	"deskotp/internal/vault"
)

func TestKeyCacheInitiallyLocked(t *testing.T) {
	kc := vault.NewKeyCache()

	key, err := kc.Key()
	if key != nil {
		t.Fatalf("expected nil key, got %v", key)
	}
	if err != vault.ErrVaultLocked {
		t.Fatalf("expected ErrVaultLocked, got %v", err)
	}
	if kc.IsUnlocked() {
		t.Fatal("expected IsUnlocked() == false for new cache")
	}
}

func TestKeyCacheUnlockAndRetrieve(t *testing.T) {
	kc := vault.NewKeyCache()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	kc.Unlock(masterKey)

	key, err := kc.Key()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(key, masterKey) {
		t.Fatalf("key mismatch: got %v, want %v", key, masterKey)
	}
	if !kc.IsUnlocked() {
		t.Fatal("expected IsUnlocked() == true after Unlock")
	}
}

func TestKeyCacheKeyReturnsCopy(t *testing.T) {
	kc := vault.NewKeyCache()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	kc.Unlock(masterKey)

	key1, _ := kc.Key()
	key2, _ := kc.Key()

	// Modify key1
	key1[0] = 0xFF

	// key2 should be unchanged
	if key2[0] == 0xFF {
		t.Fatal("Key() must return a defensive copy; modifying one result affected the other")
	}
}

func TestKeyCacheUnlockCopiesInput(t *testing.T) {
	kc := vault.NewKeyCache()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	original := make([]byte, 32)
	copy(original, masterKey)

	kc.Unlock(masterKey)

	// Modify the original slice passed to Unlock
	masterKey[0] = 0xFF

	key, _ := kc.Key()
	if key[0] == 0xFF {
		t.Fatal("Unlock must defensively copy the input; modifying original affected cached key")
	}
	if !bytes.Equal(key, original) {
		t.Fatalf("cached key changed after modifying input: got %v, want %v", key, original)
	}
}

func TestKeyCacheLockZeroesMemory(t *testing.T) {
	kc := vault.NewKeyCache()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 1) // non-zero values
	}
	kc.Unlock(masterKey)

	kc.Lock()

	key, err := kc.Key()
	if key != nil {
		t.Fatalf("expected nil key after Lock, got %v", key)
	}
	if err != vault.ErrVaultLocked {
		t.Fatalf("expected ErrVaultLocked after Lock, got %v", err)
	}
	if kc.IsUnlocked() {
		t.Fatal("expected IsUnlocked() == false after Lock")
	}
}

func TestKeyCacheLockWithoutUnlock(t *testing.T) {
	kc := vault.NewKeyCache()
	// Should not panic
	kc.Lock()
}

func TestKeyCacheConcurrentAccess(t *testing.T) {
	kc := vault.NewKeyCache()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	var wg sync.WaitGroup

	// 10 goroutines calling Key() concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				kc.Key()
				kc.IsUnlocked()
			}
		}()
	}

	// One goroutine doing Unlock then Lock
	wg.Add(1)
	go func() {
		defer wg.Done()
		kc.Unlock(masterKey)
		for j := 0; j < 50; j++ {
			kc.Key()
		}
		kc.Lock()
	}()

	wg.Wait()
}

func TestKeyCacheReUnlock(t *testing.T) {
	kc := vault.NewKeyCache()

	key1 := make([]byte, 32)
	for i := range key1 {
		key1[i] = 0x01
	}

	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = 0x02
	}

	kc.Unlock(key1)
	kc.Unlock(key2)

	got, err := kc.Key()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, key2) {
		t.Fatalf("re-unlock should replace key: got %v, want %v", got, key2)
	}
}
