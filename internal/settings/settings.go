// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"deskotp/internal/atomicfile"
)

const (
	appDirName       = "deskotp"
	settingsFileName = "settings.json"
)

// configDirOverride is empty in production. Tests set it to t.TempDir() via redirectToTempDir().
var configDirOverride string

// SetConfigDirOverride sets the config directory override for testing.
// Returns a function that restores the original value. Only used by external
// test packages (internal/settings tests use the unexported var directly).
func SetConfigDirOverride(dir string) func() {
	original := configDirOverride
	configDirOverride = dir
	return func() { configDirOverride = original }
}

// Store holds application settings as key-value string pairs with atomic persistence.
type Store struct {
	mu   sync.RWMutex
	data map[string]string
}

// New returns a new Store with an initialized map.
func New() *Store {
	return &Store{data: make(map[string]string)}
}

// settingsPath returns the full path to settings.json in the platform config directory,
// creating the deskotp subdirectory if it does not already exist.
func settingsPath() (string, error) {
	base := configDirOverride
	if base == "" {
		var err error
		base, err = os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("settings: resolve config dir: %w", err)
		}
	}

	dir := filepath.Join(base, appDirName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("settings: create config dir: %w", err)
	}

	return filepath.Join(dir, settingsFileName), nil
}

// Load reads settings from disk. If the file does not exist, it creates one
// with an empty JSON object "{}". This ensures settings.json always exists
// after a successful Load call.
func (s *Store) Load() error {
	path, err := settingsPath()
	if err != nil {
		return err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// First-run case: create file with empty object.
			s.mu.Lock()
			s.data = make(map[string]string)
			s.mu.Unlock()
			return s.save()
		}
		return fmt.Errorf("settings: read file: %w", err)
	}

	var parsed map[string]string
	if err := json.Unmarshal(data, &parsed); err != nil {
		return fmt.Errorf("settings: unmarshal: %w", err)
	}

	if parsed == nil {
		parsed = make(map[string]string)
	}

	s.mu.Lock()
	s.data = parsed
	s.mu.Unlock()

	return nil
}

// Get returns the value for key, or an empty string if the key is absent.
func (s *Store) Get(key string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data[key]
}

// Set updates a key-value pair and persists the full map to disk atomically.
func (s *Store) Set(key, value string) error {
	s.mu.Lock()
	s.data[key] = value
	s.mu.Unlock()
	return s.save()
}

// save writes the current data map to settings.json atomically using a temp file
// and os.Rename, with 0600 permissions.
func (s *Store) save() error {
	path, err := settingsPath()
	if err != nil {
		return err
	}

	s.mu.RLock()
	data, err := json.MarshalIndent(s.data, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("settings: marshal: %w", err)
	}

	return atomicfile.WriteAtomic(path, data)
}
