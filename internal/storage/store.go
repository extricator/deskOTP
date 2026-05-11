// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"deskotp/internal/atomicfile"
	"deskotp/internal/entries"
	"deskotp/internal/totp"
)

const (
	appDirName   = "deskotp"
	dataFileName = "accounts.json"
)

// configDirOverride is empty in production. Tests set it to t.TempDir() via redirectToTempDir().
var configDirOverride string

// SetConfigDirOverride sets the config directory override for testing.
// Returns a function that restores the original value. Only used by external
// test packages (internal/storage tests use the unexported var directly).
func SetConfigDirOverride(dir string) func() {
	original := configDirOverride
	configDirOverride = dir
	return func() { configDirOverride = original }
}

// dataPath returns the full path to accounts.json in the platform config directory,
// creating the deskotp subdirectory if it does not already exist.
//
// If configDirOverride is non-empty (test mode), it is used as the base directory
// instead of os.UserConfigDir(). This keeps tests isolated from ~/.config/deskotp/.
func dataPath() (string, error) {
	base := configDirOverride
	if base == "" {
		var err error
		base, err = os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("storage: resolve config dir: %w", err)
		}
	}

	dir := filepath.Join(base, appDirName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("storage: create config dir: %w", err)
	}

	return filepath.Join(dir, dataFileName), nil
}

// StorageFile is the on-disk format for accounts.json from v4.5 onward.
// Groups used to be []string; unmarshalGroups handles both formats transparently.
type StorageFile struct {
	Entries []totp.Entry        `json:"entries"`
	Groups  []entries.GroupInfo `json:"groups"`
}

// Save marshals entries and groups to JSON and persists them atomically to the platform
// config directory as accounts.json with 0600 permissions.
//
// Atomicity is achieved by writing to a temp file in the same directory
// (to avoid EXDEV cross-device rename errors) and then calling os.Rename,
// which is atomic on POSIX systems. A mid-write crash will leave the original
// file intact.
func Save(ents []totp.Entry, groups []entries.GroupInfo) error {
	path, err := dataPath()
	if err != nil {
		return err
	}

	if groups == nil {
		groups = []entries.GroupInfo{}
	}

	sf := StorageFile{Entries: ents, Groups: groups}
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return fmt.Errorf("storage: marshal entries: %w", err)
	}

	return atomicfile.WriteAtomic(path, data)
}

// SaveRaw writes raw bytes atomically to accounts.json.
// Used when vault encryption produces the final bytes externally.
func SaveRaw(data []byte) error {
	path, err := dataPath()
	if err != nil {
		return err
	}
	return atomicfile.WriteAtomic(path, data)
}

// LoadRaw reads raw bytes from accounts.json without JSON parsing.
// Returns (nil, nil) if file does not exist (first-run case).
func LoadRaw() ([]byte, error) {
	path, err := dataPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: read accounts file: %w", err)
	}

	return data, nil
}

// Load reads and unmarshals the accounts.json file from the platform config directory.
//
// If the file does not exist (first run), Load returns an empty slice and nil error.
// Supports both legacy bare-array format and the new StorageFile wrapper format.
// When loading legacy format, groups is nil.
// Groups field supports both old []string and new []GroupInfo formats transparently.
func Load() ([]totp.Entry, []entries.GroupInfo, error) {
	path, err := dataPath()
	if err != nil {
		return nil, nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		// First-run case: no file yet → return empty slice, not an error.
		if errors.Is(err, fs.ErrNotExist) {
			return []totp.Entry{}, nil, nil
		}
		return nil, nil, fmt.Errorf("storage: read accounts file: %w", err)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return []totp.Entry{}, []entries.GroupInfo{}, nil
	}

	switch trimmed[0] {
	case '[':
		// Legacy bare array format
		var ents []totp.Entry
		if err := json.Unmarshal(data, &ents); err != nil {
			return nil, nil, fmt.Errorf("storage: unmarshal accounts: %w", err)
		}
		if ents == nil {
			ents = []totp.Entry{}
		}
		return ents, nil, nil
	case '{':
		// New StorageFile wrapper format — use two-step unmarshal for backward-compatible
		// groups deserialization (supports both old []string and new []GroupInfo formats).
		type rawStorageFile struct {
			Entries []totp.Entry    `json:"entries"`
			Groups  json.RawMessage `json:"groups"`
		}
		var raw rawStorageFile
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, nil, fmt.Errorf("storage: unmarshal accounts: %w", err)
		}
		if raw.Entries == nil {
			raw.Entries = []totp.Entry{}
		}
		groups, err := unmarshalGroups(raw.Groups)
		if err != nil {
			return nil, nil, fmt.Errorf("storage: unmarshal groups: %w", err)
		}
		return raw.Entries, groups, nil
	default:
		return nil, nil, fmt.Errorf("storage: unmarshal accounts: unrecognized format")
	}
}

// unmarshalGroups deserializes a JSON groups field that may be either the old
// []string format or the new []GroupInfo format. This ensures backward compatibility
// when reading accounts.json written by older versions of the app.
func unmarshalGroups(data json.RawMessage) ([]entries.GroupInfo, error) {
	if len(data) == 0 || string(data) == "null" {
		return []entries.GroupInfo{}, nil
	}
	// Try new format first: []GroupInfo
	var groups []entries.GroupInfo
	if err := json.Unmarshal(data, &groups); err == nil {
		if groups == nil {
			groups = []entries.GroupInfo{}
		}
		return groups, nil
	}
	// Fall back to old format: []string
	var names []string
	if err := json.Unmarshal(data, &names); err != nil {
		return nil, fmt.Errorf("unrecognized format: %w", err)
	}
	result := make([]entries.GroupInfo, len(names))
	for i, name := range names {
		result[i] = entries.GroupInfo{Name: name}
	}
	return result, nil
}
