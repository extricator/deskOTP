// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package entries

import (
	"encoding/base32"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"deskotp/internal/iconmatch"
	"deskotp/internal/totp"
)

// Manager owns the in-memory entries slice, RWMutex, and undo buffer.
// All CRUD and query operations are methods on Manager.
// External dependencies (save, notify, emit) are injected as closures so that
// Manager has zero Wails imports and is independently testable.
type Manager struct {
	mu             sync.RWMutex
	entries        []totp.Entry
	groups         []GroupInfo
	undoEntry      *totp.Entry
	undoIndex      int
	saveFn         func([]totp.Entry, []GroupInfo) error // injected: app.saveEntries
	notifyFn       func()                                 // injected: app.notifyBackupChanged
	emitCodesFn    func()                                 // injected: app.emitTick (codes:tick)
	emitMetadataFn func()                                 // injected: app.emitMetadata (entries:changed)
}

// New creates a new Manager with the given injected callbacks.
func New(saveFn func([]totp.Entry, []GroupInfo) error, notifyFn func(), emitCodesFn func(), emitMetadataFn func()) *Manager {
	return &Manager{
		entries:        []totp.Entry{},
		groups:         []GroupInfo{},
		saveFn:         saveFn,
		notifyFn:       notifyFn,
		emitCodesFn:    emitCodesFn,
		emitMetadataFn: emitMetadataFn,
	}
}

// maskSecret replaces the middle of a secret with "..." to prevent exposure.
// Secrets with 4 or fewer characters are fully replaced with "****".
func maskSecret(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "..." + s[len(s)-2:]
}

// normalizeSecret strips spaces and uppercases a Base32 secret, matching the
// canonical form expected by TOTP engines (RFC 4648 Base32, no-padding).
// Input: "jbswy3dp ehpk3pxp" -> Output: "JBSWY3DPEHPK3PXP"
func normalizeSecret(s string) string {
	return strings.ToUpper(strings.ReplaceAll(s, " ", ""))
}

// validateEntryFields validates the common advanced fields shared by Add and Update.
// When secretRequired is true (Add path), also validates that secret is non-empty
// and valid base32.
func validateEntryFields(entryType, algo string, period, digits int, secret, icon string, secretRequired bool) error {
	validTypes := map[string]bool{"totp": true, "hotp": true, "steam": true}
	if !validTypes[entryType] {
		return fmt.Errorf("invalid type %q", entryType)
	}

	validAlgos := map[string]bool{"SHA1": true, "SHA256": true, "SHA512": true}
	if !validAlgos[algo] {
		return fmt.Errorf("invalid algorithm %q", algo)
	}

	if period <= 0 {
		return fmt.Errorf("invalid period %d", period)
	}

	if digits < 4 || digits > 10 {
		return fmt.Errorf("invalid digits %d", digits)
	}

	if icon != "" {
		if !slices.Contains(iconmatch.Slugs, icon) {
			return fmt.Errorf("invalid icon slug %q", icon)
		}
	}

	if secretRequired {
		if secret == "" {
			return fmt.Errorf("secret must not be empty")
		}
		if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil {
			return fmt.Errorf("invalid base32 secret: %w", err)
		}
	}

	return nil
}

// Add appends a new OTP entry with a fresh UUID to the in-memory list and
// persists it to storage. The secret is normalized (spaces stripped, uppercased)
// before validation. Returns "duplicate:" error when issuer+name already exists
// (case-insensitive) unless force=true.
//
// Snapshot pattern: mutate under lock, snapshot, unlock, then persist+emit outside lock.
// CRITICAL: saveFn and emitFn must NOT be called while holding mu.
func (m *Manager) Add(name, issuer, secret, entryType, algo string, period, digits int, counter uint64, icon, group string, force bool) error {
	// Normalize secret first — strip spaces and uppercase.
	secret = normalizeSecret(secret)

	if err := validateEntryFields(entryType, algo, period, digits, secret, icon, true); err != nil {
		return fmt.Errorf("entries: addentry: %w", err)
	}

	// Build the duplicate-detection key: lowercased issuer + NUL + lowercased name
	dupeKey := strings.ToLower(issuer) + "\x00" + strings.ToLower(name)

	m.mu.Lock()

	// Duplicate check (skip when force=true)
	if !force {
		for _, e := range m.entries {
			existingKey := strings.ToLower(e.Issuer) + "\x00" + strings.ToLower(e.Name)
			if existingKey == dupeKey {
				m.mu.Unlock() // unlock: early return — no mutation to persist
				return fmt.Errorf("entries: duplicate: entry %q / %q already exists", issuer, name)
			}
		}
	}

	// Construct and append the new entry
	entry := totp.Entry{
		UUID:    uuid.New().String(),
		Name:    name,
		Issuer:  issuer,
		Secret:  secret,
		Type:    entryType,
		Algo:    algo,
		Period:  uint(period),
		Digits:  digits,
		Counter: counter,
		Icon:    icon,
		Group:   group,
	}
	m.entries = append(m.entries, entry)

	snapshot := make([]totp.Entry, len(m.entries))
	copy(snapshot, m.entries)
	grpSnap := make([]GroupInfo, len(m.groups))
	copy(grpSnap, m.groups)
	m.mu.Unlock()

	if err := m.saveFn(snapshot, grpSnap); err != nil {
		return err
	}
	m.notifyFn()
	m.emitCodesFn()
	m.emitMetadataFn()
	return nil
}

// Update modifies an existing entry identified by id (UUID).
// Accepts basic fields (name, issuer, group, note) and advanced fields
// (entryType, algo, period, digits, newSecret). Validates advanced fields
// before mutation. If newSecret is empty, the original secret is preserved.
// UsageCount is never modifiable via Update.
// Follows the CopyCode lock pattern: mutate under lock, snapshot, unlock,
// then persist outside lock. Note: Update does NOT call emitFn.
func (m *Manager) Update(id, name, issuer, group, note, entryType, algo string, period, digits int, newSecret, icon string) error {
	// Validate advanced fields before acquiring lock
	if err := validateEntryFields(entryType, algo, period, digits, "", icon, false); err != nil {
		return fmt.Errorf("entries: update: %w", err)
	}

	m.mu.Lock()
	var found bool
	for i, e := range m.entries {
		if e.UUID == id {
			m.entries[i].Name = name
			m.entries[i].Issuer = issuer
			m.entries[i].Group = group
			m.entries[i].Note = note
			m.entries[i].Type = entryType
			m.entries[i].Algo = algo
			m.entries[i].Period = uint(period)
			m.entries[i].Digits = digits
			if newSecret != "" {
				m.entries[i].Secret = newSecret
			}
			m.entries[i].Icon = icon
			found = true
			break
		}
	}
	if !found {
		m.mu.Unlock() // unlock: early return — no mutation to persist
		return fmt.Errorf("entries: update: account %q not found", id)
	}
	snapshot := make([]totp.Entry, len(m.entries))
	copy(snapshot, m.entries)
	grpSnap := make([]GroupInfo, len(m.groups))
	copy(grpSnap, m.groups)
	m.mu.Unlock()

	if err := m.saveFn(snapshot, grpSnap); err != nil {
		return err
	}
	m.notifyFn()
	m.emitMetadataFn()
	return nil
}

// Delete removes an account by UUID, stashing it in the single-slot undo
// buffer. The undo buffer is overwritten on each delete (only the most recent
// deletion is undoable). Secrets stay in Go — never sent to JavaScript.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()

	idx := -1
	for i, e := range m.entries {
		if e.UUID == id {
			idx = i
			_ = e
			break
		}
	}
	if idx == -1 {
		m.mu.Unlock() // unlock: early return — no mutation to persist
		return fmt.Errorf("entries: delete: account %q not found", id)
	}

	// Stash deleted entry for undo
	deleted := m.entries[idx]
	m.undoEntry = &deleted
	m.undoIndex = idx

	// Remove from slice
	m.entries = append(m.entries[:idx], m.entries[idx+1:]...)

	m.pruneEmptyGroups()
	snapshot := make([]totp.Entry, len(m.entries))
	copy(snapshot, m.entries)
	grpSnap := make([]GroupInfo, len(m.groups))
	copy(grpSnap, m.groups)
	m.mu.Unlock()

	err := m.saveFn(snapshot, grpSnap)
	if err == nil {
		m.notifyFn()
	}
	m.emitCodesFn()
	m.emitMetadataFn()
	return err
}

// UndoDelete restores the most recently deleted entry at its original position
// (clamped to the current slice length if entries changed since deletion).
// Clears the undo buffer after restoring.
func (m *Manager) UndoDelete() error {
	m.mu.Lock()

	if m.undoEntry == nil {
		m.mu.Unlock() // unlock: early return — no mutation to persist
		return fmt.Errorf("entries: undo: nothing to undo")
	}

	entry := *m.undoEntry
	idx := m.undoIndex

	// Clamp index if entries shrunk since deletion
	idx = min(idx, len(m.entries))

	// Insert at idx
	m.entries = append(m.entries[:idx], append([]totp.Entry{entry}, m.entries[idx:]...)...)

	// Clear undo buffer
	m.undoEntry = nil

	snapshot := make([]totp.Entry, len(m.entries))
	copy(snapshot, m.entries)
	grpSnap := make([]GroupInfo, len(m.groups))
	copy(grpSnap, m.groups)
	m.mu.Unlock()

	err := m.saveFn(snapshot, grpSnap)
	if err == nil {
		m.notifyFn()
	}
	m.emitCodesFn()
	m.emitMetadataFn()
	return err
}

// GetDetails returns full entry details for the edit dialog.
// The secret is masked server-side — it never reaches JavaScript in usable form.
func (m *Manager) GetDetails(id string) (EntryDetails, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, e := range m.entries {
		if e.UUID == id {
			return EntryDetails{
				ID:         e.UUID,
				Name:       e.Name,
				Issuer:     e.Issuer,
				Group:      e.Group,
				Note:       e.Note,
				Secret:     maskSecret(e.Secret),
				Type:       e.EffectiveType(),
				Algo:       e.EffectiveAlgo(),
				Period:     int(e.EffectivePeriod()),
				Digits:     e.EffectiveDigits(),
				Icon:       e.Icon,
				UsageCount: e.UsageCount,
			}, nil
		}
	}
	return EntryDetails{}, fmt.Errorf("entries: entry %q not found", id)
}

// GetGroups returns the explicit ordered group list if SetGroups has been called.
// If groups is nil (legacy mode — SetGroups never called), falls back to a sorted
// deduplicated scan of entry Group fields. Returns an empty slice (not nil) always.
func (m *Manager) GetGroups() []GroupInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.groups != nil {
		result := make([]GroupInfo, len(m.groups))
		copy(result, m.groups)
		return result
	}

	// Legacy fallback: scan entries and return sorted, deduplicated list
	seen := make(map[string]bool)
	var groups []GroupInfo
	for _, e := range m.entries {
		if e.Group != "" && !seen[e.Group] {
			seen[e.Group] = true
			groups = append(groups, GroupInfo{Name: e.Group})
		}
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	if groups == nil {
		groups = []GroupInfo{}
	}
	return groups
}

// pruneEmptyGroups removes any group name from m.groups that has no entries
// referencing it. Must be called under m.mu write lock.
func (m *Manager) pruneEmptyGroups() {
	used := make(map[string]bool, len(m.entries))
	for _, e := range m.entries {
		if e.Group != "" {
			used[e.Group] = true
		}
	}
	pruned := m.groups[:0]
	for _, g := range m.groups {
		if used[g.Name] {
			pruned = append(pruned, g)
		}
	}
	m.groups = pruned
}

// SetGroups sets the explicit ordered group list on the Manager.
// Called on startup after loading groups from storage.
func (m *Manager) SetGroups(groups []GroupInfo) {
	m.mu.Lock()
	m.groups = groups
	m.mu.Unlock()
}

// SyncGroupsFromEntries appends any group names found in entries that are not
// already in the groups list. New group names are sorted before appending.
// Used after import to integrate group names from imported entries.
func (m *Manager) SyncGroupsFromEntries() {
	m.mu.Lock()
	if m.groups == nil {
		m.groups = []GroupInfo{}
	}
	existing := make(map[string]bool, len(m.groups))
	for _, g := range m.groups {
		existing[g.Name] = true
	}
	var newGroups []GroupInfo
	for _, e := range m.entries {
		if e.Group != "" && !existing[e.Group] {
			existing[e.Group] = true
			newGroups = append(newGroups, GroupInfo{Name: e.Group})
		}
	}
	sort.Slice(newGroups, func(i, j int) bool { return newGroups[i].Name < newGroups[j].Name })
	m.groups = append(m.groups, newGroups...)
	m.mu.Unlock()
}

// CreateGroup adds a new named group to the ordered group list.
// Returns an error if the name is empty or already exists.
// Does NOT call emitFn (no CodePayload.Group change on create).
func (m *Manager) CreateGroup(name, icon string) error {
	if name == "" {
		return fmt.Errorf("entries: creategroup: name must not be empty")
	}

	m.mu.Lock()
	for _, g := range m.groups {
		if g.Name == name {
			m.mu.Unlock()
			return fmt.Errorf("entries: creategroup: group %q already exists", name)
		}
	}
	m.groups = append(m.groups, GroupInfo{Name: name, Icon: icon})
	entSnap := make([]totp.Entry, len(m.entries))
	copy(entSnap, m.entries)
	grpSnap := make([]GroupInfo, len(m.groups))
	copy(grpSnap, m.groups)
	m.mu.Unlock()

	if err := m.saveFn(entSnap, grpSnap); err != nil {
		return err
	}
	m.notifyFn()
	return nil
}

// RenameGroup renames an existing group and updates all entries in that group.
// Returns an error if newName is empty, oldName is not found, or newName already exists.
// Calls emitFn because renaming changes CodePayload.Group for affected entries.
func (m *Manager) RenameGroup(oldName, newName, icon string) error {
	if newName == "" {
		return fmt.Errorf("entries: renamegroup: new name must not be empty")
	}

	m.mu.Lock()
	idx := -1
	for i, g := range m.groups {
		if g.Name == oldName {
			idx = i
			break
		}
	}
	if idx == -1 {
		m.mu.Unlock()
		return fmt.Errorf("entries: renamegroup: group %q not found", oldName)
	}
	// Check newName not already in groups (unless it's the same as oldName)
	if newName != oldName {
		for _, g := range m.groups {
			if g.Name == newName {
				m.mu.Unlock()
				return fmt.Errorf("entries: renamegroup: group %q already exists", newName)
			}
		}
	}
	m.groups[idx] = GroupInfo{Name: newName, Icon: icon}
	for i := range m.entries {
		if m.entries[i].Group == oldName {
			m.entries[i].Group = newName
		}
	}
	entSnap := make([]totp.Entry, len(m.entries))
	copy(entSnap, m.entries)
	grpSnap := make([]GroupInfo, len(m.groups))
	copy(grpSnap, m.groups)
	m.mu.Unlock()

	if err := m.saveFn(entSnap, grpSnap); err != nil {
		return err
	}
	m.notifyFn()
	m.emitCodesFn()
	m.emitMetadataFn()
	return nil
}

// DeleteGroup removes a group from the ordered list. All entries in that group
// are moved to ungrouped (empty group string).
// Returns an error if the group name is not found.
// Calls emitFn because deleting changes CodePayload.Group for affected entries.
func (m *Manager) DeleteGroup(name string) error {
	m.mu.Lock()
	idx := -1
	for i, g := range m.groups {
		if g.Name == name {
			idx = i
			break
		}
	}
	if idx == -1 {
		m.mu.Unlock()
		return fmt.Errorf("entries: deletegroup: group %q not found", name)
	}
	m.groups = append(m.groups[:idx], m.groups[idx+1:]...)
	for i := range m.entries {
		if m.entries[i].Group == name {
			m.entries[i].Group = ""
		}
	}
	entSnap := make([]totp.Entry, len(m.entries))
	copy(entSnap, m.entries)
	grpSnap := make([]GroupInfo, len(m.groups))
	copy(grpSnap, m.groups)
	m.mu.Unlock()

	if err := m.saveFn(entSnap, grpSnap); err != nil {
		return err
	}
	m.notifyFn()
	m.emitCodesFn()
	m.emitMetadataFn()
	return nil
}

// ReorderGroups replaces the ordered group list with the provided names.
// The provided names must be an exact permutation of the existing group set
// (no additions, no removals, no duplicates). Returns an error on mismatch.
// Does NOT call emitFn (reorder does not change CodePayload.Group values).
func (m *Manager) ReorderGroups(names []string) error {
	m.mu.Lock()
	if len(names) != len(m.groups) {
		m.mu.Unlock()
		return fmt.Errorf("entries: reordergroups: provided names do not match existing groups")
	}
	// Build map of existing GroupInfo by name
	existing := make(map[string]bool, len(m.groups))
	for _, g := range m.groups {
		existing[g.Name] = true
	}
	// Verify every name in names exists in existing, and no duplicates
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if !existing[n] {
			m.mu.Unlock()
			return fmt.Errorf("entries: reordergroups: provided names do not match existing groups")
		}
		if seen[n] {
			m.mu.Unlock()
			return fmt.Errorf("entries: reordergroups: provided names do not match existing groups")
		}
		seen[n] = true
	}
	// Build new groups slice preserving GroupInfo (name+icon) in new order
	newGroups := make([]GroupInfo, len(names))
	groupMap := make(map[string]GroupInfo, len(m.groups))
	for _, g := range m.groups {
		groupMap[g.Name] = g
	}
	for i, n := range names {
		newGroups[i] = groupMap[n]
	}
	m.groups = newGroups
	entSnap := make([]totp.Entry, len(m.entries))
	copy(entSnap, m.entries)
	grpSnap := make([]GroupInfo, len(m.groups))
	copy(grpSnap, m.groups)
	m.mu.Unlock()

	if err := m.saveFn(entSnap, grpSnap); err != nil {
		return err
	}
	m.notifyFn()
	return nil
}

// AnyPeriodBoundary reports whether any time-based entry's code has changed
// between lastEmit and now. Returns true on first call (lastEmit == 0) and
// true when any entry's TOTP time step has rolled over. HOTP entries are
// skipped — their codes only change on counter advance, not on ticks.
func (m *Manager) AnyPeriodBoundary(now, lastEmit int64) bool {
	if lastEmit == 0 {
		return true
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, e := range m.entries {
		if e.EffectiveType() == "hotp" {
			continue
		}
		p := int64(e.EffectivePeriod())
		// Time step changed → code changed for this entry
		if now/p != lastEmit/p {
			return true
		}
	}
	return false
}

// BuildPayloads generates code payloads for all entries at the given time.
// Entries that fail code generation are silently skipped.
// Uses explicit RUnlock (not defer) matching existing emitTick pattern.
func (m *Manager) BuildPayloads(now time.Time) []CodePayload {
	m.mu.RLock()
	payloads := make([]CodePayload, 0, len(m.entries))
	for _, e := range m.entries {
		code, remaining, err := totp.GenerateCode(e, now)
		if err != nil {
			// Skip bad entries rather than crash the ticker.
			// A single malformed entry does not stop all other codes.
			continue
		}
		payloads = append(payloads, CodePayload{
			ID:        e.UUID,
			Code:      code,
			Remaining: remaining,
			Period:    int(e.Period),
			Type:      e.EffectiveType(),
		})
	}
	m.mu.RUnlock() // unlock: read-only snapshot complete
	return payloads
}

// BuildMetadataPayloads generates metadata payloads for all entries.
// Used by emitMetadata to populate entries:changed events.
func (m *Manager) BuildMetadataPayloads() []EntryMetadata {
	m.mu.RLock()
	payloads := make([]EntryMetadata, 0, len(m.entries))
	for _, e := range m.entries {
		payloads = append(payloads, EntryMetadata{
			ID:         e.UUID,
			Name:       e.Name,
			Issuer:     e.Issuer,
			Group:      e.Group,
			Icon:       e.Icon,
			UsageCount: e.UsageCount,
			Type:       e.EffectiveType(),
		})
	}
	m.mu.RUnlock()
	return payloads
}

// Set replaces the in-memory entries slice with the provided slice.
// Used by startup/UnlockVault. Does not call saveFn.
func (m *Manager) Set(entries []totp.Entry) {
	m.mu.Lock()
	m.entries = entries
	m.mu.Unlock()
}

// Snapshot returns a copy of the current in-memory entries slice.
// Used by App for backup export and vault password operations that need raw entries.
func (m *Manager) Snapshot() []totp.Entry {
	m.mu.RLock()
	snap := make([]totp.Entry, len(m.entries))
	copy(snap, m.entries)
	m.mu.RUnlock() // unlock: read-only snapshot complete
	return snap
}

// Clear resets the entries slice to empty and clears the undo buffer.
// Used by performLock. Does not call saveFn.
func (m *Manager) Clear() {
	m.mu.Lock()
	m.entries = []totp.Entry{}
	m.groups = []GroupInfo{}
	m.undoEntry = nil
	m.mu.Unlock()
}

// GenerateAndAdvance finds the entry by ID, generates its current code,
// increments the counter for HOTP entries, and always increments UsageCount.
// Snapshots and persists outside the lock. Returns (code, error).
// Save errors are logged but do not prevent the code from being returned.
// This lets App.CopyCode delegate the entry mutation and handle clipboard + timer separately.
func (m *Manager) GenerateAndAdvance(id string, now time.Time) (string, error) {
	m.mu.Lock()

	var entry totp.Entry
	var idx int
	var found bool
	for i, e := range m.entries {
		if e.UUID == id {
			entry = e
			idx = i
			found = true
			break
		}
	}

	if !found {
		m.mu.Unlock() // unlock: early return — no mutation to persist
		return "", fmt.Errorf("entries: copycode: account %q not found", id)
	}

	code, _, err := totp.GenerateCode(entry, now)
	if err != nil {
		m.mu.Unlock() // unlock: early return — no mutation to persist
		return "", fmt.Errorf("entries: copycode: generate code: %w", err)
	}

	// Increment counter for HOTP BEFORE clipboard write (counter-first ordering).
	// If clipboard write fails, counter is already advanced — this is correct:
	// OTP servers reject replayed codes; forward counter skew is tolerated.
	if entry.EffectiveType() == "hotp" {
		m.entries[idx].Counter++
	}

	// Usage count increment (always, for all entry types)
	m.entries[idx].UsageCount++

	// Snapshot entries under lock for persistence (always, not just HOTP)
	snapshot := make([]totp.Entry, len(m.entries))
	copy(snapshot, m.entries)
	grpSnap := make([]GroupInfo, len(m.groups))
	copy(grpSnap, m.groups)

	m.mu.Unlock()

	// Persist outside lock (always, not just HOTP) — storage.Save does file I/O
	// and must not block the tick loop.
	if saveErr := m.saveFn(snapshot, grpSnap); saveErr != nil {
		// Log error but do NOT return it — code is still valid; caller should get it.
		_ = saveErr
	}

	return code, nil
}
