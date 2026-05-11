// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package main

// CreateGroup creates a new named group in the ordered group list.
// Returns an error if the name is empty or already exists.
func (a *App) CreateGroup(name, icon string) error {
	return a.entryMgr.CreateGroup(name, icon)
}

// RenameGroup renames an existing group. All entries assigned to the old
// group name are updated to the new name in a single atomic save.
// Returns an error if oldName is not found or newName is empty/duplicate.
func (a *App) RenameGroup(oldName, newName, icon string) error {
	return a.entryMgr.RenameGroup(oldName, newName, icon)
}

// DeleteGroup removes a group from the ordered list. All entries in the
// deleted group are moved to the ungrouped state (empty group string).
// Returns an error if the group name is not found.
func (a *App) DeleteGroup(name string) error {
	return a.entryMgr.DeleteGroup(name)
}

// ReorderGroups replaces the ordered group list with the provided names.
// The provided names must be an exact permutation of the existing group set
// (no additions, no removals). Returns an error on mismatch.
func (a *App) ReorderGroups(names []string) error {
	return a.entryMgr.ReorderGroups(names)
}
