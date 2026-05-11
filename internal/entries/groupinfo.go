// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package entries

// GroupInfo holds the name and optional icon slug for a group.
// Icon is stored as a slug (same namespace as entry icon slugs).
// omitempty ensures legacy compatibility — old JSON without "icon" deserializes cleanly.
type GroupInfo struct {
	Name string `json:"name"`
	Icon string `json:"icon,omitempty"`
}
