// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package entries

// CodePayload is the JSON-serializable struct emitted on every codes:tick event.
// CRITICAL: No Secret field — TOTP secrets must never reach JavaScript.
// This is a locked architecture decision (STATE.md).
// id corresponds to totp.Entry.UUID (unique identifier per account).
// Type is "totp", "hotp", or "steam" — used by the frontend to adjust display
// (e.g. suppress countdown bar for HOTP, display Steam codes unsplit).
// Display metadata (name, issuer, group, icon, usageCount) is carried separately
// by EntryMetadata on entries:changed events — not duplicated here.
type CodePayload struct {
	ID        string `json:"id"`
	Code      string `json:"code"`
	Remaining int    `json:"remaining"`
	Period    int    `json:"period"`
	Type      string `json:"type"`
}

// EntryMetadata is the JSON-serializable struct emitted on entries:changed events.
// Carries all display metadata but NO code/remaining/period fields.
// CRITICAL: No Secret field — TOTP secrets must never reach JavaScript.
type EntryMetadata struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Issuer     string `json:"issuer"`
	Group      string `json:"group"`
	Icon       string `json:"icon"`
	UsageCount int    `json:"usageCount"`
	Type       string `json:"type"`
}

// EntryDetails is the JSON-serializable struct returned by GetEntryDetails.
// Secret is masked server-side before reaching JavaScript.
// Secret is ALWAYS populated via maskSecret(), never Entry.Secret directly.
type EntryDetails struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Issuer     string `json:"issuer"`
	Group      string `json:"group"`
	Note       string `json:"note"`
	Secret     string `json:"secret"`
	Type       string `json:"type"`
	Algo       string `json:"algo"`
	Period     int    `json:"period"`
	Digits     int    `json:"digits"`
	Icon       string `json:"icon"`
	UsageCount int    `json:"usageCount"`
}
