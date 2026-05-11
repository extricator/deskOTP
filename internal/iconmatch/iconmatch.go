// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

// Package iconmatch provides issuer-to-icon-slug matching with a deterministic
// three-tier lookup: exact slug, alias table, normalized contains.
package iconmatch

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"
)

//go:embed aliases.json
var aliasData []byte

// aliases maps lowercased issuer variants to their canonical icon slug.
var aliases map[string]string

// slugSet provides O(1) lookup for valid icon slugs.
var slugSet map[string]bool

// sortedSlugs contains slugs with len >= 4, sorted alphabetically,
// used for deterministic tier-3 substring matching.
var sortedSlugs []string

func init() {
	// Parse alias table
	aliases = make(map[string]string)
	if err := json.Unmarshal(aliasData, &aliases); err != nil {
		panic("iconmatch: failed to parse aliases.json: " + err.Error())
	}

	// Build slug set from the canonical Slugs list
	slugSet = make(map[string]bool, len(Slugs))
	for _, slug := range Slugs {
		slugSet[slug] = true
	}

	// Build sorted slug list for tier 3, filtering out short slugs (< 4 chars)
	// to avoid false positives like "x", "hp", "ea", "fly", "npm", "ovh", "sap", "wix".
	sortedSlugs = make([]string, 0, len(Slugs))
	for _, slug := range Slugs {
		if len(slug) >= 4 {
			sortedSlugs = append(sortedSlugs, slug)
		}
	}
	sort.Strings(sortedSlugs)
}

// Match returns the icon slug for the given issuer name, or empty string if no match.
//
// Three-tier lookup (in order):
//  1. Exact slug: lowercased issuer is a valid slug
//  2. Alias table: lowercased issuer is a key in aliases.json
//  3. Normalized contains: lowercased issuer contains a slug as substring (longest match wins, slugs < 4 chars excluded)
func Match(issuer string) string {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return ""
	}

	normalized := strings.ToLower(issuer)

	// Tier 1: exact slug match
	if slugSet[normalized] {
		return normalized
	}

	// Tier 2: alias lookup
	if slug, ok := aliases[normalized]; ok {
		return slug
	}

	// Tier 3: substring contains (longest match wins)
	// Also check with spaces removed for compound names like "digitalocean" in "digital ocean cloud".
	compacted := strings.ReplaceAll(normalized, " ", "")
	var best string
	for _, slug := range sortedSlugs {
		if strings.Contains(normalized, slug) || strings.Contains(compacted, slug) {
			if len(slug) > len(best) {
				best = slug
			}
		}
	}

	return best
}
