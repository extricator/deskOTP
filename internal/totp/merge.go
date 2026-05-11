// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

// internal/totp/merge.go
package totp

import "strings"

// MergeResult reports how many incoming entries were added versus skipped.
// Skipped means the entry already exists in the result set (by issuer+name key).
type MergeResult struct {
	Added   int
	Skipped int
}

// mergeKey returns a case-insensitive composite key for deduplication.
// The NUL byte separator prevents prefix collisions such as
// Issuer="Foo", Name="Bar" vs Issuer="FooBar", Name="".
func mergeKey(e Entry) string {
	return strings.ToLower(e.Issuer) + "\x00" + strings.ToLower(e.Name)
}

// Merge combines existing and incoming OTP entries, deduplicating by a
// case-insensitive issuer+name composite key.
//
// Rules:
//   - Entries already in existing are kept unchanged (HOTP counters preserved).
//   - Incoming entries whose key is not in the result set are appended.
//   - Incoming entries whose key is already present are skipped.
//   - Duplicates within incoming itself are also detected and skipped.
//
// The returned slice is a new slice; neither existing nor incoming is modified.
func Merge(existing, incoming []Entry) ([]Entry, MergeResult) {
	// Build lookup map from existing entries.
	seen := make(map[string]bool, len(existing))
	for _, e := range existing {
		seen[mergeKey(e)] = true
	}

	// Start result from a copy of existing.
	result := make([]Entry, len(existing))
	copy(result, existing)

	var mr MergeResult
	for _, e := range incoming {
		k := mergeKey(e)
		if seen[k] {
			mr.Skipped++
		} else {
			seen[k] = true
			result = append(result, e)
			mr.Added++
		}
	}

	return result, mr
}
