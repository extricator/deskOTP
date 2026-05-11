// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

// internal/totp/merge_test.go
package totp

import (
	"testing"
)

// TestMerge covers all edge cases for the Merge function.
// Test cases are written RED-first per TDD discipline.
func TestMerge(t *testing.T) {
	t.Run("identity merge re-imports same data", func(t *testing.T) {
		existing := []Entry{
			{Issuer: "GitHub", Name: "user@example.com"},
			{Issuer: "Google", Name: "me@gmail.com"},
		}
		incoming := []Entry{
			{Issuer: "GitHub", Name: "user@example.com"},
			{Issuer: "Google", Name: "me@gmail.com"},
		}
		result, mr := Merge(existing, incoming)
		if len(result) != 2 {
			t.Errorf("identity: want len 2, got %d", len(result))
		}
		if mr.Added != 0 {
			t.Errorf("identity: want Added==0, got %d", mr.Added)
		}
		if mr.Skipped != 2 {
			t.Errorf("identity: want Skipped==2, got %d", mr.Skipped)
		}
	})

	t.Run("disjoint merge all new entries appended", func(t *testing.T) {
		existing := []Entry{
			{Issuer: "GitHub", Name: "user@example.com"},
		}
		incoming := []Entry{
			{Issuer: "AWS", Name: "admin@company.com"},
		}
		result, mr := Merge(existing, incoming)
		if len(result) != 2 {
			t.Errorf("disjoint: want len 2, got %d", len(result))
		}
		if mr.Added != 1 {
			t.Errorf("disjoint: want Added==1, got %d", mr.Added)
		}
		if mr.Skipped != 0 {
			t.Errorf("disjoint: want Skipped==0, got %d", mr.Skipped)
		}
	})

	t.Run("overlap merge adds only new entries", func(t *testing.T) {
		existing := []Entry{
			{Issuer: "GitHub", Name: "user@example.com"},
			{Issuer: "Google", Name: "me@gmail.com"},
		}
		incoming := []Entry{
			{Issuer: "GitHub", Name: "user@example.com"},
			{Issuer: "AWS", Name: "admin@company.com"},
		}
		result, mr := Merge(existing, incoming)
		if len(result) != 3 {
			t.Errorf("overlap: want len 3, got %d", len(result))
		}
		if mr.Added != 1 {
			t.Errorf("overlap: want Added==1, got %d", mr.Added)
		}
		if mr.Skipped != 1 {
			t.Errorf("overlap: want Skipped==1, got %d", mr.Skipped)
		}
	})

	t.Run("HOTP counter preserved from existing entry", func(t *testing.T) {
		existing := []Entry{
			{Issuer: "Service", Name: "user", Type: "hotp", Counter: 42},
		}
		incoming := []Entry{
			{Issuer: "Service", Name: "user", Type: "hotp", Counter: 5},
		}
		result, mr := Merge(existing, incoming)
		if len(result) != 1 {
			t.Fatalf("HOTP counter: want len 1, got %d", len(result))
		}
		if result[0].Counter != 42 {
			t.Errorf("HOTP counter: want Counter==42 (existing preserved), got %d", result[0].Counter)
		}
		if mr.Added != 0 {
			t.Errorf("HOTP counter: want Added==0, got %d", mr.Added)
		}
		if mr.Skipped != 1 {
			t.Errorf("HOTP counter: want Skipped==1, got %d", mr.Skipped)
		}
	})

	t.Run("case-insensitive key treats same account from different apps as one", func(t *testing.T) {
		existing := []Entry{
			{Issuer: "GitHub", Name: "User@Example.com"},
		}
		incoming := []Entry{
			{Issuer: "github", Name: "user@example.com"},
		}
		result, mr := Merge(existing, incoming)
		if len(result) != 1 {
			t.Errorf("case-insensitive: want len 1, got %d", len(result))
		}
		if mr.Added != 0 {
			t.Errorf("case-insensitive: want Added==0, got %d", mr.Added)
		}
		if mr.Skipped != 1 {
			t.Errorf("case-insensitive: want Skipped==1, got %d", mr.Skipped)
		}
	})

	t.Run("empty issuer entries match by name alone", func(t *testing.T) {
		existing := []Entry{
			{Issuer: "", Name: "user@example.com"},
		}
		incoming := []Entry{
			{Issuer: "", Name: "user@example.com"},
		}
		result, mr := Merge(existing, incoming)
		if len(result) != 1 {
			t.Errorf("empty issuer: want len 1, got %d", len(result))
		}
		if mr.Added != 0 {
			t.Errorf("empty issuer: want Added==0, got %d", mr.Added)
		}
		if mr.Skipped != 1 {
			t.Errorf("empty issuer: want Skipped==1, got %d", mr.Skipped)
		}
	})

	t.Run("empty issuer does not collide with non-empty issuer same name", func(t *testing.T) {
		existing := []Entry{
			{Issuer: "", Name: "user@example.com"},
		}
		incoming := []Entry{
			{Issuer: "GitHub", Name: "user@example.com"},
		}
		result, mr := Merge(existing, incoming)
		if len(result) != 2 {
			t.Errorf("empty vs non-empty issuer: want len 2, got %d", len(result))
		}
		if mr.Added != 1 {
			t.Errorf("empty vs non-empty issuer: want Added==1, got %d", mr.Added)
		}
		if mr.Skipped != 0 {
			t.Errorf("empty vs non-empty issuer: want Skipped==0, got %d", mr.Skipped)
		}
	})

	t.Run("empty existing treats all incoming as added", func(t *testing.T) {
		existing := []Entry{}
		incoming := []Entry{
			{Issuer: "GitHub", Name: "user"},
			{Issuer: "Google", Name: "me"},
		}
		result, mr := Merge(existing, incoming)
		if len(result) != 2 {
			t.Errorf("empty existing: want len 2, got %d", len(result))
		}
		if mr.Added != 2 {
			t.Errorf("empty existing: want Added==2, got %d", mr.Added)
		}
		if mr.Skipped != 0 {
			t.Errorf("empty existing: want Skipped==0, got %d", mr.Skipped)
		}
	})

	t.Run("empty incoming returns existing unchanged", func(t *testing.T) {
		existing := []Entry{
			{Issuer: "GitHub", Name: "user"},
		}
		incoming := []Entry{}
		result, mr := Merge(existing, incoming)
		if len(result) != 1 {
			t.Errorf("empty incoming: want len 1, got %d", len(result))
		}
		if mr.Added != 0 {
			t.Errorf("empty incoming: want Added==0, got %d", mr.Added)
		}
		if mr.Skipped != 0 {
			t.Errorf("empty incoming: want Skipped==0, got %d", mr.Skipped)
		}
	})

	t.Run("both empty returns empty slice", func(t *testing.T) {
		result, mr := Merge([]Entry{}, []Entry{})
		if len(result) != 0 {
			t.Errorf("both empty: want len 0, got %d", len(result))
		}
		if mr.Added != 0 {
			t.Errorf("both empty: want Added==0, got %d", mr.Added)
		}
		if mr.Skipped != 0 {
			t.Errorf("both empty: want Skipped==0, got %d", mr.Skipped)
		}
	})

	t.Run("incoming duplicate within itself counts second as skipped", func(t *testing.T) {
		existing := []Entry{}
		incoming := []Entry{
			{Issuer: "GitHub", Name: "user"},
			{Issuer: "GitHub", Name: "user"},
		}
		result, mr := Merge(existing, incoming)
		if len(result) != 1 {
			t.Errorf("self-duplicate: want len 1, got %d", len(result))
		}
		if mr.Added != 1 {
			t.Errorf("self-duplicate: want Added==1, got %d", mr.Added)
		}
		if mr.Skipped != 1 {
			t.Errorf("self-duplicate: want Skipped==1, got %d", mr.Skipped)
		}
	})
}
