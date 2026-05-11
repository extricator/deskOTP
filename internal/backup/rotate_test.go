// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package backup_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"deskotp/internal/backup"
)

// createBackupFile creates a fake backup file with the given name in dir.
func createBackupFile(t *testing.T, dir, name string) {
	t.Helper()
	f := filepath.Join(dir, name)
	if err := os.WriteFile(f, []byte("{}"), 0644); err != nil {
		t.Fatalf("createBackupFile: %v", err)
	}
}

func TestRotate_DeletesOldestBeyondRetention(t *testing.T) {
	dir := t.TempDir()
	names := []string{
		"deskotp-backup-20260101-000001.json",
		"deskotp-backup-20260101-000002.json",
		"deskotp-backup-20260101-000003.json",
		"deskotp-backup-20260101-000004.json",
		"deskotp-backup-20260101-000005.json",
	}
	for _, n := range names {
		createBackupFile(t, dir, n)
	}

	if err := backup.Rotate(dir, 3); err != nil {
		t.Fatalf("Rotate returned error: %v", err)
	}

	// Oldest 2 must be gone
	for _, n := range names[:2] {
		if _, err := os.Stat(filepath.Join(dir, n)); !os.IsNotExist(err) {
			t.Errorf("expected %s to be deleted, but it still exists", n)
		}
	}
	// Newest 3 must remain
	for _, n := range names[2:] {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("expected %s to remain, but got: %v", n, err)
		}
	}
}

func TestRotate_UnderRetention_DeletesNothing(t *testing.T) {
	dir := t.TempDir()
	names := []string{
		"deskotp-backup-20260101-000001.json",
		"deskotp-backup-20260101-000002.json",
		"deskotp-backup-20260101-000003.json",
	}
	for _, n := range names {
		createBackupFile(t, dir, n)
	}

	if err := backup.Rotate(dir, 5); err != nil {
		t.Fatalf("Rotate returned error: %v", err)
	}

	for _, n := range names {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("expected %s to remain, but got: %v", n, err)
		}
	}
}

func TestRotate_AtRetention_DeletesNothing(t *testing.T) {
	dir := t.TempDir()
	names := []string{
		"deskotp-backup-20260101-000001.json",
		"deskotp-backup-20260101-000002.json",
		"deskotp-backup-20260101-000003.json",
	}
	for _, n := range names {
		createBackupFile(t, dir, n)
	}

	if err := backup.Rotate(dir, 3); err != nil {
		t.Fatalf("Rotate returned error: %v", err)
	}

	for _, n := range names {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("expected %s to remain, but got: %v", n, err)
		}
	}
}

func TestRotate_ZeroRetention_Noop(t *testing.T) {
	dir := t.TempDir()
	createBackupFile(t, dir, "deskotp-backup-20260101-000001.json")

	if err := backup.Rotate(dir, 0); err != nil {
		t.Fatalf("Rotate returned error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "deskotp-backup-20260101-000001.json")); err != nil {
		t.Errorf("expected file to remain: %v", err)
	}
}

func TestRotate_NegativeRetention_Noop(t *testing.T) {
	dir := t.TempDir()
	createBackupFile(t, dir, "deskotp-backup-20260101-000001.json")

	if err := backup.Rotate(dir, -1); err != nil {
		t.Fatalf("Rotate returned error: %v", err)
	}
}

func TestRotate_TmpFilesIgnored(t *testing.T) {
	dir := t.TempDir()
	// 3 real backups
	for i := 1; i <= 3; i++ {
		createBackupFile(t, dir, fmt.Sprintf("deskotp-backup-2026010%d-000001.json", i))
	}
	// tmp files — must NOT be counted or deleted
	createBackupFile(t, dir, "deskotp-backup-20260101-000001.json.tmp")
	createBackupFile(t, dir, "deskotp-backup-20260102-000001.json.tmp")

	// With retention=2 and 3 real files, should delete 1 oldest real file
	if err := backup.Rotate(dir, 2); err != nil {
		t.Fatalf("Rotate returned error: %v", err)
	}

	// Oldest real file deleted
	if _, err := os.Stat(filepath.Join(dir, "deskotp-backup-20260101-000001.json")); !os.IsNotExist(err) {
		t.Errorf("expected oldest .json to be deleted")
	}
	// tmp files untouched
	for _, n := range []string{"deskotp-backup-20260101-000001.json.tmp", "deskotp-backup-20260102-000001.json.tmp"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("expected tmp file %s to remain: %v", n, err)
		}
	}
}

func TestRotate_EmptyDirectory_ReturnsNil(t *testing.T) {
	dir := t.TempDir()
	if err := backup.Rotate(dir, 5); err != nil {
		t.Fatalf("Rotate on empty dir returned error: %v", err)
	}
}

func TestRotate_ContinuesOnRemoveError(t *testing.T) {
	dir := t.TempDir()
	names := []string{
		"deskotp-backup-20260101-000001.json",
		"deskotp-backup-20260101-000002.json",
		"deskotp-backup-20260101-000003.json",
		"deskotp-backup-20260101-000004.json",
	}
	for _, n := range names {
		createBackupFile(t, dir, n)
	}

	// Make dir read-only so removals fail
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(dir, 0755) //nolint:errcheck

	err := backup.Rotate(dir, 2)
	if err == nil {
		t.Error("expected error when os.Remove fails, got nil")
	}
}
