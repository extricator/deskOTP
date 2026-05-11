// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

// ImportCounts carries the structured result of a file import operation.
// Frontend uses these integers to compose localized messages instead of reading
// the pre-composed Go summary string (ImportResult.summary is DEPRECATED).
export interface ImportCounts {
  added: number;
  skipped: number;
  format?: string;
}

// CodePayload mirrors the Go CodePayload struct emitted by codes:tick events.
// CRITICAL: No secret field — TOTP secrets never reach JavaScript.
// type is "totp" | "hotp" | "steam" — used for conditional rendering in OtpCard.
export interface CodePayload {
  id: string;
  name: string;
  issuer: string;
  code: string;
  remaining: number;
  period: number;
  type: string; // "totp" | "hotp" | "steam"
  icon: string;
  group: string;
  usageCount: number;
}

// CodeTickPayload mirrors the shrunk Go CodePayload — TOTP-only fields from codes:tick.
// Used internally by useCodeStore for merge; not exported to components.
export interface CodeTickPayload {
  id: string;
  code: string;
  remaining: number;
  period: number;
  type: string;
}

// EntryMetadata mirrors the Go EntryMetadata struct from entries:changed events.
// Used internally by useCodeStore for merge; not exported to components.
export interface EntryMetadata {
  id: string;
  name: string;
  issuer: string;
  group: string;
  icon: string;
  usageCount: number;
  type: string;
}

// SortOption defines the available sort presets for the token list.
export type SortOption = "issuer" | "name" | "date-added" | "usage-count";
export type SortDirection = "asc" | "desc";

// Format TOTP code with space separator for readability.
// 6 digits: "123 456", 8 digits: "1234 5678"
// Code length determines split point — no digits field needed.
export function formatCode(code: string): string {
  const mid = Math.floor(code.length / 2);
  return code.slice(0, mid) + " " + code.slice(mid);
}
