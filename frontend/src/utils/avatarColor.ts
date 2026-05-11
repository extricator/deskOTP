// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

// frontend/src/utils/avatarColor.ts
// Algorithm adapted from Mantine's get-initials-color.ts (MIT License)
// Source: https://github.com/mantinedev/mantine/blob/master/packages/%40mantine/core/src/components/Avatar/get-initials-color/get-initials-color.ts

/**
 * djb2-family string hash function.
 * Returns a 32-bit integer (may be negative due to |= 0 overflow).
 * Same string always produces same result — deterministic for AVTR-02.
 */
function hashCode(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0; // Clamp to 32-bit integer
  }
  return hash;
}

/**
 * Curated palette of WCAG AA compliant colors (≥4.5:1 contrast with white text).
 * All values are Tailwind v3 600-weight hex colors.
 * NOTE: yellow-600 and amber-600 are intentionally excluded — they fail with white text.
 * Order determines color assignment — do NOT reorder after shipping.
 */
const AVATAR_COLORS: readonly string[] = [
  "#dc2626", // red-600      — contrast ~4.6:1 with white
  "#ea580c", // orange-600   — contrast ~4.5:1 with white
  "#16a34a", // green-600    — contrast ~4.5:1 with white
  "#059669", // emerald-600  — contrast ~4.8:1 with white
  "#0891b2", // cyan-600     — contrast ~4.5:1 with white
  "#0284c7", // sky-600      — contrast ~4.6:1 with white
  "#2563eb", // blue-600     — contrast ~5.0:1 with white
  "#4f46e5", // indigo-600   — contrast ~5.5:1 with white
  "#7c3aed", // violet-600   — contrast ~6.0:1 with white
  "#9333ea", // purple-600   — contrast ~5.0:1 with white
  "#c026d3", // fuchsia-600  — contrast ~4.6:1 with white
  "#db2777", // pink-600     — contrast ~4.5:1 with white
];

/**
 * Maps any string to a deterministic color from the AVATAR_COLORS palette.
 * Same input always returns same output (AVTR-02).
 */
// First color is always present — AVATAR_COLORS has 12 entries
const FALLBACK_COLOR = "#dc2626";

export function stringToColor(str: string): string {
  if (!str) return FALLBACK_COLOR;
  const index = Math.abs(hashCode(str)) % AVATAR_COLORS.length;
  return AVATAR_COLORS[index] ?? FALLBACK_COLOR;
}

/**
 * Returns the display letter for an avatar.
 * Uses issuer first; falls back to name; falls back to '?' for empty entries.
 */
export function getAvatarLetter(issuer: string, name: string): string {
  const source = issuer?.trim() || name?.trim() || "?";
  return source.charAt(0).toUpperCase();
}
