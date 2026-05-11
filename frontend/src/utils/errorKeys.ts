// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import type { ParseKeys } from "i18next";

/**
 * Maps known Go sentinel error strings to i18n translation keys.
 * Go methods document their error string contracts in comments (app.go).
 * If a string is not a known sentinel, returns the provided fallback key.
 */
export function goErrorToKey<F extends ParseKeys>(
  raw: string,
  fallbackKey: F
): ParseKeys {
  if (raw.includes("qr: no QR code found")) return "screenQR.noQRFound";
  if (raw.includes("file is empty")) return "errors.fileEmpty";
  if (raw.includes("file too large")) return "errors.fileTooLarge";
  if (raw.includes("not a backup file")) return "errors.notABackupFile";
  switch (raw) {
    case "incorrect password":
      return "errors.incorrectPassword";
    case "password required":
      return "errors.passwordRequired";
    case "no supported backup format found":
      return "errors.noParserFound";
    default:
      return fallbackKey;
  }
}
