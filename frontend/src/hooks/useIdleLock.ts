// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useEffect, useRef } from "react";
import { LockVault } from "../../wailsjs/go/main/App";

// Map from setting string to milliseconds — module-level constant, stable across renders
const TIMEOUT_MS: Record<string, number> = {
  "1": 60000,
  "5": 300000,
  "15": 900000,
  "30": 1800000,
};

/**
 * useIdleLock — starts an idle auto-lock timer while the vault is unlocked.
 *
 * @param vaultUnlocked - Must be `vaultStatus.enabled && vaultStatus.unlocked`.
 *   Do NOT pass just `unlocked` — plain vaults (enabled=false) must NOT trigger
 *   the idle timer because LockVault() is a no-op for them.
 * @param timeoutSetting - Raw string from GetSetting('auto_lock_timeout').
 *   One of '1', '5', '15', '30', or 'never' (default).
 *   Any unrecognised value (including '') is treated as 'never'.
 */
export function useIdleLock(
  vaultUnlocked: boolean,
  timeoutSetting: string
): void {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    // IDLE-04: no timer runs while vault is locked
    if (!vaultUnlocked) {
      if (timerRef.current !== null) clearTimeout(timerRef.current);
      timerRef.current = null;
      return;
    }

    // IDLE-03: 'never' (and any unknown value) means no timer
    const ms = TIMEOUT_MS[timeoutSetting];
    if (ms === undefined) {
      return;
    }

    // reset() restarts the countdown from now
    function reset() {
      if (timerRef.current !== null) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => {
        LockVault().catch(() => {});
      }, ms);
    }

    // Start the timer immediately on mount or when dependencies change
    reset();

    // Activity on any of these events resets the countdown (IDLE-04)
    document.addEventListener("mousemove", reset, { passive: true });
    document.addEventListener("keydown", reset, { passive: true });
    document.addEventListener("wheel", reset, { passive: true });

    return () => {
      document.removeEventListener("mousemove", reset);
      document.removeEventListener("keydown", reset);
      document.removeEventListener("wheel", reset);
      if (timerRef.current !== null) clearTimeout(timerRef.current);
      timerRef.current = null;
    };
  }, [vaultUnlocked, timeoutSetting]);
}
