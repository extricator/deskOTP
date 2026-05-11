// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useCallback, useEffect } from "react";
import { GetVaultStatus, LockVault } from "../../wailsjs/go/main/App";
import { EventsOn } from "../../wailsjs/runtime/runtime";

/** useVaultState manages vault status, handles vault:locked events, and exposes vault control handlers. */
export function useVaultState(resetReady: () => void): {
  vaultStatus: { enabled: boolean; unlocked: boolean } | null;
  setVaultStatus: React.Dispatch<
    React.SetStateAction<{ enabled: boolean; unlocked: boolean } | null>
  >;
  handleLock: () => Promise<void>;
  handlePasswordSet: () => void;
  handlePasswordRemoved: () => void;
} {
  const [vaultStatus, setVaultStatus] = useState<{
    enabled: boolean;
    unlocked: boolean;
  } | null>(null);

  // Load initial vault status on mount
  useEffect(() => {
    GetVaultStatus().then(setVaultStatus);
  }, []);

  // Subscribe to vault:locked event — single source of truth for all lock state transitions (LMCH-03)
  useEffect(() => {
    const unlisten = EventsOn("vault:locked", () => {
      setVaultStatus({ enabled: true, unlocked: false });
      resetReady();
    });
    return unlisten;
  }, [resetReady]);

  const handleLock = useCallback(async () => {
    try {
      await LockVault();
      // vault:locked event will arrive and trigger state update via EventsOn handler
    } catch (e: unknown) {
      console.error("LockVault failed:", e instanceof Error ? e.message : e);
    }
  }, []);

  const handlePasswordSet = useCallback(() => {
    setVaultStatus({ enabled: true, unlocked: true });
  }, []);

  const handlePasswordRemoved = useCallback(() => {
    setVaultStatus({ enabled: false, unlocked: false });
  }, []);

  return {
    vaultStatus,
    setVaultStatus,
    handleLock,
    handlePasswordSet,
    handlePasswordRemoved,
  };
}
