// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useCallback, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { EventsOn } from "../../wailsjs/runtime/runtime";

/** useToast manages ephemeral toast state: undo toast, lock message, and clipboard cleared notification. */
export function useToast(): {
  undoToast: { name: string } | null;
  lockMessage: string | null;
  clipboardCleared: boolean;
  showLockMessage: () => void;
  showUndoToast: (name: string) => void;
  dismissUndoToast: () => void;
} {
  const { t } = useTranslation();
  const [undoToast, setUndoToast] = useState<{ name: string } | null>(null);
  const [lockMessage, setLockMessage] = useState<string | null>(null);
  const [clipboardCleared, setClipboardCleared] = useState(false);

  // Subscribe to clipboard:cleared event — show ephemeral toast (CLIP-04)
  useEffect(() => {
    const unlisten = EventsOn("clipboard:cleared", () => {
      setClipboardCleared(true);
      setTimeout(() => setClipboardCleared(false), 2000);
    });
    return unlisten;
  }, []);

  const showLockMessage = useCallback(() => {
    setLockMessage(t("nav.lockDisabledMessage"));
    setTimeout(() => setLockMessage(null), 3000);
  }, [t]);

  const showUndoToast = useCallback((name: string) => {
    setUndoToast({ name });
  }, []);

  const dismissUndoToast = useCallback(() => {
    setUndoToast(null);
  }, []);

  return {
    undoToast,
    lockMessage,
    clipboardCleared,
    showLockMessage,
    showUndoToast,
    dismissUndoToast,
  };
}
