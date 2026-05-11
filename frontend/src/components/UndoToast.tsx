// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useEffect, useLayoutEffect, useRef } from "react";
import { useTranslation } from "react-i18next";

interface UndoToastProps {
  message: string;
  onUndo: () => void;
  onDismiss: () => void;
  duration?: number;
}

export function UndoToast({
  message,
  onUndo,
  onDismiss,
  duration = 5000,
}: UndoToastProps) {
  const { t } = useTranslation();
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onDismissRef = useRef(onDismiss);

  // Keep the ref in sync with the latest onDismiss via useLayoutEffect (not during render)
  useLayoutEffect(() => {
    onDismissRef.current = onDismiss;
  });

  useEffect(() => {
    timeoutRef.current = setTimeout(() => onDismissRef.current(), duration);
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, [duration]);

  function handleUndo() {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    onUndo();
  }

  return (
    <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 bg-[rgb(var(--color-surface))] rounded-xl shadow-card px-4 py-3 flex items-center gap-3">
      <span className="text-token-body text-[rgb(var(--color-text-primary))]">
        {message}
      </span>
      <button
        type="button"
        onClick={handleUndo}
        className="text-token-body font-medium text-primary hover:text-primary hover:underline cursor-pointer"
      >
        {t("deleteAccount.undo")}
      </button>
    </div>
  );
}
