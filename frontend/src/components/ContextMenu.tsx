// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";

interface Props {
  x: number;
  y: number;
  onCopy: () => void;
  onEdit: () => void;
  onDelete: () => void;
  onClose: () => void;
}

const MENU_WIDTH = 180;
const MENU_HEIGHT = 128;

export function ContextMenu({
  x,
  y,
  onCopy,
  onEdit,
  onDelete,
  onClose,
}: Props) {
  const { t } = useTranslation();
  const menuRef = useRef<HTMLDivElement>(null);

  // Dismiss on outside click and Escape key
  useEffect(() => {
    const handleMouseDown = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
    };
    document.addEventListener("mousedown", handleMouseDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handleMouseDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [onClose]);

  const clampedX = Math.min(x, window.innerWidth - MENU_WIDTH - 8);
  const clampedY = Math.min(y, window.innerHeight - MENU_HEIGHT - 8);

  const baseClass =
    "w-full text-left px-4 py-2 text-token-body hover:bg-[rgb(var(--color-surface-hover))]";

  return (
    <div
      ref={menuRef}
      className="fixed z-40 bg-[rgb(var(--color-surface-lowest))] rounded-xl overflow-hidden ghost-border"
      style={{ boxShadow: '0px 8px 24px rgba(25, 28, 30, 0.12), 0px 2px 8px rgba(25, 28, 30, 0.08)', left: clampedX, top: clampedY, width: MENU_WIDTH }}
    >
      <button
        className={`${baseClass} text-[rgb(var(--color-text-primary))]`}
        onClick={onCopy}
      >
        {t("contextMenu.copy")}
      </button>
      <button
        className={`${baseClass} text-[rgb(var(--color-text-primary))]`}
        onClick={onEdit}
      >
        {t("contextMenu.edit")}
      </button>
      <button
        className={`${baseClass} text-[rgb(var(--color-error))]`}
        onClick={onDelete}
      >
        {t("contextMenu.delete")}
      </button>
    </div>
  );
}
