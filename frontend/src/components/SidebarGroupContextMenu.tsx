// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";

interface Props {
  x: number;
  y: number;
  groupName: string;
  isFirst: boolean;
  isLast: boolean;
  onRename: () => void;
  onMoveUp: () => void;
  onMoveDown: () => void;
  onDelete: () => void;
  onClose: () => void;
}

const MENU_WIDTH = 180;
const MENU_HEIGHT = 160;
const PADDING = 8;

export function SidebarGroupContextMenu({
  x,
  y,
  groupName: _groupName,
  isFirst,
  isLast,
  onRename,
  onMoveUp,
  onMoveDown,
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

  const clampedX = Math.min(x, window.innerWidth - MENU_WIDTH - PADDING);
  const clampedY = Math.min(y, window.innerHeight - MENU_HEIGHT - PADDING);

  const baseClass =
    "w-full text-left px-4 py-2 text-token-body hover:bg-[rgb(var(--color-surface-hover))] disabled:opacity-40 disabled:cursor-not-allowed";

  return (
    <div
      ref={menuRef}
      className="fixed z-50 bg-[rgb(var(--color-surface-lowest))] rounded-xl overflow-hidden ghost-border"
      style={{
        boxShadow:
          "0px 8px 24px rgba(25, 28, 30, 0.12), 0px 2px 8px rgba(25, 28, 30, 0.08)",
        left: clampedX,
        top: clampedY,
        width: MENU_WIDTH,
      }}
    >
      <button
        className={`${baseClass} text-[rgb(var(--color-text-primary))]`}
        onClick={() => {
          onRename();
          onClose();
        }}
      >
        {t("sidebar.contextMenu.rename")}
      </button>
      <button
        className={`${baseClass} text-[rgb(var(--color-text-primary))]`}
        disabled={isFirst}
        onClick={() => {
          onMoveUp();
          onClose();
        }}
      >
        {t("sidebar.contextMenu.moveUp")}
      </button>
      <button
        className={`${baseClass} text-[rgb(var(--color-text-primary))]`}
        disabled={isLast}
        onClick={() => {
          onMoveDown();
          onClose();
        }}
      >
        {t("sidebar.contextMenu.moveDown")}
      </button>
      <button
        className={`${baseClass} text-[rgb(var(--color-error))]`}
        onClick={() => {
          onDelete();
          onClose();
        }}
      >
        {t("sidebar.contextMenu.delete")}
      </button>
    </div>
  );
}
