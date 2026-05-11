// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import React, { useEffect, useRef } from "react";
import { createPortal } from "react-dom";

const FOCUSABLE_SELECTOR =
  "a[href], button:not([disabled]), input:not([disabled]), " +
  "select:not([disabled]), textarea:not([disabled]), " +
  '[tabindex]:not([tabindex="-1"])';

function getFocusable(container: HTMLElement | null): HTMLElement[] {
  if (!container) return [];
  return Array.from(
    container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)
  );
}

interface ModalProps {
  onClose: () => void;
  children: React.ReactNode;
  width?: string;
  zIndex?: string;
  containerClassName?: string;
  /** When true, renders children directly inside the backdrop without the inner container div. */
  noContainer?: boolean;
  /** Override the backdrop background class. Defaults to "bg-black/60". */
  backdropClassName?: string;
  /** When true, blurs the app content behind the modal overlay. */
  blurContent?: boolean;
}

export function Modal({
  onClose,
  children,
  width = "max-w-sm",
  zIndex = "z-50",
  containerClassName,
  noContainer = false,
  backdropClassName,
  blurContent = false,
}: ModalProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const previousFocus = useRef<Element | null>(null);

  useEffect(() => {
    previousFocus.current = document.activeElement;
    const focusable = getFocusable(containerRef.current);
    const firstEl = focusable[0];
    if (firstEl !== undefined) {
      firstEl.focus();
    }
    return () => {
      (previousFocus.current as HTMLElement | null)?.focus();
    };
  }, []);

  useEffect(() => {
    if (!blurContent) return;
    const appContent = document.getElementById("app-content");
    if (appContent) {
      appContent.classList.add("dialog-blur");
    }
    return () => {
      if (appContent) {
        appContent.classList.remove("dialog-blur");
      }
    };
  }, [blurContent]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key === "Tab") {
        const focusable = getFocusable(containerRef.current);
        if (focusable.length === 0) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (first === undefined || last === undefined) return;
        if (e.shiftKey) {
          if (document.activeElement === first) {
            e.preventDefault();
            last.focus();
          }
        } else {
          if (document.activeElement === last) {
            e.preventDefault();
            first.focus();
          }
        }
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  function handleBackdropClick(e: React.MouseEvent) {
    if (e.target === e.currentTarget) onClose();
  }

  const modal = (
    <div
      className={`fixed inset-0 ${zIndex} flex items-center justify-center ${backdropClassName ?? "bg-black/60"}`}
      onClick={handleBackdropClick}
    >
      {noContainer ? (
        <div ref={containerRef} role="dialog" aria-modal="true">
          {children}
        </div>
      ) : (
        <div
          ref={containerRef}
          role="dialog"
          aria-modal="true"
          className={`bg-[rgb(var(--color-modal-bg))] rounded-2xl shadow-card p-6 w-full ${width} mx-4${containerClassName ? ` ${containerClassName}` : ""}`}
        >
          {children}
        </div>
      )}
    </div>
  );

  // Portal to document.body when blurContent is true so the modal
  // lives outside the blurred #app-content DOM subtree.
  if (blurContent) {
    return createPortal(modal, document.body);
  }

  return modal;
}
