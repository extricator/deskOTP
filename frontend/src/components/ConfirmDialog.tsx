// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { Modal } from "./Modal";

interface ConfirmDialogProps {
  title: string;
  message: string;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({
  title,
  message,
  confirmLabel,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const { t } = useTranslation();
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    containerRef.current?.focus();
  }, []);

  return (
    <Modal onClose={onCancel}>
      <div
        ref={containerRef}
        tabIndex={-1}
        onKeyDown={(e) => {
          if (e.key === "Escape") onCancel();
        }}
        className="outline-none"
      >
        <h2 className="text-token-heading font-semibold text-[rgb(var(--color-text-primary))] mb-2">
          {title}
        </h2>
        <p className="text-token-body text-[rgb(var(--color-text-secondary))] mb-4 whitespace-pre-line">
          {message}
        </p>
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 rounded-lg text-token-body text-[rgb(var(--color-text-secondary))] hover:bg-[rgb(var(--color-card-bg))]"
          >
            {t("confirmDialog.cancel")}
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className="px-4 py-2 rounded-lg text-token-body text-white bg-red-600 hover:bg-red-700"
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </Modal>
  );
}
