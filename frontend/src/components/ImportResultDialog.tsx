// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useTranslation } from "react-i18next";
import { Modal } from "./Modal";

interface ImportResultDialogProps {
  added: number;
  skipped: number;
  onClose: () => void;
  showEncryptionNotice?: boolean;
  onSetupEncryption?: () => void;
  format?: string;
}

function composeImportMessage(
  t: ReturnType<typeof useTranslation>["t"],
  added: number,
  skipped: number,
  format?: string
): string {
  if (added > 0 && skipped > 0) {
    return format
      ? t("importResult.addedAndSkippedFormat", {
          added,
          skipped,
          formatName: format,
        })
      : t("importResult.addedAndSkipped", { added, skipped });
  }
  if (added > 0) {
    return format
      ? t("importResult.addedOnlyFormat", { added, formatName: format })
      : t("importResult.addedOnly", { added });
  }
  if (skipped > 0) return t("importResult.allExisted", { skipped });
  return format
    ? t("importResult.noTokensFound", { formatName: format })
    : t("importResult.noneFound");
}

export function ImportResultDialog({
  added,
  skipped,
  onClose,
  showEncryptionNotice,
  onSetupEncryption,
  format,
}: ImportResultDialogProps) {
  const { t } = useTranslation();
  const message = composeImportMessage(t, added, skipped, format);

  return (
    <Modal onClose={onClose} width="max-w-xs">
      <div
        className="text-center"
        tabIndex={-1}
        onKeyDown={(e) => {
          if (e.key === "Escape") onClose();
        }}
      >
        <h2 className="text-token-heading font-semibold text-[rgb(var(--color-text-primary))] mb-1">
          {t("importResult.title")}
        </h2>
        <p className="text-token-body text-[rgb(var(--color-success))] mb-4">
          {message}
        </p>

        {showEncryptionNotice && (
          <div className="border-t border-[rgb(var(--color-border))] mt-3 pt-3 mb-4">
            <p className="text-token-body text-[rgb(var(--color-text-secondary))]">
              {"\uD83D\uDD12"} {t("importResult.encryptionNotice")}
            </p>
            <button
              type="button"
              onClick={onSetupEncryption}
              className="text-token-body text-primary hover:text-primary cursor-pointer underline mt-1"
            >
              {t("importResult.setupEncryption")}
            </button>
          </div>
        )}

        <button
          onClick={onClose}
          autoFocus
          className="px-4 py-2 rounded-lg bg-primary hover:bg-primary-container
                     text-on-primary font-medium"
        >
          {t("common.ok")}
        </button>
      </div>
    </Modal>
  );
}
