// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useImperativeHandle, forwardRef, Ref } from "react";
import { useTranslation } from "react-i18next";
import { PickFile, ImportFile } from "../../wailsjs/go/main/App";
import { PasswordModal } from "./PasswordModal";
import { goErrorToKey } from "../utils/errorKeys";
import { extractErrorMessage } from "../utils/extractErrorMessage";
import { ImportCounts } from "../types";
import { SUPPORTED_FORMATS } from "../data/supportedFormats";
import { Modal } from "./Modal";

export interface ImportAreaHandle {
  /** Returns true if a file was picked, false if the user cancelled. */
  triggerImport: () => Promise<boolean>;
}

interface Props {
  showInstructions?: boolean; // true for empty state, false for toolbar
  compact?: boolean; // true for nav bar icon button, false for blue pill
  onResult: (counts: ImportCounts) => void;
}

export const ImportArea = forwardRef(function ImportArea({
  showInstructions = false,
  compact = false,
  onResult,
}: Props, ref: Ref<ImportAreaHandle>) {
  const { t } = useTranslation();
  const [error, setError] = useState<string | null>(null);
  const [showFormatHelp, setShowFormatHelp] = useState(false);
  const [showFormats, setShowFormats] = useState(false);
  const [importing, setImporting] = useState(false);
  const [pendingPath, setPendingPath] = useState<string | null>(null);
  const [decrypting, setDecrypting] = useState(false);
  const [passwordError, setPasswordError] = useState<string | null>(null);

  useImperativeHandle(ref, () => ({ triggerImport: handleImport }));

  async function handleImport(): Promise<boolean> {
    setImporting(true);
    setError(null);
    setShowFormatHelp(false);
    setPendingPath(null);
    setPasswordError(null);
    try {
      const path = await PickFile();
      if (!path) return false; // user cancelled file dialog

      try {
        // Try importing without password first (works for plain files)
        const importResult = await ImportFile(path, "");
        // Success -- plain file imported, no modal needed
        if (importResult) {
          onResult({
            added: importResult.added,
            skipped: importResult.skipped,
            format: importResult.format,
          });
        }
      } catch (importErr: unknown) {
        // Wails rejects with a plain string, not an Error object
        const msg: string = extractErrorMessage(importErr);
        if (msg === "password required") {
          // Encrypted file detected -- store path and show password modal
          setPendingPath(path);
        } else {
          const key = goErrorToKey(msg, "importArea.importFailed");
          // If the error mapped to a specific key, show translated text.
          // If it fell through to the generic fallback, append the raw
          // message so the user can see what actually went wrong.
          const translated = t(key);
          setError(
            key === "importArea.importFailed" && msg
              ? `${translated}: ${msg}`
              : translated
          );
          setShowFormatHelp(key === "errors.noParserFound");
        }
      }
      return true;
    } catch (e: unknown) {
      const rawMsg = extractErrorMessage(e);
      const errKey = goErrorToKey(rawMsg, "importArea.openFileFailed");
      const translated = t(errKey);
      setError(
        errKey === "importArea.openFileFailed" && rawMsg
          ? `${translated}: ${rawMsg}`
          : translated
      );
      return true; // file was picked, but open failed
    } finally {
      setImporting(false);
    }
  }

  async function handlePasswordSubmit(password: string) {
    if (!pendingPath) return;
    setDecrypting(true);
    setPasswordError(null);
    try {
      const importResult = await ImportFile(pendingPath, password);
      // Success -- close the modal and show result
      setDecrypting(false);
      setPendingPath(null);
      if (importResult) {
        onResult({
          added: importResult.added,
          skipped: importResult.skipped,
          format: importResult.format,
        });
      }
    } catch (e: unknown) {
      setDecrypting(false);
      // Wails rejects with a plain string, not an Error object
      const msg: string = extractErrorMessage(e);
      if (msg === "incorrect password") {
        setPasswordError(t("importArea.incorrectPassword"));
      } else {
        setPasswordError(t(goErrorToKey(msg, "importArea.decryptionFailed")));
      }
    }
  }

  function handlePasswordCancel() {
    setPendingPath(null);
    setPasswordError(null);
    setDecrypting(false);
  }

  function dismissError() {
    setError(null);
    setShowFormatHelp(false);
  }

  const errorModal = error ? (
    <Modal onClose={dismissError} width="max-w-xs">
      <div className="text-center">
        <p className="text-token-body text-[rgb(var(--color-text-primary))] mb-4">
          {error}
        </p>
        {showFormatHelp && (
          <div className="mt-3 pt-3 text-left">
            <p className="text-token-caption font-semibold text-[rgb(var(--color-text-secondary))] mb-2">
              {t("formatHelp.heading")}
            </p>
            <ul className="space-y-1 max-h-48 overflow-y-auto">
              {SUPPORTED_FORMATS.map((f) => (
                <li
                  key={f.name}
                  className="text-token-caption text-[rgb(var(--color-text-secondary))] flex justify-between gap-2"
                >
                  <span>{f.name}</span>
                  <span className="text-[rgb(var(--color-text-muted))]">
                    {f.extensions}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
        <button
          onClick={dismissError}
          className="px-4 py-2 rounded-lg text-token-body bg-gradient-to-br from-primary to-primary-container text-on-primary hover:opacity-90"
        >
          {t("common.dismiss")}
        </button>
      </div>
    </Modal>
  ) : null;

  if (compact) {
    return (
      <>
        <button
          onClick={handleImport}
          disabled={importing}
          aria-label={t("nav.importBackup")}
          title={t("nav.importBackup")}
          className="p-2 text-primary hover:bg-surface rounded-lg transition-all active:scale-95 disabled:opacity-50 cursor-pointer"
        >
          {importing ? (
            <svg
              aria-hidden="true"
              className="animate-spin w-5 h-5"
              viewBox="0 0 24 24"
              fill="none"
            >
              <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="4"
              />
              <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
              />
            </svg>
          ) : (
            <svg
              aria-hidden="true"
              xmlns="http://www.w3.org/2000/svg"
              className="w-density-icon h-density-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <polyline points="16 16 12 12 8 16" />
              <line x1="12" y1="12" x2="12" y2="21" />
              <path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3" />
            </svg>
          )}
        </button>
        {errorModal}
        {pendingPath && (
          <PasswordModal
            onSubmit={handlePasswordSubmit}
            onCancel={handlePasswordCancel}
            error={passwordError}
            decrypting={decrypting}
          />
        )}
      </>
    );
  }

  return (
    <div className="flex flex-col items-center gap-3">
      {showInstructions && (
        <>
          <div className="text-token-heading text-[rgb(var(--color-text-primary))]">
            {t("tokensPage.noAccounts")}
          </div>
          <div className="text-token-body text-[rgb(var(--color-text-secondary))]">
            {t("importArea.hint")}
          </div>
        </>
      )}
      <button
        onClick={handleImport}
        disabled={importing}
        className="px-6 py-2 rounded-lg bg-gradient-to-br from-primary to-primary-container disabled:opacity-50
                   text-on-primary hover:opacity-90 font-medium"
      >
        {importing ? t("importArea.importing") : t("importArea.importButton")}
      </button>
      <button
        onClick={() => setShowFormats((f) => !f)}
        className="text-token-caption text-[rgb(var(--color-text-muted))] hover:text-[rgb(var(--color-text-secondary))] transition-colors"
      >
        {showFormats
          ? t("formatHelp.hideFormats")
          : t("formatHelp.showFormats")}
      </button>
      {showFormats && (
        <div className="w-full max-w-xs text-left">
          <ul className="space-y-1 max-h-48 overflow-y-auto">
            {SUPPORTED_FORMATS.map((f) => (
              <li
                key={f.name}
                className="text-token-caption text-[rgb(var(--color-text-secondary))] flex justify-between gap-2"
              >
                <span>{f.name}</span>
                <span className="text-[rgb(var(--color-text-muted))]">
                  {f.extensions}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {errorModal}
      {pendingPath && (
        <PasswordModal
          onSubmit={handlePasswordSubmit}
          onCancel={handlePasswordCancel}
          error={passwordError}
          decrypting={decrypting}
        />
      )}
    </div>
  );
});
