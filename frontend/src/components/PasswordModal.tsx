// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useRef, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { BASE_INPUT_CLASS } from "../utils/inputClass";
import { Modal } from "./Modal";

interface PasswordModalProps {
  onSubmit: (password: string) => void; // called with the entered password
  onCancel: () => void; // called when user cancels
  error: string | null; // "Incorrect password" or null
  decrypting: boolean; // true while ImportFile is in flight
}

export function PasswordModal({
  onSubmit,
  onCancel,
  error,
  decrypting,
}: PasswordModalProps) {
  const { t } = useTranslation();
  const [password, setPassword] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  // Auto-focus password input when modal opens
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!password.trim() || decrypting) return;
    onSubmit(password);
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") {
      onCancel();
    }
  }

  return (
    <Modal onClose={onCancel}>
      <div onKeyDown={handleKeyDown}>
        <h2 className="text-token-heading font-semibold text-[rgb(var(--color-text-primary))] mb-1">
          {t("passwordModal.title")}
        </h2>
        <p className="text-token-body text-[rgb(var(--color-text-secondary))] mb-4">
          {t("passwordModal.description")}
        </p>
        <form onSubmit={handleSubmit}>
          <input
            ref={inputRef}
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={t("passwordModal.placeholder")}
            disabled={decrypting}
            className={`${BASE_INPUT_CLASS} disabled:opacity-50 mb-3`}
            autoComplete="off"
          />
          {error && (
            <p className="text-token-body text-[rgb(var(--color-error))] mb-3">
              {error}
            </p>
          )}
          <div className="flex gap-2 justify-end">
            <button
              type="button"
              onClick={onCancel}
              disabled={decrypting}
              className="px-4 py-2 rounded-lg text-[rgb(var(--color-text-secondary))] hover:text-[rgb(var(--color-text-primary))]
                         hover:bg-[rgb(var(--color-surface-hover))] transition-colors disabled:opacity-50"
            >
              {t("passwordModal.cancel")}
            </button>
            <button
              type="submit"
              disabled={decrypting || !password.trim()}
              className="px-4 py-2 rounded-lg bg-primary hover:bg-primary-container
                         text-on-primary font-medium disabled:opacity-50"
            >
              {decrypting
                ? t("passwordModal.unlocking")
                : t("passwordModal.unlock")}
            </button>
          </div>
        </form>
      </div>
    </Modal>
  );
}
