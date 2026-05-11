// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { AddEntry, GetIconSuggestion } from "../../wailsjs/go/main/App";
import { main } from "../../wailsjs/go/models";
import { AccountAvatar } from "./AccountAvatar";
import { GroupPicker } from "./GroupPicker";
import { IconPickerModal } from "./IconPickerModal";
import { ConfirmDialog } from "./ConfirmDialog";
import { goErrorToKey } from "../utils/errorKeys";
import { extractErrorMessage } from "../utils/extractErrorMessage";
import { BASE_INPUT_CLASS } from "../utils/inputClass";

interface ReviewFormProps {
  initialPreview: main.URIPreview;
  initialGroup?: string;
  onSaved: () => void;
  onCancel: () => void;
}

export function ReviewForm({
  initialPreview,
  initialGroup,
  onSaved,
  onCancel,
}: ReviewFormProps) {
  const { t } = useTranslation();

  // Primary editable fields
  const [issuer, setIssuer] = useState(initialPreview.issuer);
  const [name, setName] = useState(initialPreview.name);
  const [icon, setIcon] = useState("");
  const [group, setGroup] = useState(initialGroup ?? "");

  // Advanced editable fields (initialized from preview)
  const [entryType, setEntryType] = useState(initialPreview.type || "totp");
  const [algo, setAlgo] = useState(initialPreview.algo || "SHA1");
  const [period, setPeriod] = useState(initialPreview.period || 30);
  const [digits, setDigits] = useState(initialPreview.digits || 6);
  const [counter, setCounter] = useState(initialPreview.counter || 0);

  // UI state
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showIconPicker, setShowIconPicker] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [showDuplicateConfirm, setShowDuplicateConfirm] = useState(false);

  const inputClass = BASE_INPUT_CLASS;

  // Auto-suggest icon from issuer on mount
  useEffect(() => {
    if (!initialPreview.issuer) return;
    GetIconSuggestion(initialPreview.issuer)
      .then((slug) => {
        if (slug) setIcon(slug);
      })
      .catch(() => {});
  }, [initialPreview.issuer]);

  // Escape key closes the form (unless a sub-modal is open)
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape" && !showIconPicker && !showDuplicateConfirm) {
        e.stopPropagation();
        onCancel();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [showIconPicker, showDuplicateConfirm, onCancel]);

  async function doSave(force: boolean) {
    setSaving(true);
    setSaveError(null);
    try {
      await AddEntry(
        name.trim(),
        issuer.trim(),
        initialPreview.secret,
        entryType,
        algo,
        period,
        digits,
        counter,
        icon,
        group,
        force
      );
      onSaved();
    } catch (e: unknown) {
      const raw = extractErrorMessage(e);
      if (raw.startsWith("duplicate:")) {
        setShowDuplicateConfirm(true);
      } else {
        setSaveError(t(goErrorToKey(raw, "reviewForm.saveError")));
      }
      setSaving(false);
    }
  }

  function handleSave() {
    doSave(false);
  }

  function handleDuplicateConfirm() {
    setShowDuplicateConfirm(false);
    doSave(true);
  }

  function handleDuplicateCancel() {
    setShowDuplicateConfirm(false);
  }

  return (
    <div className="bg-[rgb(var(--color-modal-bg))] border border-[rgb(var(--color-border))] rounded-xl shadow-2xl p-6 w-full max-w-md mx-4 max-h-[90vh] overflow-y-auto">
      <h2 className="text-token-heading font-semibold text-[rgb(var(--color-text-primary))] mb-4">
        {t("reviewForm.title")}
      </h2>

      {/* Clickable avatar -- opens icon picker */}
      <button
        type="button"
        onClick={() => setShowIconPicker(true)}
        className="relative group mx-auto mb-4 block rounded-full"
        title={t("reviewForm.changeIconTitle")}
      >
        <AccountAvatar icon={icon || undefined} issuer={issuer} name={name} />
        <div className="absolute inset-0 rounded-full bg-black/40 opacity-0 group-hover:opacity-100 flex items-center justify-center transition-opacity">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            className="w-5 h-5 text-white"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"
            />
          </svg>
        </div>
      </button>

      {/* Basic fields */}
      <div className="space-y-3 mb-4">
        <div>
          <label className="block text-token-body text-[rgb(var(--color-text-secondary))] mb-1">
            {t("reviewForm.labelIssuer")}
          </label>
          <input
            type="text"
            value={issuer}
            onChange={(e) => setIssuer(e.target.value)}
            placeholder={t("reviewForm.placeholderIssuer")}
            className={inputClass}
            autoComplete="off"
          />
        </div>
        <div>
          <label className="block text-token-body text-[rgb(var(--color-text-secondary))] mb-1">
            {t("reviewForm.labelName")}
          </label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t("reviewForm.placeholderName")}
            className={inputClass}
            autoComplete="off"
          />
        </div>
        <div>
          <label className="block text-token-body text-[rgb(var(--color-text-secondary))] mb-1">
            {t("reviewForm.labelGroup")}
          </label>
          <GroupPicker value={group} onChange={setGroup} />
        </div>
      </div>

      {/* Advanced toggle */}
      <button
        type="button"
        onClick={() => setShowAdvanced(!showAdvanced)}
        className="text-token-body text-primary hover:text-primary mb-3"
      >
        {showAdvanced
          ? t("reviewForm.hideAdvanced")
          : t("reviewForm.showAdvanced")}
      </button>

      {showAdvanced && (
        <div className="mb-4 p-3 rounded-lg bg-[rgb(var(--color-input-bg))] border border-[rgb(var(--color-border))] space-y-3">
          <div className="grid grid-cols-2 gap-x-4 gap-y-3">
            <div>
              <label className="block text-token-caption text-[rgb(var(--color-text-muted))] mb-1">
                {t("reviewForm.labelType")}
              </label>
              <select
                value={entryType}
                onChange={(e) => setEntryType(e.target.value)}
                className={inputClass}
              >
                <option value="totp">totp</option>
                <option value="hotp">hotp</option>
                <option value="steam">steam</option>
              </select>
            </div>
            <div>
              <label className="block text-token-caption text-[rgb(var(--color-text-muted))] mb-1">
                {t("reviewForm.labelAlgorithm")}
              </label>
              <select
                value={algo}
                onChange={(e) => setAlgo(e.target.value)}
                className={inputClass}
              >
                <option value="SHA1">SHA1</option>
                <option value="SHA256">SHA256</option>
                <option value="SHA512">SHA512</option>
              </select>
            </div>
            <div>
              <label className="block text-token-caption text-[rgb(var(--color-text-muted))] mb-1">
                {t("reviewForm.labelPeriod")}
              </label>
              <input
                type="number"
                min={1}
                value={period}
                onChange={(e) => setPeriod(parseInt(e.target.value, 10) || 30)}
                className={inputClass}
              />
            </div>
            <div>
              <label className="block text-token-caption text-[rgb(var(--color-text-muted))] mb-1">
                {t("reviewForm.labelDigits")}
              </label>
              <select
                value={digits}
                onChange={(e) => setDigits(parseInt(e.target.value, 10))}
                className={inputClass}
              >
                <option value={5}>5</option>
                <option value={6}>6</option>
                <option value={8}>8</option>
              </select>
            </div>
            {entryType === "hotp" && (
              <div>
                <label className="block text-token-caption text-[rgb(var(--color-text-muted))] mb-1">
                  {t("reviewForm.labelCounter")}
                </label>
                <input
                  type="number"
                  min={0}
                  value={counter}
                  onChange={(e) =>
                    setCounter(parseInt(e.target.value, 10) || 0)
                  }
                  className={inputClass}
                />
              </div>
            )}
          </div>
          <div>
            <label className="block text-token-caption text-[rgb(var(--color-text-muted))] mb-1">
              {t("reviewForm.labelSecret")}
            </label>
            <p className="text-token-body text-[rgb(var(--color-text-primary))] font-mono break-all">
              {initialPreview.secret}
            </p>
          </div>
        </div>
      )}

      {/* Save error */}
      {saveError && (
        <p className="text-token-body text-[rgb(var(--color-error))] mb-3">
          {saveError}
        </p>
      )}

      {/* Buttons */}
      <div className="flex gap-2 justify-end">
        <button
          type="button"
          onClick={onCancel}
          disabled={saving}
          className="px-4 py-2 rounded-lg text-[rgb(var(--color-text-secondary))] hover:text-[rgb(var(--color-text-primary))] hover:bg-[rgb(var(--color-surface-hover))] transition-colors disabled:opacity-50"
        >
          {t("reviewForm.cancel")}
        </button>
        <button
          type="button"
          onClick={handleSave}
          disabled={saving}
          className="px-4 py-2 rounded-lg bg-gradient-to-br from-primary to-primary-container text-on-primary hover:opacity-90 font-medium disabled:opacity-50"
        >
          {saving ? t("reviewForm.saving") : t("reviewForm.save")}
        </button>
      </div>

      {/* Icon picker modal */}
      {showIconPicker && (
        <IconPickerModal
          currentIcon={icon}
          issuer={issuer}
          onSelect={(slug) => {
            setIcon(slug);
            setShowIconPicker(false);
          }}
          onRemove={() => {
            setIcon("");
            setShowIconPicker(false);
          }}
          onClose={() => setShowIconPicker(false)}
        />
      )}

      {/* Duplicate confirm dialog */}
      {showDuplicateConfirm && (
        <ConfirmDialog
          title={t("reviewForm.duplicateTitle")}
          message={t("reviewForm.duplicateMessage", {
            issuer: issuer.trim(),
            name: name.trim(),
          })}
          confirmLabel={t("reviewForm.duplicateConfirm")}
          onConfirm={handleDuplicateConfirm}
          onCancel={handleDuplicateCancel}
        />
      )}
    </div>
  );
}
