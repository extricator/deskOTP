// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import {
  GetEntryDetails,
  UpdateEntry,
} from "../../wailsjs/go/main/App";
import { entries } from "../../wailsjs/go/models";
import { AccountAvatar } from "./AccountAvatar";
import { IconPickerModal } from "./IconPickerModal";
import { goErrorToKey } from "../utils/errorKeys";
import { extractErrorMessage } from "../utils/extractErrorMessage";
import { BASE_INPUT_CLASS } from "../utils/inputClass";
import { Modal } from "./Modal";
import { GroupPicker } from "./GroupPicker";

interface EditDialogProps {
  entryId: string;
  onClose: () => void;
  onSaved: () => void;
}

export function EditDialog({ entryId, onClose, onSaved }: EditDialogProps) {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Form fields
  const [name, setName] = useState("");
  const [issuer, setIssuer] = useState("");
  const [group, setGroup] = useState("");
  const [note, setNote] = useState("");
  const [entryType, setEntryType] = useState("");
  const [algo, setAlgo] = useState("");
  const [period, setPeriod] = useState(30);
  const [digits, setDigits] = useState(6);
  const [changingSecret, setChangingSecret] = useState(false);
  const [newSecret, setNewSecret] = useState("");

  // Original values for change detection
  const [original, setOriginal] = useState({
    name: "",
    issuer: "",
    group: "",
    note: "",
    entryType: "",
    algo: "",
    period: 30,
    digits: 6,
  });

  // Icon state
  const [icon, setIcon] = useState("");
  const [originalIcon, setOriginalIcon] = useState("");
  const [showIconPicker, setShowIconPicker] = useState(false);

  // Read-only details
  const [details, setDetails] = useState<entries.EntryDetails | null>(null);

  const nameRef = useRef<HTMLInputElement>(null);

  // Global Escape handler — works regardless of focus state
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape" && !showIconPicker) {
        onClose();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [showIconPicker, onClose]);

  // Load entry details and groups on mount
  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const entry = await GetEntryDetails(entryId);
        if (cancelled) return;
        setDetails(entry);
        setName(entry.name);
        setIssuer(entry.issuer);
        setGroup(entry.group);
        setNote(entry.note);
        setEntryType(entry.type);
        setAlgo(entry.algo);
        setPeriod(entry.period);
        setDigits(entry.digits);
        setIcon(entry.icon ?? "");
        setOriginalIcon(entry.icon ?? "");
        setOriginal({
          name: entry.name,
          issuer: entry.issuer,
          group: entry.group,
          note: entry.note,
          entryType: entry.type,
          algo: entry.algo,
          period: entry.period,
          digits: entry.digits,
        });
        setLoading(false);
        // Focus name input after loading
        setTimeout(() => nameRef.current?.focus(), 0);
      } catch (e: unknown) {
        if (cancelled) return;
        const raw = extractErrorMessage(e);
        setLoadError(t(goErrorToKey(raw, "editDialog.loadError")));
        setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [entryId, t]);

  const hasChanges =
    name.trim() !== original.name ||
    issuer.trim() !== original.issuer ||
    group.trim() !== original.group ||
    note.trim() !== original.note ||
    entryType !== original.entryType ||
    algo !== original.algo ||
    period !== original.period ||
    digits !== original.digits ||
    (changingSecret && newSecret.trim().length > 0) ||
    icon !== originalIcon;

  const canSave = name.trim().length > 0 && hasChanges && !saving;

  async function handleSave() {
    setSaveError(null);
    setSaving(true);
    try {
      await UpdateEntry(
        entryId,
        name.trim(),
        issuer.trim(),
        group.trim(),
        note.trim(),
        entryType,
        algo,
        period,
        digits,
        changingSecret ? newSecret.trim() : "",
        icon
      );
      onSaved();
    } catch (e: unknown) {
      const raw = extractErrorMessage(e);
      setSaveError(t(goErrorToKey(raw, "editDialog.saveError")));
      setSaving(false);
    }
  }

  const inputClass = BASE_INPUT_CLASS;

  return (
    <Modal
      onClose={onClose}
      width="max-w-md"
      containerClassName="max-h-[90vh] overflow-y-auto"
    >
      <h2 className="text-token-heading font-semibold text-[rgb(var(--color-text-primary))] mb-4">
        {t("editDialog.title")}
      </h2>

      {loading ? (
        <p className="text-token-body text-[rgb(var(--color-text-secondary))]">
          {t("editDialog.loading")}
        </p>
      ) : loadError ? (
        <>
          <p className="text-token-body text-[rgb(var(--color-error))] mb-4">
            {loadError}
          </p>
          <div className="flex justify-end">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-gradient-to-br from-primary to-primary-container text-on-primary hover:opacity-90 font-medium"
            >
              {t("editDialog.close")}
            </button>
          </div>
        </>
      ) : (
        <>
          {/* Clickable avatar -- opens icon picker */}
          <button
            type="button"
            onClick={() => setShowIconPicker(true)}
            className="relative group mx-auto mb-4 block rounded-full"
            title={t("editDialog.changeIconTitle")}
          >
            <AccountAvatar
              icon={icon || undefined}
              issuer={issuer || details?.issuer || ""}
              name={name || details?.name || ""}
            />
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
                {t("editDialog.labelName")}
              </label>
              <input
                ref={nameRef}
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={t("editDialog.placeholderName")}
                className={inputClass}
                autoComplete="off"
              />
            </div>
            <div>
              <label className="block text-token-body text-[rgb(var(--color-text-secondary))] mb-1">
                {t("editDialog.labelIssuer")}
              </label>
              <input
                type="text"
                value={issuer}
                onChange={(e) => setIssuer(e.target.value)}
                placeholder={t("editDialog.placeholderIssuer")}
                className={inputClass}
                autoComplete="off"
              />
            </div>
            <div>
              <label className="block text-token-body text-[rgb(var(--color-text-secondary))] mb-1">
                {t("editDialog.labelGroup")}
              </label>
              <GroupPicker value={group} onChange={setGroup} />
            </div>
            <div>
              <label className="block text-token-body text-[rgb(var(--color-text-secondary))] mb-1">
                {t("editDialog.labelNote")}
              </label>
              <textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder={t("editDialog.placeholderNote")}
                rows={3}
                className={inputClass + " resize-none"}
                autoComplete="off"
              />
            </div>
          </div>

          {/* Advanced toggle */}
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="text-token-body text-primary hover:text-primary mb-3"
          >
            {showAdvanced
              ? t("editDialog.hideAdvanced")
              : t("editDialog.showAdvanced")}
          </button>

          {showAdvanced && details && (
            <div className="mb-4 p-3 rounded-lg bg-[rgb(var(--color-input-bg))] border border-[rgb(var(--color-border))] space-y-3">
              <div className="grid grid-cols-2 gap-x-4 gap-y-3">
                <div>
                  <label className="block text-token-caption text-[rgb(var(--color-text-muted))] mb-1">
                    {t("editDialog.labelType")}
                  </label>
                  <select
                    value={entryType}
                    onChange={(e) => {
                      const newType = e.target.value;
                      setEntryType(newType);
                      if (newType === "steam") {
                        setDigits(5);
                        setAlgo("SHA1");
                        setPeriod(30);
                      } else if (entryType === "steam") {
                        setDigits(6);
                      }
                    }}
                    className={inputClass}
                  >
                    <option value="totp">totp</option>
                    <option value="hotp">hotp</option>
                    <option value="steam">steam</option>
                  </select>
                </div>
                <div>
                  <label className="block text-token-caption text-[rgb(var(--color-text-muted))] mb-1">
                    {t("editDialog.labelAlgorithm")}
                  </label>
                  <select
                    value={algo}
                    onChange={(e) => setAlgo(e.target.value)}
                    className={inputClass}
                    disabled={entryType === "steam"}
                  >
                    <option value="SHA1">SHA1</option>
                    <option value="SHA256">SHA256</option>
                    <option value="SHA512">SHA512</option>
                  </select>
                </div>
                <div>
                  <label className="block text-token-caption text-[rgb(var(--color-text-muted))] mb-1">
                    {t("editDialog.labelPeriod")}
                  </label>
                  <input
                    type="number"
                    min={1}
                    value={period}
                    onChange={(e) =>
                      setPeriod(parseInt(e.target.value, 10) || 30)
                    }
                    className={inputClass}
                    disabled={entryType === "steam"}
                  />
                </div>
                <div>
                  <label className="block text-token-caption text-[rgb(var(--color-text-muted))] mb-1">
                    {t("editDialog.labelDigits")}
                  </label>
                  <select
                    value={digits}
                    onChange={(e) => setDigits(parseInt(e.target.value, 10))}
                    className={inputClass}
                    disabled={entryType === "steam"}
                  >
                    {entryType === "steam" ? (
                      <option value={5}>5</option>
                    ) : (
                      <>
                        <option value={6}>6</option>
                        <option value={7}>7</option>
                        <option value={8}>8</option>
                      </>
                    )}
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-token-caption text-[rgb(var(--color-text-muted))] mb-1">
                  {t("editDialog.labelSecret")}
                </label>
                <p className="text-token-body text-[rgb(var(--color-text-primary))] font-mono mb-1">
                  {details.secret}
                </p>
                {changingSecret ? (
                  <div className="flex gap-2 items-center">
                    <input
                      type="text"
                      value={newSecret}
                      onChange={(e) => setNewSecret(e.target.value)}
                      placeholder={t("editDialog.placeholderSecret")}
                      className={inputClass}
                      autoComplete="off"
                    />
                    <button
                      type="button"
                      onClick={() => {
                        setChangingSecret(false);
                        setNewSecret("");
                      }}
                      className="text-token-caption text-[rgb(var(--color-text-muted))] hover:text-[rgb(var(--color-text-primary))] whitespace-nowrap"
                    >
                      {t("editDialog.cancelSecretChange")}
                    </button>
                  </div>
                ) : (
                  <button
                    type="button"
                    onClick={() => setChangingSecret(true)}
                    className="text-token-caption text-primary hover:text-primary"
                  >
                    {t("editDialog.changeSecret")}
                  </button>
                )}
              </div>
              <div>
                <span className="text-token-caption text-[rgb(var(--color-text-muted))]">
                  {t("editDialog.labelUsageCount")}
                </span>
                <p className="text-token-body text-[rgb(var(--color-text-primary))]">
                  {details.usageCount}
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
              onClick={onClose}
              disabled={saving}
              className="px-4 py-2 rounded-lg text-[rgb(var(--color-text-secondary))] hover:text-[rgb(var(--color-text-primary))] hover:bg-[rgb(var(--color-surface-hover))] transition-colors disabled:opacity-50"
            >
              {t("editDialog.cancel")}
            </button>
            <button
              type="button"
              onClick={handleSave}
              disabled={!canSave}
              className="px-4 py-2 rounded-lg bg-gradient-to-br from-primary to-primary-container text-on-primary hover:opacity-90 font-medium disabled:opacity-50"
            >
              {saving ? t("editDialog.saving") : t("editDialog.save")}
            </button>
          </div>
        </>
      )}
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
    </Modal>
  );
}
