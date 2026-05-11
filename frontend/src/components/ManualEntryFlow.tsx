// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { main } from "../../wailsjs/go/models";
import { ReviewForm } from "./ReviewForm";
import { GroupPicker } from "./GroupPicker";
import { BASE_INPUT_CLASS } from "../utils/inputClass";
import { Modal } from "./Modal";

type ManualFlowState =
  | { stage: "entering" }
  | { stage: "reviewing"; preview: main.URIPreview };

interface ManualEntryFlowProps {
  onSaved: () => void;
  onCancel: () => void;
}

const inputClass = BASE_INPUT_CLASS;

function isValidBase32(value: string): boolean {
  const normalized = value.replace(/\s/g, "").toUpperCase();
  return normalized.length > 0 && /^[A-Z2-7]+$/.test(normalized);
}

export function ManualEntryFlow({ onSaved, onCancel }: ManualEntryFlowProps) {
  const { t } = useTranslation();
  const [flow, setFlow] = useState<ManualFlowState>({ stage: "entering" });

  // Basic fields
  const [issuer, setIssuer] = useState("");
  const [name, setName] = useState("");
  const [secret, setSecret] = useState("");
  const [secretError, setSecretError] = useState<string | null>(null);
  const [group, setGroup] = useState("");

  // Advanced fields
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [entryType, setEntryType] = useState("totp");
  const [algo, setAlgo] = useState("SHA1");
  const [period, setPeriod] = useState(30);
  const [digits, setDigits] = useState(6);
  const [counter, setCounter] = useState(0);

  // Escape key closes the flow when not reviewing (ReviewForm handles its own escape)
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape" && flow.stage !== "reviewing") {
        onCancel();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [flow.stage, onCancel]);

  function handleClose() {
    if (flow.stage === "entering") {
      onCancel();
    }
  }

  function handleSecretBlur() {
    if (secret.trim().length === 0) {
      setSecretError(null);
      return;
    }
    const normalized = secret.replace(/\s/g, "").toUpperCase();
    if (!/^[A-Z2-7]+$/.test(normalized)) {
      setSecretError(t("manualEntry.secretInvalidBase32"));
    } else {
      setSecretError(null);
    }
  }

  function handleSecretChange(value: string) {
    setSecret(value);
    setSecretError(null);
  }

  function handleTypeChange(value: string) {
    setEntryType(value);
    if (value === "steam") {
      setAlgo("SHA1");
      setPeriod(30);
      setDigits(5);
    }
  }

  const canProceed =
    issuer.trim().length > 0 &&
    name.trim().length > 0 &&
    secret.trim().length > 0 &&
    secretError === null &&
    isValidBase32(secret);

  function handleProceed() {
    const normalizedSecret = secret.replace(/\s/g, "").toUpperCase();
    const effectiveAlgo = entryType === "steam" ? "SHA1" : algo;
    const effectivePeriod = entryType === "steam" ? 30 : period;
    const effectiveDigits = entryType === "steam" ? 5 : digits;

    const preview = main.URIPreview.createFrom({
      type: entryType,
      issuer: issuer.trim(),
      name: name.trim(),
      secret: normalizedSecret,
      algo: effectiveAlgo,
      digits: effectiveDigits,
      period: effectivePeriod,
      counter: entryType === "hotp" ? counter : 0,
    });
    setFlow({ stage: "reviewing", preview });
  }

  const disabledClass = "opacity-50 cursor-not-allowed";

  const isReviewing = flow.stage === "reviewing";

  return (
    <Modal
      onClose={handleClose}
      width="max-w-md"
      containerClassName="max-h-[90vh] overflow-y-auto"
      noContainer={isReviewing}
    >
      {isReviewing && flow.stage === "reviewing" ? (
        <ReviewForm
          initialPreview={flow.preview}
          initialGroup={group}
          onSaved={onSaved}
          onCancel={() => setFlow({ stage: "entering" })}
        />
      ) : (
        <>
          <h2 className="text-token-heading font-semibold text-[rgb(var(--color-text-primary))] mb-4">
            {t("manualEntry.title")}
          </h2>

          {/* Basic fields */}
          <div className="space-y-3 mb-4">
            {/* Issuer */}
            <div>
              <label className="block text-token-body text-[rgb(var(--color-text-secondary))] mb-1">
                {t("manualEntry.labelIssuer")}
              </label>
              <input
                type="text"
                value={issuer}
                onChange={(e) => setIssuer(e.target.value)}
                placeholder={t("manualEntry.placeholderIssuer")}
                className={inputClass}
                autoComplete="off"
              />
            </div>

            {/* Account name */}
            <div>
              <label className="block text-token-body text-[rgb(var(--color-text-secondary))] mb-1">
                {t("manualEntry.labelName")}
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={t("manualEntry.placeholderName")}
                className={inputClass}
                autoComplete="off"
              />
            </div>

            {/* Secret key */}
            <div>
              <label className="block text-token-body text-[rgb(var(--color-text-secondary))] mb-1">
                {t("manualEntry.labelSecret")}
              </label>
              <input
                type="text"
                value={secret}
                onChange={(e) => handleSecretChange(e.target.value)}
                onBlur={handleSecretBlur}
                placeholder={t("manualEntry.placeholderSecret")}
                className={`${inputClass}${secretError ? " border-[rgb(var(--color-error))]" : ""}`}
                autoComplete="off"
                autoCapitalize="characters"
                spellCheck={false}
              />
              {secretError ? (
                <p className="text-token-caption text-[rgb(var(--color-error))] mt-1">
                  {secretError}
                </p>
              ) : (
                <p className="text-token-caption text-[rgb(var(--color-text-muted))] mt-1">
                  {t("manualEntry.secretHint")}
                </p>
              )}
            </div>

            {/* Group */}
            <div>
              <label className="block text-token-body text-[rgb(var(--color-text-secondary))] mb-1">
                {t("manualEntry.labelGroup")}
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
              ? t("manualEntry.hideAdvanced")
              : t("manualEntry.showAdvanced")}
          </button>

          {/* Advanced section */}
          {showAdvanced && (
            <div className="mb-4 p-3 rounded-lg bg-[rgb(var(--color-input-bg))] border border-[rgb(var(--color-border))] space-y-3">
              <div className="grid grid-cols-2 gap-x-4 gap-y-3">
                {/* Type */}
                <div>
                  <label className="block text-token-caption text-[rgb(var(--color-text-muted))] mb-1">
                    {t("manualEntry.labelType")}
                  </label>
                  <select
                    value={entryType}
                    onChange={(e) => handleTypeChange(e.target.value)}
                    className={inputClass}
                  >
                    <option value="totp">totp</option>
                    <option value="hotp">hotp</option>
                    <option value="steam">steam</option>
                  </select>
                </div>

                {/* Algorithm */}
                <div>
                  <label className="block text-token-caption text-[rgb(var(--color-text-muted))] mb-1">
                    {t("manualEntry.labelAlgorithm")}
                  </label>
                  <select
                    value={algo}
                    onChange={(e) => setAlgo(e.target.value)}
                    disabled={entryType === "steam"}
                    className={`${inputClass}${entryType === "steam" ? ` ${disabledClass}` : ""}`}
                  >
                    <option value="SHA1">SHA1</option>
                    <option value="SHA256">SHA256</option>
                    <option value="SHA512">SHA512</option>
                  </select>
                </div>

                {/* Period */}
                <div>
                  <label className="block text-token-caption text-[rgb(var(--color-text-muted))] mb-1">
                    {t("manualEntry.labelPeriod")}
                  </label>
                  <input
                    type="number"
                    min={1}
                    value={period}
                    onChange={(e) =>
                      setPeriod(parseInt(e.target.value, 10) || 30)
                    }
                    disabled={entryType === "steam"}
                    className={`${inputClass}${entryType === "steam" ? ` ${disabledClass}` : ""}`}
                  />
                </div>

                {/* Digits */}
                <div>
                  <label className="block text-token-caption text-[rgb(var(--color-text-muted))] mb-1">
                    {t("manualEntry.labelDigits")}
                  </label>
                  <select
                    value={digits}
                    onChange={(e) => setDigits(parseInt(e.target.value, 10))}
                    disabled={entryType === "steam"}
                    className={`${inputClass}${entryType === "steam" ? ` ${disabledClass}` : ""}`}
                  >
                    <option value={5}>5</option>
                    <option value={6}>6</option>
                    <option value={8}>8</option>
                  </select>
                </div>

                {/* Counter — only shown when HOTP */}
                {entryType === "hotp" && (
                  <div>
                    <label className="block text-token-caption text-[rgb(var(--color-text-muted))] mb-1">
                      {t("manualEntry.labelCounter")}
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
            </div>
          )}

          {/* Buttons */}
          <div className="flex gap-2 justify-end">
            <button
              type="button"
              onClick={onCancel}
              className="px-4 py-2 rounded-lg text-[rgb(var(--color-text-secondary))] hover:text-[rgb(var(--color-text-primary))] hover:bg-[rgb(var(--color-surface-hover))] transition-colors"
            >
              {t("manualEntry.cancel")}
            </button>
            <button
              type="button"
              onClick={handleProceed}
              disabled={!canProceed}
              className="px-4 py-2 rounded-lg bg-gradient-to-br from-primary to-primary-container text-on-primary hover:opacity-90 font-medium disabled:opacity-50"
            >
              {t("manualEntry.proceed")}
            </button>
          </div>
        </>
      )}
    </Modal>
  );
}
