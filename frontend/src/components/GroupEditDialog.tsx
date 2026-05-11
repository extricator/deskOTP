// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { CreateGroup, RenameGroup } from "../../wailsjs/go/main/App";
import { extractErrorMessage } from "../utils/extractErrorMessage";
import { BASE_INPUT_CLASS } from "../utils/inputClass";
import { Modal } from "./Modal";
import { GroupIcon } from "./GroupIcon";
import { GroupIconPickerModal } from "./GroupIconPickerModal";

interface GroupEditDialogProps {
  mode: "create" | "rename";
  initialName?: string;
  initialIcon?: string; // current icon slug for rename mode
  groups: string[]; // names only, for duplicate check
  onGroupsChanged: (info: { oldName?: string; newName: string }) => void;
  onClose: () => void;
}

export function GroupEditDialog({
  mode,
  initialName,
  initialIcon,
  groups,
  onGroupsChanged,
  onClose,
}: GroupEditDialogProps) {
  const { t } = useTranslation();
  const [inputValue, setInputValue] = useState(initialName ?? "");
  const [selectedIcon, setSelectedIcon] = useState(initialIcon ?? "");
  const [pickerOpen, setPickerOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const title =
    mode === "create"
      ? t("groupEditDialog.titleCreate")
      : t("groupEditDialog.titleRename");

  function handleIconSelect(slug: string) {
    setSelectedIcon(slug);
    setPickerOpen(false);
  }

  function handleIconRemove() {
    setSelectedIcon("");
    setPickerOpen(false);
  }

  async function handleSubmit() {
    const trimmed = inputValue.trim();

    if (!trimmed) {
      setError(t("sidebar.contextMenu.newGroupPlaceholder"));
      return;
    }

    if (mode === "rename" && trimmed === initialName && selectedIcon === (initialIcon ?? "")) {
      onClose();
      return;
    }

    if (groups.some((g) => g.toLowerCase() === trimmed.toLowerCase()) && (mode === "create" || trimmed !== initialName)) {
      setError(t("groupPicker.duplicateError"));
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      if (mode === "create") {
        await CreateGroup(trimmed, selectedIcon);
        onGroupsChanged({ newName: trimmed });
      } else {
        await RenameGroup(initialName ?? "", trimmed, selectedIcon);
        onGroupsChanged({ oldName: initialName, newName: trimmed });
      }
      onClose();
    } catch (e) {
      setError(extractErrorMessage(e) || t("groupPicker.createError"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <Modal onClose={onClose} width="max-w-sm">
        <h2 className="text-base font-semibold text-[rgb(var(--color-text-primary))] mb-4">
          {title}
        </h2>

        {/* Compact row: clickable icon avatar (left) + name input (right) */}
        <div className="flex items-center gap-3 mb-4">
          {/* Clickable icon avatar — sole trigger for picker */}
          <button
            type="button"
            onClick={() => setPickerOpen(true)}
            className="flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center
                       bg-[rgb(var(--color-surface-hover))]
                       hover:ring-2 hover:ring-primary hover:scale-105
                       transition-all"
            aria-label={t("groupEditDialog.chooseIcon")}
            title={t("groupEditDialog.chooseIcon")}
          >
            <GroupIcon icon={selectedIcon} size={24} />
          </button>

          {/* Name input — flex-1 fills remaining width */}
          <input
            type="text"
            value={inputValue}
            onChange={(e) => { setInputValue(e.target.value); setError(null); }}
            onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); handleSubmit(); } }}
            placeholder={t("sidebar.contextMenu.newGroupPlaceholder")}
            autoFocus
            autoComplete="off"
            className={BASE_INPUT_CLASS + " flex-1"}
            disabled={submitting}
          />
        </div>

        {error && (
          <p className="text-token-caption text-[rgb(var(--color-error))] mt-1 mb-2">
            {error}
          </p>
        )}

        <div className="flex justify-end gap-2 mt-4">
          <button
            type="button"
            onClick={onClose}
            disabled={submitting}
            className="px-4 py-2 rounded-lg text-[rgb(var(--color-text-secondary))] hover:text-[rgb(var(--color-text-primary))] hover:bg-[rgb(var(--color-surface-hover))] transition-colors disabled:opacity-50"
          >
            {t("confirmDialog.cancel")}
          </button>
          <button
            type="button"
            onClick={handleSubmit}
            disabled={submitting}
            className="px-4 py-2 rounded-lg bg-gradient-to-br from-primary to-primary-container text-on-primary hover:opacity-90 font-medium disabled:opacity-50"
          >
            {title}
          </button>
        </div>
      </Modal>

      {pickerOpen && (
        <GroupIconPickerModal
          currentIcon={selectedIcon}
          onSelect={handleIconSelect}
          onRemove={handleIconRemove}
          onClose={() => setPickerOpen(false)}
        />
      )}
    </>
  );
}
