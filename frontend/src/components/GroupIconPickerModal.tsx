// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { GROUP_ICON_CATEGORIES, findGroupIcon } from "../data/groupIcons";
import { BASE_INPUT_CLASS } from "../utils/inputClass";
import { Modal } from "./Modal";
import { GroupIcon } from "./GroupIcon";

interface GroupIconPickerModalProps {
  currentIcon: string;
  onSelect: (slug: string) => void;
  onRemove: () => void;
  onClose: () => void;
}

export function GroupIconPickerModal({
  currentIcon,
  onSelect,
  onRemove,
  onClose,
}: GroupIconPickerModalProps) {
  const { t } = useTranslation();
  const [query, setQuery] = useState("");
  const [confirmRemove, setConfirmRemove] = useState(false);

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") {
      e.stopPropagation();
      onClose();
    }
  }

  const filteredIcons = useMemo(() => {
    const queryLower = query.toLowerCase().trim();
    if (!queryLower) return null;
    // Flatten all category slugs and filter
    const allSlugs = GROUP_ICON_CATEGORIES.flatMap((cat) => cat.slugs);
    return allSlugs.filter((slug) => {
      const def = findGroupIcon(slug);
      if (!def) return false;
      return (
        slug.includes(queryLower) ||
        def.label.toLowerCase().includes(queryLower)
      );
    });
  }, [query]);

  return (
    <Modal
      onClose={onClose}
      zIndex="z-[60]"
      width="max-w-md"
      containerClassName="!p-4 max-h-[80vh] flex flex-col"
    >
      <div onKeyDown={handleKeyDown}>
        <h3 className="text-token-heading font-semibold text-[rgb(var(--color-text-primary))] mb-3">
          {t("groupIconPicker.title")}
        </h3>

        {/* Search input */}
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t("groupIconPicker.searchPlaceholder")}
          className={BASE_INPUT_CLASS + " mb-3"}
          autoFocus
          autoComplete="off"
        />

        {/* Scrollable icon grid area */}
        <div className="overflow-y-auto flex-1" style={{ maxHeight: "360px" }}>
          {filteredIcons !== null ? (
            /* Flat filtered grid when search query is active */
            filteredIcons.length === 0 ? (
              <p className="text-token-body text-[rgb(var(--color-text-muted))] text-center py-8">
                {t("groupIconPicker.noMatches", { query })}
              </p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {filteredIcons.map((slug) => {
                  const def = findGroupIcon(slug);
                  return (
                    <button
                      key={slug}
                      type="button"
                      title={def?.label ?? slug}
                      onClick={() => onSelect(slug)}
                      className={
                        "w-14 h-14 rounded-lg flex items-center justify-center transition-all hover:bg-[rgb(var(--color-surface-hover))]" +
                        (slug === currentIcon
                          ? " ring-2 ring-primary bg-[rgb(var(--color-surface))]"
                          : "")
                      }
                    >
                      <GroupIcon icon={slug} size={30} />
                    </button>
                  );
                })}
              </div>
            )
          ) : (
            /* Category-grouped grid when search is empty */
            GROUP_ICON_CATEGORIES.map((cat) => (
              <div key={cat.label} className="mb-3">
                <p className="text-token-caption text-[rgb(var(--color-text-muted))] mb-1.5">
                  {cat.label}
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {cat.slugs.map((slug) => {
                    const def = findGroupIcon(slug);
                    return (
                      <button
                        key={slug}
                        type="button"
                        title={def?.label ?? slug}
                        onClick={() => onSelect(slug)}
                        className={
                          "w-14 h-14 rounded-lg flex items-center justify-center transition-all hover:bg-[rgb(var(--color-surface-hover))]" +
                          (slug === currentIcon
                            ? " ring-2 ring-primary bg-[rgb(var(--color-surface))]"
                            : "")
                        }
                      >
                        <GroupIcon icon={slug} size={30} />
                      </button>
                    );
                  })}
                </div>
              </div>
            ))
          )}
        </div>

        {/* Remove icon button / confirmation */}
        {currentIcon &&
          (confirmRemove ? (
            <div className="flex items-center justify-between mt-3">
              <span className="text-token-caption text-[rgb(var(--color-text-secondary))]">
                {t("groupIconPicker.revertConfirm")}
              </span>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setConfirmRemove(false)}
                  className="text-token-caption text-[rgb(var(--color-text-muted))] hover:text-[rgb(var(--color-text-primary))] transition-colors"
                >
                  {t("groupIconPicker.cancel")}
                </button>
                <button
                  type="button"
                  onClick={onRemove}
                  className="text-token-caption text-[rgb(var(--color-error))] hover:text-red-400 transition-colors font-medium"
                >
                  {t("groupIconPicker.remove")}
                </button>
              </div>
            </div>
          ) : (
            <button
              type="button"
              onClick={() => setConfirmRemove(true)}
              className="text-token-caption text-[rgb(var(--color-error))] hover:text-red-400 mt-3 transition-colors"
            >
              {t("groupIconPicker.removeIcon")}
            </button>
          ))}
      </div>
    </Modal>
  );
}
