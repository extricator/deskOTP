// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useMemo, useRef } from "react";
import { useTranslation } from "react-i18next";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ICON_SLUGS } from "../data/iconSlugs";
import { BASE_INPUT_CLASS } from "../utils/inputClass";
import { Modal } from "./Modal";

interface IconPickerModalProps {
  currentIcon: string;
  issuer?: string;
  onSelect: (slug: string) => void;
  onRemove: () => void;
  onClose: () => void;
}

const COLS = 6;
const ROW_HEIGHT = 72; // 64px icon + 8px gap/padding

function matchIcons(issuer: string, slugs: readonly string[]): string[] {
  const normalized = issuer.toLowerCase().trim();
  if (!normalized) return [];
  // Exact match
  const exact = slugs.filter((s) => s === normalized);
  if (exact.length > 0) return exact;
  // Substring: slugs (>= 4 chars) contained in the issuer, or issuer contained in slug
  return slugs.filter(
    (s) => s.length >= 4 && (normalized.includes(s) || s.includes(normalized))
  );
}

export function IconPickerModal({
  currentIcon,
  issuer,
  onSelect,
  onRemove,
  onClose,
}: IconPickerModalProps) {
  const { t } = useTranslation();
  const [query, setQuery] = useState("");
  const [confirmRemove, setConfirmRemove] = useState(false);

  const parentRef = useRef<HTMLDivElement>(null);

  const filtered = useMemo(
    () =>
      query.trim() === ""
        ? ICON_SLUGS
        : ICON_SLUGS.filter((s) => s.includes(query.toLowerCase().trim())),
    [query]
  );

  const suggested = useMemo(
    () => (issuer && query.trim() === "" ? matchIcons(issuer, ICON_SLUGS) : []),
    [issuer, query]
  );

  const rows = useMemo(() => {
    const result: string[][] = [];
    for (let i = 0; i < filtered.length; i += COLS) {
      result.push(filtered.slice(i, i + COLS));
    }
    return result;
  }, [filtered]);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 3,
  });

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") {
      e.stopPropagation();
      onClose();
    }
  }

  const inputClass = BASE_INPUT_CLASS;

  return (
    <Modal
      onClose={onClose}
      zIndex="z-[60]"
      width="max-w-lg"
      containerClassName="!p-4 max-h-[80vh] flex flex-col"
    >
      <div onKeyDown={handleKeyDown}>
        <h3 className="text-token-heading font-semibold text-[rgb(var(--color-text-primary))] mb-3">
          {t("iconPicker.title")}
        </h3>

        {/* Search input */}
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t("iconPicker.searchPlaceholder")}
          className={inputClass + " mb-3"}
          autoFocus
          autoComplete="off"
        />

        {/* Suggested section — shown only when issuer exists and search is empty */}
        {suggested.length > 0 && (
          <div className="mb-2">
            <p className="text-token-caption text-[rgb(var(--color-text-muted))] mb-1">
              {t("iconPicker.suggested")}
            </p>
            <div className="flex flex-wrap gap-1">
              {suggested.map((slug) => (
                <button
                  key={slug}
                  type="button"
                  title={slug}
                  onClick={() => onSelect(slug)}
                  className={
                    "p-1.5 rounded hover:bg-[rgb(var(--color-surface-hover))] transition-colors" +
                    (slug === currentIcon ? " ring-2 ring-blue-500" : "")
                  }
                >
                  <img
                    src={`/icons/${slug}.svg`}
                    alt={slug}
                    loading="lazy"
                    className="w-16 h-16 object-contain"
                  />
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Virtualized icon grid */}
        <div
          ref={parentRef}
          className="overflow-y-auto flex-1"
          style={{ maxHeight: "360px" }}
        >
          {filtered.length === 0 ? (
            <p className="text-token-body text-[rgb(var(--color-text-muted))] text-center py-8">
              {t("iconPicker.noMatches", { query })}
            </p>
          ) : (
            <div
              style={{
                height: `${virtualizer.getTotalSize()}px`,
                position: "relative",
                width: "100%",
              }}
            >
              {virtualizer.getVirtualItems().map((virtualRow) => (
                <div
                  key={virtualRow.index}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    height: `${virtualRow.size}px`,
                    transform: `translateY(${virtualRow.start}px)`,
                  }}
                  className="flex gap-1 px-1"
                >
                  {(rows[virtualRow.index] ?? []).map((slug) => (
                    <button
                      key={slug}
                      type="button"
                      title={slug}
                      onClick={() => onSelect(slug)}
                      className={
                        "p-1.5 rounded hover:bg-[rgb(var(--color-surface-hover))] transition-colors" +
                        (slug === currentIcon ? " ring-2 ring-blue-500" : "")
                      }
                    >
                      <img
                        src={`/icons/${slug}.svg`}
                        alt={slug}
                        loading="lazy"
                        className="w-16 h-16 object-contain"
                      />
                    </button>
                  ))}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Remove icon button / confirmation */}
        {currentIcon &&
          (confirmRemove ? (
            <div className="flex items-center justify-between mt-3">
              <span className="text-token-caption text-[rgb(var(--color-text-secondary))]">
                {t("iconPicker.revertConfirm")}
              </span>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setConfirmRemove(false)}
                  className="text-token-caption text-[rgb(var(--color-text-muted))] hover:text-[rgb(var(--color-text-primary))] transition-colors"
                >
                  {t("iconPicker.cancel")}
                </button>
                <button
                  type="button"
                  onClick={onRemove}
                  className="text-token-caption text-[rgb(var(--color-error))] hover:text-red-400 transition-colors font-medium"
                >
                  {t("iconPicker.remove")}
                </button>
              </div>
            </div>
          ) : (
            <button
              type="button"
              onClick={() => setConfirmRemove(true)}
              className="text-token-caption text-[rgb(var(--color-error))] hover:text-red-400 mt-3 transition-colors"
            >
              {t("iconPicker.removeIcon")}
            </button>
          ))}
      </div>
    </Modal>
  );
}
