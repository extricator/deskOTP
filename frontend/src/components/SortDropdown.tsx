// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useRef, useEffect, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { SortOption, SortDirection } from "../types";

interface Props {
  value: SortOption;
  direction: SortDirection;
  onChange: (option: SortOption, direction: SortDirection) => void;
}

function defaultDirection(opt: SortOption): SortDirection {
  return opt === "date-added" || opt === "usage-count" ? "desc" : "asc";
}

export function SortDropdown({ value, direction, onChange }: Props) {
  const { t } = useTranslation();
  const [isOpen, setIsOpen] = useState(false);
  const [pendingDirs, setPendingDirs] = useState<
    Partial<Record<SortOption, SortDirection>>
  >({});
  const containerRef = useRef<HTMLDivElement>(null);

  const SORT_OPTIONS = useMemo(
    () => [
      {
        value: "issuer" as SortOption,
        label: t("sort.issuer"),
        ascLabel: t("sort.ascending"),
        descLabel: t("sort.descending"),
      },
      {
        value: "name" as SortOption,
        label: t("sort.name"),
        ascLabel: t("sort.ascending"),
        descLabel: t("sort.descending"),
      },
      {
        value: "date-added" as SortOption,
        label: t("sort.dateAdded"),
        ascLabel: t("sort.oldest"),
        descLabel: t("sort.newest"),
      },
      {
        value: "usage-count" as SortOption,
        label: t("sort.usageCount"),
        ascLabel: t("sort.least"),
        descLabel: t("sort.most"),
      },
    ],
    [t]
  );

  const current = SORT_OPTIONS.find((o) => o.value === value);
  const currentLabel = current
    ? `${current.label} (${direction === "asc" ? current.ascLabel : current.descLabel})`
    : t("sort.label");

  // Click-outside dismissal (same pattern as ContextMenu)
  useEffect(() => {
    if (!isOpen) return;
    const handleMouseDown = (e: MouseEvent) => {
      if (
        containerRef.current &&
        !containerRef.current.contains(e.target as Node)
      ) {
        setIsOpen(false);
        setPendingDirs({});
      }
    };
    document.addEventListener("mousedown", handleMouseDown);
    return () => document.removeEventListener("mousedown", handleMouseDown);
  }, [isOpen]);

  // Escape key dismissal
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        setIsOpen(false);
        setPendingDirs({});
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [isOpen]);

  return (
    <div ref={containerRef} className="relative">
      {/* Toggle button */}
      <button
        onClick={() => setIsOpen((prev) => !prev)}
        className="flex items-center gap-2 px-4 py-2.5 bg-surface-container-high hover:bg-surface-container-highest text-sm font-semibold rounded-lg transition-all border border-transparent hover:border-outline-variant/20"
      >
        {/* Sort icon */}
        <svg
          xmlns="http://www.w3.org/2000/svg"
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <line x1="8" y1="6" x2="21" y2="6" />
          <line x1="8" y1="12" x2="21" y2="12" />
          <line x1="8" y1="18" x2="21" y2="18" />
          <polyline points="3 6 4 5 5 6" />
          <polyline points="3 18 4 19 5 18" />
        </svg>

        <span className="text-token-body">{currentLabel}</span>

        {/* Chevron — rotates when open */}
        <svg
          xmlns="http://www.w3.org/2000/svg"
          width="14"
          height="14"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
          className={`transition-transform ${isOpen ? "rotate-180" : ""}`}
        >
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>

      {/* Dropdown menu */}
      {isOpen && (
        <div
          className="absolute right-0 top-full mt-1 min-w-[200px] z-10
                        bg-[rgb(var(--color-surface))]
                        rounded-xl shadow-card py-1"
        >
          {SORT_OPTIONS.map((option) => {
            const isActive = option.value === value;
            const dir = isActive
              ? direction
              : (pendingDirs[option.value] ?? defaultDirection(option.value));
            return (
              <div
                key={option.value}
                className={`flex items-center text-token-body
                           hover:bg-[rgb(var(--color-surface-hover))] transition-colors
                           ${
                             isActive
                               ? "text-[rgb(var(--color-text-primary))] font-medium"
                               : "text-[rgb(var(--color-text-secondary))]"
                           }`}
              >
                {/* Label area — clicking applies the sort */}
                <button
                  className="flex-1 flex items-center gap-2 px-4 py-2 text-left"
                  onClick={() => {
                    onChange(option.value, dir);
                    setIsOpen(false);
                    setPendingDirs({});
                  }}
                >
                  <span className="w-4 text-center shrink-0">
                    {isActive && (
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        width="14"
                        height="14"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2.5"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      >
                        <polyline points="20 6 9 17 4 12" />
                      </svg>
                    )}
                  </span>
                  <span className="flex-1">{option.label}</span>
                </button>
                {/* Direction toggle — clicking cycles direction without applying */}
                <button
                  className="flex items-center gap-1 px-3 py-2 text-token-caption text-[rgb(var(--color-text-muted))] hover:text-[rgb(var(--color-text-primary))] transition-colors"
                  onClick={() => {
                    const newDir = dir === "asc" ? "desc" : "asc";
                    if (isActive) {
                      onChange(option.value, newDir);
                    } else {
                      setPendingDirs((prev) => ({
                        ...prev,
                        [option.value]: newDir,
                      }));
                    }
                  }}
                >
                  <span>
                    {dir === "asc" ? option.ascLabel : option.descLabel}
                  </span>
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    width="12"
                    height="12"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    className="shrink-0"
                  >
                    {dir === "asc" ? (
                      <polyline points="18 15 12 9 6 15" />
                    ) : (
                      <polyline points="6 9 12 15 18 9" />
                    )}
                  </svg>
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
