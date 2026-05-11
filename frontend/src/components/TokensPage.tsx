// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useMemo, useEffect, useCallback, useRef } from "react";
import { useTranslation } from "react-i18next";
import { CopyCode } from "../../wailsjs/go/main/App";
import { CodePayload, SortOption, SortDirection } from "../types";
import { SortDropdown } from "./SortDropdown";
import { CardGrid } from "./CardGrid";

interface TokensPageProps {
  entries: CodePayload[];
  ready: boolean;
  sortOrder: SortOption;
  sortDirection: SortDirection;
  onSortChange: (option: SortOption, direction: SortDirection) => void;
  onEdit: (entryId: string) => void;
  onDelete: (entryId: string, name: string) => void;
  searchQuery: string;
  onOpenAddToken: () => void;
  selectedGroup: string;
  onGroupChange: (group: string) => void;
}

export function TokensPage({
  entries,
  ready,
  sortOrder,
  sortDirection,
  onSortChange,
  onEdit,
  onDelete,
  searchQuery,
  onOpenAddToken,
  selectedGroup,
  onGroupChange,
}: TokensPageProps) {
  const { t } = useTranslation();
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const [showSelection, setShowSelection] = useState(false);
  const selectionTimer = useRef<ReturnType<typeof setTimeout>>();
  const [copiedId, setCopiedId] = useState("");

  // Reset keyboard selection when group filter changes
  useEffect(() => {
    setSelectedIndex(-1);
    setShowSelection(false);
  }, [selectedGroup]);

  const triggerCopy = useCallback(async (entry: { id: string }) => {
    try {
      await CopyCode(entry.id);
      setCopiedId(entry.id);
      setTimeout(() => setCopiedId(""), 1500);
    } catch (e: unknown) {
      console.error("CopyCode failed:", e instanceof Error ? e.message : e);
    }
  }, []);

  const handleEdit = useCallback((entryId: string) => {
    onEdit(entryId);
  }, [onEdit]);

  const handleDelete = useCallback((entryId: string) => {
    const entry = entries.find((e) => e.id === entryId);
    if (entry) onDelete(entryId, entry.issuer || entry.name);
  }, [entries, onDelete]);

  // Sort entries by selected sort order — sort BEFORE filter for correct ordering
  const sortedEntries = useMemo(() => {
    const dir = sortDirection === "asc" ? 1 : -1;
    if (sortOrder === "date-added") {
      if (sortDirection === "asc") return entries;
      return [...entries].reverse();
    }
    const sorted = [...entries];
    switch (sortOrder) {
      case "issuer":
        sorted.sort(
          (a, b) =>
            dir * a.issuer.localeCompare(b.issuer) ||
            entries.indexOf(a) - entries.indexOf(b)
        );
        break;
      case "name":
        sorted.sort(
          (a, b) =>
            dir * a.name.localeCompare(b.name) ||
            entries.indexOf(a) - entries.indexOf(b)
        );
        break;
      case "usage-count":
        sorted.sort(
          (a, b) =>
            dir * (a.usageCount - b.usageCount) ||
            a.issuer.localeCompare(b.issuer)
        );
        break;
    }
    return sorted;
  }, [entries, sortOrder, sortDirection]);

  // Group filter — applied after sort, before search (D-07)
  const groupFilteredEntries = useMemo(() => {
    if (!selectedGroup) return sortedEntries;
    return sortedEntries.filter((e) => e.group === selectedGroup);
  }, [sortedEntries, selectedGroup]);

  // Filter entries by search query — no debounce needed for local in-memory filter
  const filteredEntries = useMemo(() => {
    if (!searchQuery.trim()) return groupFilteredEntries;
    const q = searchQuery.toLowerCase();
    return groupFilteredEntries.filter(
      (e) =>
        e.issuer.toLowerCase().includes(q) || e.name.toLowerCase().includes(q)
    );
  }, [groupFilteredEntries, searchQuery]);

  // Keyboard navigation handler
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;

      // Arrow navigation works even when search is focused
      const flashSelection = () => {
        clearTimeout(selectionTimer.current);
        setShowSelection(true);
        selectionTimer.current = setTimeout(() => setShowSelection(false), 1500);
      };

      // Detect grid column count from the card grid container.
      // SYNC: selector ".grid.grid-cols-1" must match the base class in CardGrid.tsx.
      const getColCount = () => {
        const grid = document.querySelector(".grid.grid-cols-1");
        if (!grid || grid.children.length < 2) return 1;
        const firstTop = (grid.children[0] as HTMLElement).offsetTop;
        let cols = 1;
        for (let i = 1; i < grid.children.length; i++) {
          if ((grid.children[i] as HTMLElement).offsetTop !== firstTop) break;
          cols++;
        }
        return cols;
      };

      if (e.key === "ArrowRight") {
        e.preventDefault();
        flashSelection();
        setSelectedIndex((i) => Math.min(i + 1, filteredEntries.length - 1));
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        flashSelection();
        setSelectedIndex((i) => Math.max(i - 1, 0));
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        flashSelection();
        const cols = getColCount();
        setSelectedIndex((i) => Math.min(i + cols, filteredEntries.length - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        flashSelection();
        const cols = getColCount();
        setSelectedIndex((i) => Math.max(i - cols, 0));
      } else if (
        e.key === "Enter" &&
        !(target instanceof HTMLInputElement && selectedIndex < 0)
      ) {
        // Enter copies selected entry's code
        // If search input is focused AND no selection, let Enter do nothing (don't submit)
        // If there IS a selection, copy regardless of focus
        if (selectedIndex >= 0 && selectedIndex < filteredEntries.length) {
          e.preventDefault();
          const entry = filteredEntries[selectedIndex];
          if (entry) {
            triggerCopy(entry);
          }
        }
      } else if (e.key === "Escape") {
        // Escape: clear selection
        setSelectedIndex(-1);
        setShowSelection(false);
      }
    };

    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [filteredEntries, selectedIndex, triggerCopy]);

  const hasEntries = entries.length > 0;

  const header = ready && hasEntries ? (
    <div className="hidden md:block px-8 pt-6 bg-bg" style={{ paddingBottom: 'var(--density-card-gap)' }}>
      <div className="flex flex-col md:flex-row justify-between items-end" style={{ paddingTop: 'var(--density-card-gap)', gap: 'var(--density-section-gap)' }}>
        <div>
          <h1 className="font-headline font-extrabold text-on-surface tracking-tight mb-2 text-4xl">
            {t("tokensPage.secureVaultHeading")}
          </h1>
          <p className="text-on-surface-variant font-medium flex items-center gap-2" style={{ fontSize: 'var(--text-body)' }}>
            <span className="w-2 h-2 rounded-full bg-secondary animate-pulse" />
            {t("tokensPage.activeTokenCount", { count: filteredEntries.length })}
          </p>
        </div>
        <SortDropdown
          value={sortOrder}
          direction={sortDirection}
          onChange={onSortChange}
        />
      </div>
    </div>
  ) : null;

  return (
    <>
      {header}

      {/* Card grid or empty state — this part scrolls */}
      <div className="pb-12 px-8 flex-1 flex flex-col w-full overflow-y-auto min-h-0"
        onClick={(e) => {
          if (!(e.target as HTMLElement).closest(".card-surface")) {
            setSelectedIndex(-1);
            setShowSelection(false);
          }
        }}
      >
        {!ready ? null : hasEntries ? (
          filteredEntries.length > 0 ? (
            <CardGrid
              entries={filteredEntries}
              selectedIndex={showSelection ? selectedIndex : -1}
              copiedId={copiedId}
              onCopy={(entry) => {
                const idx = filteredEntries.findIndex((e) => e.id === entry.id);
                if (idx >= 0) setSelectedIndex(idx);
                triggerCopy(entry);
              }}
              onEdit={handleEdit}
              onDelete={handleDelete}
            />
          ) : (
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center flex flex-col items-center gap-3">
                <svg
                  width="48"
                  height="48"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  className="text-text-muted"
                  aria-hidden="true"
                >
                  <circle cx="11" cy="11" r="8" />
                  <line x1="21" y1="21" x2="16.65" y2="16.65" />
                  <line x1="8" y1="8" x2="14" y2="14" />
                  <line x1="14" y1="8" x2="8" y2="14" />
                </svg>
                <div className="text-on-surface font-medium">
                  {t("tokensPage.noMatches")}
                </div>
              </div>
            </div>
          )
        ) : (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center flex flex-col items-center gap-3">
              <svg
                width="48"
                height="48"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="text-text-muted"
                aria-hidden="true"
              >
                <polyline points="22 12 16 12 14 15 10 15 8 12 2 12" />
                <path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" />
              </svg>
              <div>
                <div className="text-on-surface font-medium">
                  {t("tokensPage.noAccounts")}
                </div>
                <div className="text-outline text-sm mt-1">
                  {t("tokensPage.noAccountsHint")}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
