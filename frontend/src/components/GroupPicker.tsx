// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { GetEntryGroups, CreateGroup } from "../../wailsjs/go/main/App";
import { extractErrorMessage } from "../utils/extractErrorMessage";
import { BASE_INPUT_CLASS } from "../utils/inputClass";
import { GroupIcon } from "./GroupIcon";

interface GroupPickerProps {
  value: string; // "" = ungrouped
  onChange: (group: string) => void;
}

export function GroupPicker({ value, onChange }: GroupPickerProps) {
  const { t } = useTranslation();
  const [isOpen, setIsOpen] = useState(false);
  const [groups, setGroups] = useState<Array<{ name: string; icon?: string }>>([]);
  const [createInput, setCreateInput] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  // Load groups on mount
  useEffect(() => {
    GetEntryGroups().then(setGroups).catch(() => {});
  }, []);

  // Click-outside dismissal
  useEffect(() => {
    if (!isOpen) return;
    const handleMouseDown = (e: MouseEvent) => {
      if (
        containerRef.current &&
        !containerRef.current.contains(e.target as Node)
      ) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleMouseDown);
    return () => document.removeEventListener("mousedown", handleMouseDown);
  }, [isOpen]);

  // Escape key dismissal — stopPropagation prevents EditDialog's Escape from firing
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        setIsOpen(false);
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [isOpen]);

  // Filtered groups based on createInput
  const filteredGroups = createInput.trim()
    ? groups.filter((g) =>
        g.name.toLowerCase().includes(createInput.toLowerCase())
      )
    : groups;

  // Whether to show the Create button
  const trimmedInput = createInput.trim();
  const groupExactMatch = groups.some(
    (g) => g.name.toLowerCase() === trimmedInput.toLowerCase()
  );
  const showCreateButton = trimmedInput.length > 0 && !groupExactMatch;

  async function handleCreate() {
    const name = createInput.trim();
    if (!name) return;
    setCreating(true);
    setCreateError(null);
    try {
      await CreateGroup(name, "");
      const updated = await GetEntryGroups();
      setGroups(updated);
      onChange(name);
      setCreateInput("");
      setIsOpen(false);
    } catch (e) {
      const raw = extractErrorMessage(e);
      setCreateError(
        raw.includes("already exists")
          ? t("groupPicker.duplicateError")
          : t("groupPicker.createError")
      );
    } finally {
      setCreating(false);
    }
  }

  return (
    <div ref={containerRef} className="relative">
      {/* Trigger button */}
      <button
        type="button"
        onClick={() => setIsOpen((prev) => !prev)}
        className={`${BASE_INPUT_CLASS} flex items-center justify-between`}
      >
        <span className="flex items-center gap-2">
          {value ? (
            <>
              <GroupIcon
                icon={groups.find(g => g.name === value)?.icon ?? ""}
                size={16}
                className="shrink-0 text-[rgb(var(--color-text-muted))]"
              />
              <span className="text-[rgb(var(--color-text-primary))]">{value}</span>
            </>
          ) : (
            <span className="text-[rgb(var(--color-text-muted))]">
              {t("groupPicker.placeholder")}
            </span>
          )}
        </span>
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
          className={`transition-transform shrink-0 ${isOpen ? "rotate-180" : ""}`}
        >
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>

      {/* Popover dropdown */}
      {isOpen && (
        <div className="absolute left-0 top-full mt-1 w-full z-20 bg-[rgb(var(--color-surface))] border border-[rgb(var(--color-border))] rounded-lg shadow-xl py-1">
          {/* Create input area (top of popover) */}
          <div className="px-3 py-2 border-b border-[rgb(var(--color-border))]">
            <div className="flex gap-2 items-center">
              <input
                type="text"
                value={createInput}
                onChange={(e) => {
                  setCreateInput(e.target.value);
                  setCreateError(null);
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && showCreateButton) {
                    e.preventDefault();
                    handleCreate();
                  }
                }}
                placeholder={t("groupPicker.placeholder")}
                className={BASE_INPUT_CLASS}
                autoComplete="off"
              />
              {showCreateButton && (
                <button
                  type="button"
                  onClick={handleCreate}
                  disabled={creating}
                  className="px-3 py-1 rounded bg-primary text-on-primary text-token-caption font-medium disabled:opacity-50 whitespace-nowrap"
                >
                  {creating
                    ? t("groupPicker.creating")
                    : t("groupPicker.createButton")}
                </button>
              )}
            </div>
            {createError && (
              <p className="text-token-caption text-[rgb(var(--color-error))] mt-1">
                {createError}
              </p>
            )}
          </div>

          {/* "None" option */}
          <button
            type="button"
            onClick={() => {
              onChange("");
              setIsOpen(false);
            }}
            className="flex items-center gap-2 px-4 py-2 w-full text-left hover:bg-[rgb(var(--color-surface-hover))] transition-colors"
          >
            <span className="w-4 text-center shrink-0">
              {value === "" && (
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
            <span
              className={
                value === ""
                  ? "font-medium text-[rgb(var(--color-text-primary))]"
                  : "text-[rgb(var(--color-text-secondary))]"
              }
            >
              {t("groupPicker.none")}
            </span>
          </button>

          {/* Filtered group list */}
          {filteredGroups.map((group) => (
            <button
              key={group.name}
              type="button"
              onClick={() => {
                onChange(group.name);
                setIsOpen(false);
              }}
              className="flex items-center gap-2 px-4 py-2 w-full text-left hover:bg-[rgb(var(--color-surface-hover))] transition-colors"
            >
              <span className="w-4 text-center shrink-0">
                {value === group.name && (
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
              <GroupIcon
                icon={group.icon}
                size={16}
                className="shrink-0 text-[rgb(var(--color-text-muted))]"
              />
              <span
                className={
                  value === group.name
                    ? "font-medium text-[rgb(var(--color-text-primary))]"
                    : "text-[rgb(var(--color-text-secondary))]"
                }
              >
                {group.name}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
