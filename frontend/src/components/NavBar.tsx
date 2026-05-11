// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useRef, useEffect, RefObject } from "react";
import { useTranslation } from "react-i18next";
import { useTheme } from "../hooks/useTheme";
import { ImportArea, ImportAreaHandle } from "./ImportArea";
import { ImportCounts } from "../types";

type Page = "tokens" | "settings";

interface Props {
  searchQuery: string;
  onSearchChange: (query: string) => void;
  onToggleSidebar?: () => void;
  onResult: (counts: ImportCounts) => void;
  vaultEnabled: boolean;
  onLock: () => void;
  onLockDisabled: () => void;
  showBadge?: boolean;
  activePage: Page;
  onNavigate: (page: Page) => void;
  importRef?: RefObject<ImportAreaHandle>;
}

export function NavBar({
  searchQuery,
  onSearchChange,
  onToggleSidebar,
  onResult,
  vaultEnabled,
  onLock,
  onLockDisabled,
  showBadge,
  activePage,
  onNavigate,
  importRef,
}: Props) {
  const { theme, toggleTheme } = useTheme();
  const { t } = useTranslation();
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      if (
        (e.key === "/" || (e.key === "k" && (e.ctrlKey || e.metaKey))) &&
        !(target instanceof HTMLInputElement)
      ) {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, []);

  return (
    <header
      className="flex justify-between items-center w-full px-8 bg-bg border-b border-outline-variant/30 fixed top-0 left-0 right-0 z-50"
      style={{ paddingTop: 'var(--density-navbar-py)', paddingBottom: 'var(--density-navbar-py)' }}
    >
      {/* Left: hamburger (mobile) + brand */}
      <div className="flex items-center gap-4">
        <button
          onClick={onToggleSidebar}
          className="lg:hidden p-2 text-on-surface hover:bg-surface-container-high rounded-lg transition-colors cursor-pointer"
          aria-label="Toggle navigation"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <line x1="3" y1="6" x2="21" y2="6" />
            <line x1="3" y1="12" x2="21" y2="12" />
            <line x1="3" y1="18" x2="21" y2="18" />
          </svg>
        </button>
        <span className="text-2xl font-bold tracking-tighter text-primary font-headline select-none hidden lg:inline">
          deskOTP
        </span>
        <div
          className="hidden md:flex items-center gap-6"
          style={{ marginLeft: 'calc(var(--sidebar-width) - 7.5rem)' }}
        >
          <button
            onClick={() => onNavigate("tokens")}
            className={`px-2 py-1 font-semibold transition-colors cursor-pointer border-b-[3px] ${
              activePage === "tokens"
                ? "text-primary border-primary"
                : "text-text-muted border-transparent hover:text-on-surface"
            }`}
          >
            {t("tokensPage.heading")}
          </button>
          <button
            onClick={() => onNavigate("settings")}
            className={`px-2 py-1 font-semibold transition-colors cursor-pointer border-b-[3px] relative ${
              activePage === "settings"
                ? "text-primary border-primary"
                : "text-text-muted border-transparent hover:text-on-surface"
            }`}
          >
            {t("nav.settings")}
            {showBadge && activePage !== "settings" && (
              <span className="absolute -top-1 -right-2 w-2 h-2 rounded-full bg-tertiary" />
            )}
          </button>
        </div>
      </div>

      {/* Right: search + utility buttons */}
      <div className="flex items-center gap-4">
        {/* Search input */}
        <div className="relative">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            ref={searchRef}
            className="pl-10 pr-4 py-1.5 bg-surface-container-high border-none rounded-lg text-sm w-32 sm:w-48 lg:w-64 focus:ring-2 focus:ring-primary/20 focus:bg-surface-container-lowest transition-all placeholder:text-text-muted text-text-primary focus:outline-none"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder={t("tokensPage.searchPlaceholder")}
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                if (searchQuery) {
                  // Stage 1: clear text, stop propagation so TokensPage doesn't also deselect
                  e.stopPropagation();
                  onSearchChange("");
                } else {
                  // Stage 2: input already empty, blur the search bar
                  // No stopPropagation — let TokensPage deselect card if any
                  searchRef.current?.blur();
                }
              }
            }}
          />
        </div>

        <div className="flex items-center gap-2">
        {/* Import */}
        <ImportArea ref={importRef} compact onResult={onResult} />

        {/* Lock */}
        <button
          onClick={vaultEnabled ? onLock : onLockDisabled}
          aria-label={vaultEnabled ? t("nav.lockTooltip") : t("nav.lockDisabledTooltip")}
          title={vaultEnabled ? t("nav.lockTooltip") : t("nav.lockDisabledTooltip")}
          className={`p-2 rounded-lg transition-all active:scale-95 ${
            vaultEnabled
              ? "text-text-muted hover:text-primary hover:bg-surface-container-high cursor-pointer"
              : "text-text-muted cursor-not-allowed"
          }`}
        >
          <svg aria-hidden="true" xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
        </button>

        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          aria-label={theme === "dark" ? t("nav.themeDark") : t("nav.themeLight")}
          title={theme === "dark" ? t("nav.themeDark") : t("nav.themeLight")}
          className="p-2 text-text-muted hover:text-primary hover:bg-surface-container-high rounded-lg transition-all active:scale-95 cursor-pointer"
        >
          {theme === "dark" ? (
            <svg aria-hidden="true" xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="5" />
              <line x1="12" y1="1" x2="12" y2="3" />
              <line x1="12" y1="21" x2="12" y2="23" />
              <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
              <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
              <line x1="1" y1="12" x2="3" y2="12" />
              <line x1="21" y1="12" x2="23" y2="12" />
              <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
              <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
            </svg>
          ) : (
            <svg aria-hidden="true" xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
            </svg>
          )}
        </button>
        </div>
      </div>
    </header>
  );
}
