// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useCallback, useEffect } from "react";
import { WindowSetBackgroundColour } from "../../wailsjs/runtime/runtime";
import { SetSetting } from "../../wailsjs/go/main/App";

type Theme = "light" | "dark";

// Dark theme Wails background: Obsidian dark = rgb(17, 19, 23)
const DARK_BG = { r: 17, g: 19, b: 23 } as const;
// Light theme Wails background: Obsidian light = rgb(248, 249, 251)
const LIGHT_BG = { r: 248, g: 249, b: 251 } as const;

function getInitialTheme(): Theme {
  const stored = localStorage.getItem("theme");
  if (stored === "dark" || stored === "light") return stored;
  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

export function useTheme() {
  const [theme, setTheme] = useState<Theme>(getInitialTheme);

  // Sync DOM class and Wails background whenever theme changes
  useEffect(() => {
    const html = document.documentElement;
    // Enable smooth cross-fade for the theme switch only
    html.classList.add("theme-transitioning");
    if (theme === "dark") {
      html.classList.add("dark");
      WindowSetBackgroundColour(DARK_BG.r, DARK_BG.g, DARK_BG.b, 255);
    } else {
      html.classList.remove("dark");
      WindowSetBackgroundColour(LIGHT_BG.r, LIGHT_BG.g, LIGHT_BG.b, 255);
    }
    // Remove after transition completes so scroll compositing stays clean
    const tid = setTimeout(() => html.classList.remove("theme-transitioning"), 200);
    localStorage.setItem("theme", theme);
    // Write-through to Go settings.json (source of truth).
    // Fire-and-forget: localStorage is the FOWT cache read by the inline script
    // before React loads. settings.json is authoritative for Go-side consumers.
    SetSetting("theme", theme).catch(() => {});
    return () => clearTimeout(tid);
  }, [theme]);

  const toggleTheme = useCallback(() => {
    setTheme((t) => (t === "dark" ? "light" : "dark"));
  }, []);

  return { theme, toggleTheme };
}
