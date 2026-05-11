// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useCallback, useEffect } from "react";
import { GetSetting, SetSetting } from "../../wailsjs/go/main/App";
import { SortOption, SortDirection } from "../types";
import i18n from "../i18n";

/** useAppSettings loads and manages all persistent app settings from the Go backend on mount. */
export function useAppSettings(): {
  nudgeDismissed: boolean | null;
  setNudgeDismissed: React.Dispatch<React.SetStateAction<boolean | null>>;
  sortOrder: SortOption;
  sortDirection: SortDirection;
  autoLockTimeout: string;
  handleSortChange: (option: SortOption, direction: SortDirection) => void;
  handleAutoLockChange: (val: string) => void;
} {
  const [nudgeDismissed, setNudgeDismissed] = useState<boolean | null>(null);
  const [sortOrder, setSortOrder] = useState<SortOption>("date-added");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [autoLockTimeout, setAutoLockTimeout] = useState<string>("never");

  // Load all settings on mount
  useEffect(() => {
    GetSetting("nudge_dismissed")
      .then((val) => setNudgeDismissed(val === "true"))
      .catch(() => setNudgeDismissed(false));
    GetSetting("sort_order")
      .then((val) => {
        if (
          val &&
          ["issuer", "name", "date-added", "usage-count"].includes(val)
        ) {
          setSortOrder(val as SortOption);
        }
      })
      .catch(() => {});
    GetSetting("sort_direction")
      .then((val) => {
        if (val === "asc" || val === "desc") {
          setSortDirection(val as SortDirection);
        }
      })
      .catch(() => {});
    GetSetting("auto_lock_timeout")
      .then((val) => {
        if (val && ["1", "5", "15", "30", "never"].includes(val)) {
          setAutoLockTimeout(val);
        }
      })
      .catch(() => {});
    // Language reconciliation — Go settings is source of truth
    GetSetting("language")
      .then((lang) => {
        const validLangs = ["en", "es"];
        if (lang && validLangs.includes(lang) && lang !== i18n.language) {
          i18n.changeLanguage(lang);
          localStorage.setItem("language", lang);
        }
      })
      .catch(() => {});
  }, []);

  const handleSortChange = useCallback(
    (option: SortOption, direction: SortDirection) => {
      setSortOrder(option);
      setSortDirection(direction);
      SetSetting("sort_order", option).catch(console.error);
      SetSetting("sort_direction", direction).catch(console.error);
    },
    []
  );

  const handleAutoLockChange = useCallback((val: string) => {
    setAutoLockTimeout(val);
  }, []);

  return {
    nudgeDismissed,
    setNudgeDismissed,
    sortOrder,
    sortDirection,
    autoLockTimeout,
    handleSortChange,
    handleAutoLockChange,
  };
}
