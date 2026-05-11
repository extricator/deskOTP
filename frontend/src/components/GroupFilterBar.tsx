// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useTranslation } from "react-i18next";

interface GroupFilterBarProps {
  groups: string[];
  selected: string;
  onSelect: (group: string) => void;
}

export function GroupFilterBar({ groups, selected, onSelect }: GroupFilterBarProps) {
  const { t } = useTranslation();
  const allChips = ["", ...groups];

  return (
    <div className="flex flex-wrap gap-2 pb-3">
      {allChips.map((g) => {
        const isActive = selected === g;
        return (
          <button
            key={g || "__all__"}
            onClick={() => onSelect(g)}
            className={`px-3 py-1.5 rounded-full text-sm font-medium transition-colors cursor-pointer ${
              isActive
                ? "bg-primary text-on-primary"
                : "bg-surface-container-high text-on-surface hover:bg-surface-container-highest"
            }`}
          >
            {g || t("groupFilterBar.all")}
          </button>
        );
      })}
    </div>
  );
}
