// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { findGroupIcon } from "../data/groupIcons";

// Folder SVG paths — fallback when no icon is set (per D-13)
const FOLDER_PATHS = '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>';

interface GroupIconProps {
  icon?: string; // slug or "" / undefined for fallback
  size?: number;
  className?: string;
}

export function GroupIcon({ icon, size = 20, className = "" }: GroupIconProps) {
  const def = icon ? findGroupIcon(icon) : undefined;
  const paths = def?.paths ?? FOLDER_PATHS;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className={className}
      dangerouslySetInnerHTML={{ __html: paths }}
    />
  );
}
