// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

// frontend/src/components/LetterAvatar.tsx
import { stringToColor, getAvatarLetter } from "../utils/avatarColor";

interface Props {
  issuer: string;
  name: string;
}

export function LetterAvatar({ issuer, name }: Props) {
  const letter = getAvatarLetter(issuer, name);
  const bgColor = stringToColor(issuer?.trim() || name?.trim() || "");

  return (
    <div
      className="rounded-full flex items-center justify-center text-lg font-bold text-white flex-shrink-0 select-none"
      style={{ backgroundColor: bgColor, width: 'var(--density-avatar-size)', height: 'var(--density-avatar-size)' }}
      aria-hidden="true"
    >
      {letter}
    </div>
  );
}
