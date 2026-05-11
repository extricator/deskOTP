// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState } from "react";
import { LetterAvatar } from "./LetterAvatar";

interface Props {
  icon?: string; // slug e.g. "github"; empty/undefined = no icon
  issuer: string;
  name: string;
}

export function AccountAvatar({ icon, issuer, name }: Props) {
  const [imgError, setImgError] = useState(false);

  if (icon && !imgError) {
    return (
      <img
        src={`/icons/${icon}.svg`}
        alt=""
        aria-hidden="true"
        className="flex-shrink-0 object-contain"
        style={{ width: 'var(--density-avatar-size)', height: 'var(--density-avatar-size)' }}
        onError={() => setImgError(true)}
      />
    );
  }

  return <LetterAvatar issuer={issuer} name={name} />;
}
