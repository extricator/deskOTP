// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import React from "react";

interface Props {
  remaining: number;
  period: number;
}

/** Compute bar color as an rgb() string for a given remaining/period ratio. */
function barColor(remaining: number, period: number): string {
  const ratio = Math.max(0, Math.min(1, remaining / period));
  // mid-green (#2aad7a) → error (#ba1a1a)
  const r = Math.round(42 + (186 - 42) * (1 - ratio));
  const g = Math.round(173 + (26 - 173) * (1 - ratio));
  const b = Math.round(122 + (26 - 122) * (1 - ratio));
  return `rgb(${r}, ${g}, ${b})`;
}

// End color is always full red (remaining=0)
const END_COLOR = "rgb(186, 26, 26)";

export function getTimerPhase(remaining: number, period: number): "normal" | "warning" | "critical" {
  const pct = (remaining / period) * 100;
  if (pct < 20) return "critical";
  if (pct <= 50) return "warning";
  return "normal";
}

/**
 * CountdownBar uses a pure CSS animation to shrink from the current scale to 0
 * over `remaining` seconds. No JavaScript timer or React re-renders are needed
 * during the countdown — the browser's compositor handles the animation on the
 * GPU. The bar is re-mounted (via key in the parent) when a new code arrives,
 * restarting the animation from the fresh remaining value.
 */
export const CountdownBar = React.memo(function CountdownBar({ remaining, period }: Props) {
  const startScale = Math.max(0, Math.min(1, remaining / period));

  return (
    <div className="w-full h-1.5 bg-surface-container-high rounded-full overflow-hidden">
      <div
        className="h-full w-full origin-left rounded-full countdown-bar"
        style={{
          transform: `scaleX(${startScale})`,
          backgroundColor: barColor(remaining, period),
          animationDuration: `${remaining}s`,
          // CSS custom property for the end color used by the @keyframes rule
          "--countdown-end-bg": END_COLOR,
        } as React.CSSProperties}
      />
    </div>
  );
});
