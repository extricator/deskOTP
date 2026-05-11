// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import React, { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { CountdownBar, getTimerPhase } from "./CountdownBar";
import { AccountAvatar } from "./AccountAvatar";
import { CodePayload, formatCode } from "../types";

interface Props {
  entry: CodePayload;
  selected: boolean;
  copiedId: string;
  onCopy: (entry: CodePayload) => void;
  onContextMenu: (e: React.MouseEvent, entry: CodePayload) => void;
}

function areOtpCardPropsEqual(prev: Props, next: Props): boolean {
  return (
    prev.entry.id === next.entry.id &&
    prev.entry.code === next.entry.code &&
    // remaining is NOT compared — CountdownBar handles its own CSS animation.
    // OtpCard only re-renders when the code actually changes (every period).
    prev.entry.period === next.entry.period &&
    prev.entry.issuer === next.entry.issuer &&
    prev.entry.name === next.entry.name &&
    prev.entry.icon === next.entry.icon &&
    prev.entry.type === next.entry.type &&
    prev.entry.usageCount === next.entry.usageCount &&
    prev.entry.group === next.entry.group &&
    prev.selected === next.selected &&
    prev.copiedId === next.copiedId
  );
}

export const OtpCard = React.memo(function OtpCard({
  entry,
  selected,
  copiedId,
  onCopy,
  onContextMenu,
}: Props) {
  const { t } = useTranslation();
  const copied = copiedId === entry.id;

  // Phase starts from the entry's current remaining value and transitions
  // to "warning" and "critical" via scheduled timers. This avoids per-second
  // re-renders — only 0-2 phase transitions happen per code period.
  const [phase, setPhase] = useState<"normal" | "warning" | "critical">(() =>
    entry.type !== "hotp" ? getTimerPhase(entry.remaining, entry.period) : "normal"
  );

  useEffect(() => {
    if (entry.type === "hotp") return;

    const { remaining, period } = entry;
    const currentPhase = getTimerPhase(remaining, period);
    setPhase(currentPhase);

    // Schedule future phase transitions
    const warningThreshold = Math.ceil(period * 0.5);
    const criticalThreshold = Math.ceil(period * 0.2);
    const timers: ReturnType<typeof setTimeout>[] = [];

    if (currentPhase === "normal" && remaining > warningThreshold) {
      timers.push(
        setTimeout(() => setPhase("warning"), (remaining - warningThreshold) * 1000)
      );
    }
    if ((currentPhase === "normal" || currentPhase === "warning") && remaining > criticalThreshold) {
      timers.push(
        setTimeout(() => setPhase("critical"), (remaining - criticalThreshold) * 1000)
      );
    }

    return () => timers.forEach(clearTimeout);
  }, [entry.code, entry.remaining, entry.period, entry.type]);

  return (
    <div
      onClick={() => onCopy(entry)}
      onContextMenu={(e) => {
        e.preventDefault();
        onContextMenu(e, entry);
      }}
      className={`group relative card-surface overflow-hidden transition-[background-color,box-shadow] cursor-pointer select-none
        ${copied ? "outline outline-2 -outline-offset-2 outline-primary/40" : ""}
        ${selected ? "outline outline-2 -outline-offset-2 outline-primary/40 bg-primary/5" : ""}
      `}
      style={{ padding: 'var(--density-card-py) var(--density-card-px)' }}
    >
      {/* Header: avatar + issuer/name + status badge or three-dot */}
      <div className="relative flex items-start justify-between" style={{ marginBottom: 'var(--density-card-gap)' }}>
        <div className="flex items-center gap-4 min-w-0">
          <AccountAvatar icon={entry.icon} issuer={entry.issuer} name={entry.name} />
          <div className="min-w-0">
            <h3 className="font-headline font-bold text-on-surface truncate text-lg">{entry.issuer}</h3>
            <p className="text-text-muted font-medium truncate" style={{ fontSize: 'var(--text-caption)' }}>{entry.name}</p>
          </div>
        </div>
        <button
          onClick={(e) => { e.stopPropagation(); onContextMenu(e, entry); }}
          className="opacity-0 group-hover:opacity-100 p-1.5 hover:bg-surface-container-low rounded-full transition-[opacity,background-color] shrink-0"
          aria-label={t("contextMenu.moreOptions", "More options")}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" className="text-text-muted" aria-hidden="true">
            <circle cx="12" cy="5" r="2" />
            <circle cx="12" cy="12" r="2" />
            <circle cx="12" cy="19" r="2" />
          </svg>
        </button>
      </div>

      {/* Centered code box */}
      <div className="relative" style={{ marginBottom: 'var(--density-card-py)' }}>
        {copied && (
          <div className="absolute inset-0 z-10 flex items-center justify-center bg-primary/10 rounded-lg backdrop-blur-sm">
            <span className="text-primary font-black text-sm uppercase tracking-widest flex items-center gap-2">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" className="text-primary" aria-hidden="true">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
              </svg>
              {t("tokensPage.copied")}
            </span>
          </div>
        )}
        <div
          className={`bg-surface-container-low rounded-lg py-4 text-center font-headline font-medium tabular-nums tracking-[0.2em] text-3xl transition-[transform] group-hover:scale-[1.02] ${
            copied ? "text-primary/20 blur-[2px]" : phase === "critical" ? "text-error" : "text-primary"
          }`}
        >
          {entry.type === "steam" ? entry.code : formatCode(entry.code)}
        </div>
      </div>

      {/* Countdown bar — CSS animation handles the countdown, no JS timer needed.
          key={entry.code} remounts the bar when the code changes, restarting the animation. */}
      {entry.type !== "hotp" && (
        <CountdownBar key={entry.code} remaining={entry.remaining} period={entry.period} />
      )}
    </div>
  );
}, areOtpCardPropsEqual);
