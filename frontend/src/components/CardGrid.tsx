// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useRef, useEffect, useState, useCallback } from "react";
import { OtpCard } from "./OtpCard";
import { ContextMenu } from "./ContextMenu";
import { CodePayload } from "../types";

interface Props {
  entries: CodePayload[];
  selectedIndex: number;
  copiedId: string;
  onCopy: (entry: CodePayload) => void;
  onEdit?: (entryId: string) => void;
  onDelete?: (entryId: string) => void;
}

interface ContextMenuState {
  entryId: string;
  x: number;
  y: number;
}

export function CardGrid({
  entries,
  selectedIndex,
  copiedId,
  onCopy,
  onEdit,
  onDelete,
}: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);

  // Scroll selected card into view when navigating by keyboard
  useEffect(() => {
    if (selectedIndex < 0 || !containerRef.current) return;
    const cards = containerRef.current.children;
    const card = cards[selectedIndex] as HTMLElement | undefined;
    card?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [selectedIndex]);

  const handleContextMenu = useCallback(
    (e: React.MouseEvent, entry: CodePayload) => {
      setContextMenu({ entryId: entry.id, x: e.clientX, y: e.clientY });
    },
    []
  );

  // Dismiss context menu on scroll
  useEffect(() => {
    const container = containerRef.current;
    if (!container || !contextMenu) return;
    const handleScroll = () => setContextMenu(null);
    container.addEventListener("scroll", handleScroll);
    return () => container.removeEventListener("scroll", handleScroll);
  }, [contextMenu]);

  return (
    <>
      {/* NOTE: getColCount() in TokensPage.tsx queries ".grid.grid-cols-1" — keep base class in sync */}
      <div
        ref={containerRef}
        className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-4 content-start gap-4"
      >
        {entries.map((entry, i) => (
          <OtpCard
            key={entry.id}
            entry={entry}
            selected={i === selectedIndex}
            copiedId={copiedId}
            onCopy={onCopy}
            onContextMenu={handleContextMenu}
          />
        ))}
      </div>
      {contextMenu && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          onCopy={() => {
            const entry = entries.find((e) => e.id === contextMenu.entryId);
            if (entry) onCopy(entry);
            setContextMenu(null);
          }}
          onEdit={() => {
            onEdit?.(contextMenu.entryId);
            setContextMenu(null);
          }}
          onDelete={() => {
            onDelete?.(contextMenu.entryId);
            setContextMenu(null);
          }}
          onClose={() => setContextMenu(null)}
        />
      )}
    </>
  );
}
