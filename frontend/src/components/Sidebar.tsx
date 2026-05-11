// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { SidebarGroupContextMenu } from "./SidebarGroupContextMenu";
import { GroupEditDialog } from "./GroupEditDialog";
import { GroupIcon } from "./GroupIcon";
import { GetEntryGroups, ReorderGroups } from "../../wailsjs/go/main/App";

interface GroupData {
  name: string;
  icon?: string;
}

interface SidebarProps {
  activePage: "tokens" | "settings";
  onNavigate: (page: "tokens" | "settings") => void;
  groups: GroupData[];
  selectedGroup: string;
  onGroupChange: (group: string) => void;
  onAddToken: () => void;
  open: boolean;
  onClose: () => void;
  onGroupsChanged: (info: { oldName?: string; newName: string }) => void;
  onDeleteGroup: (groupName: string) => void;
}

export function Sidebar({
  activePage,
  onNavigate,
  groups,
  selectedGroup,
  onGroupChange,
  onAddToken,
  open,
  onClose,
  onGroupsChanged,
  onDeleteGroup,
}: SidebarProps) {
  const { t } = useTranslation();

  const [groupDialog, setGroupDialog] = useState<{
    mode: "create" | "rename";
    initialName?: string;
    initialIcon?: string;
  } | null>(null);

  const [contextMenu, setContextMenu] = useState<{
    x: number;
    y: number;
    group: string;
    isFirst: boolean;
    isLast: boolean;
  } | null>(null);

  const isTokensActive = activePage === "tokens";
  const isAllTokens = isTokensActive && !selectedGroup;

  const navItemBase =
    "flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all text-sm";
  const navItemActive =
    "bg-surface-container-lowest text-primary font-bold shadow-sm";
  const navItemInactive =
    "text-text-muted font-medium hover:text-primary hover:bg-surface-container-lowest/50";

  function handleAllTokens() {
    onGroupChange("");
    onNavigate("tokens");
    onClose();
  }

  function handleGroup(groupName: string) {
    onGroupChange(groupName);
    onNavigate("tokens");
    onClose();
  }

  return (
    <>
      {/* Backdrop for mobile */}
      {open && (
        <div
          className="fixed inset-0 bg-black/40 z-40 lg:hidden"
          onClick={onClose}
        />
      )}

      {/* Sidebar panel */}
      <aside
        className={`fixed left-0 w-sidebar bg-surface-container-low border-r border-outline-variant/30 flex flex-col p-4 gap-2 z-40 transition-transform
          ${open ? "translate-x-0" : "-translate-x-full"} lg:translate-x-0`}
        style={{ top: 'var(--navbar-height)', height: 'calc(100vh - var(--navbar-height))' }}
      >
        {/* Section label */}
        <div className="mb-4 px-2 pt-2">
          <h2 className="text-xs font-bold uppercase tracking-widest text-text-muted">Filter &amp; Groups</h2>
        </div>

        {/* Navigation */}
        <nav className="flex flex-col gap-1 flex-1 overflow-y-auto">
          {/* All Tokens */}
          <button
            onClick={handleAllTokens}
            className={`${navItemBase} ${isAllTokens ? navItemActive : navItemInactive}`}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            <span>{t("sidebar.allTokens")}</span>
          </button>

          {groups.length > 0 && (
            <>
              <div className="mt-3" />
              <div className="w-1/2 mx-auto border-t border-outline-variant/30" />
              <div className="mt-1" />
            </>
          )}

          {groups.map((group, index) => {
            const isActive = isTokensActive && selectedGroup === group.name;
            const isMenuOpen = contextMenu?.group === group.name;
            return (
              <div key={group.name} className="group relative">
                <button
                  onClick={() => handleGroup(group.name)}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    setContextMenu({
                      x: e.clientX,
                      y: e.clientY,
                      group: group.name,
                      isFirst: index === 0,
                      isLast: index === groups.length - 1,
                    });
                  }}
                  className={`${navItemBase} w-full pr-8 ${isActive ? navItemActive : navItemInactive}`}
                >
                  <GroupIcon icon={group.icon} size={20} />
                  <span className="truncate">{group.name}</span>
                </button>
                {/* Kebab (three-dot) button — hover/focus reveal, per D-01 through D-09 */}
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    const rect = e.currentTarget.getBoundingClientRect();
                    setContextMenu({
                      x: rect.left,
                      y: rect.bottom,
                      group: group.name,
                      isFirst: index === 0,
                      isLast: index === groups.length - 1,
                    });
                  }}
                  className={`absolute right-2 top-1/2 -translate-y-1/2 p-1 rounded-full transition-opacity hover:bg-surface-container-lowest/50 ${
                    isMenuOpen ? "opacity-100" : "opacity-0 group-hover:opacity-100 focus:opacity-100"
                  }`}
                  aria-label={t("contextMenu.moreOptions", "More options")}
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" className="text-text-muted" aria-hidden="true">
                    <circle cx="12" cy="5" r="2" />
                    <circle cx="12" cy="12" r="2" />
                    <circle cx="12" cy="19" r="2" />
                  </svg>
                </button>
              </div>
            );
          })}

          <div className="mt-auto" />
        </nav>

        {/* Bottom actions */}
        <div className="pt-4 flex flex-col gap-2">
          {/* New Group button — outline style, secondary action (per D-02..D-08) */}
          <button
            type="button"
            onClick={() => setGroupDialog({ mode: "create" })}
            className="w-full py-2.5 px-4 rounded-lg border border-outline-variant text-text-muted font-medium text-sm flex items-center justify-center transition-all hover:border-primary hover:text-primary active:scale-95"
          >
            + {t("sidebar.newGroup")}
          </button>
          {/* Short centered divider (per D-03) */}
          <div className="w-1/2 mx-auto border-t border-outline-variant/30" />
          {/* Add New Token button — gradient, primary action (unchanged) */}
          <button
            onClick={() => { onAddToken(); onClose(); }}
            className="w-full py-3 px-4 rounded-lg bg-gradient-to-br from-primary to-primary-container text-on-primary font-semibold text-sm flex items-center justify-center gap-2 hover:opacity-90 active:scale-95 transition-all shadow-card"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <line x1="12" y1="5" x2="12" y2="19" />
              <line x1="5" y1="12" x2="19" y2="12" />
            </svg>
            {t("sidebar.addNewToken")}
          </button>
        </div>
      </aside>

      {contextMenu && (
        <SidebarGroupContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          groupName={contextMenu.group}
          isFirst={contextMenu.isFirst}
          isLast={contextMenu.isLast}
          onRename={() => {
            const g = groups.find(g => g.name === contextMenu.group);
            setGroupDialog({ mode: "rename", initialName: contextMenu.group, initialIcon: g?.icon ?? "" });
            setContextMenu(null);
          }}
          onMoveUp={async () => {
            const groupName = contextMenu.group;
            setContextMenu(null);
            try {
              const fresh = await GetEntryGroups();
              const freshNames = fresh.map(g => g.name);
              const idx = freshNames.indexOf(groupName);
              if (idx <= 0) return;
              const reordered = [...freshNames];
              const tmp = reordered[idx - 1] as string;
              reordered[idx - 1] = reordered[idx] as string;
              reordered[idx] = tmp;
              await ReorderGroups(reordered);
              onGroupsChanged({ newName: groupName });
            } catch (e) {
              console.error("ReorderGroups (up) failed:", e);
            }
          }}
          onMoveDown={async () => {
            const groupName = contextMenu.group;
            setContextMenu(null);
            try {
              const fresh = await GetEntryGroups();
              const freshNames = fresh.map(g => g.name);
              const idx = freshNames.indexOf(groupName);
              if (idx < 0 || idx >= freshNames.length - 1) return;
              const reordered = [...freshNames];
              const tmp = reordered[idx + 1] as string;
              reordered[idx + 1] = reordered[idx] as string;
              reordered[idx] = tmp;
              await ReorderGroups(reordered);
              onGroupsChanged({ newName: groupName });
            } catch (e) {
              console.error("ReorderGroups (down) failed:", e);
            }
          }}
          onDelete={() => {
            onDeleteGroup(contextMenu.group);
            setContextMenu(null);
          }}
          onClose={() => setContextMenu(null)}
        />
      )}

      {groupDialog && (
        <GroupEditDialog
          mode={groupDialog.mode}
          initialName={groupDialog.initialName}
          initialIcon={groupDialog.initialIcon}
          groups={groups.map(g => g.name)}
          onGroupsChanged={(info) => {
            onGroupsChanged(info);
            setGroupDialog(null);
          }}
          onClose={() => setGroupDialog(null)}
        />
      )}
    </>
  );
}
