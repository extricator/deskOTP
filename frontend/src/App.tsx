// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useCallback, useEffect, useMemo, useRef } from "react";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { useTranslation } from "react-i18next";
import {
  DeleteEntry,
  DeleteGroup,
  UndoDelete,
  GetVaultStatus,
  GetSetting,
  SetSetting,
  GetEntryGroups,
} from "../wailsjs/go/main/App";
import { ImportCounts } from "./types";
import { ImportAreaHandle } from "./components/ImportArea";
import { useCodeStore } from "./hooks/useCodeStore";
import { useIdleLock } from "./hooks/useIdleLock";
import { useToast } from "./hooks/useToast";
import { useAppSettings } from "./hooks/useAppSettings";
import { useVaultState } from "./hooks/useVaultState";
import { NavBar } from "./components/NavBar";
import { Sidebar } from "./components/Sidebar";
import { TokensPage } from "./components/TokensPage";
import { EditDialog } from "./components/EditDialog";
import { ConfirmDialog } from "./components/ConfirmDialog";
import { UndoToast } from "./components/UndoToast";
import { ImportResultDialog } from "./components/ImportResultDialog";
import { FileQRFlow } from "./components/FileQRFlow";
import { ManualEntryFlow } from "./components/ManualEntryFlow";
import { URIPasteFlow } from "./components/URIPasteFlow";
import { ScreenCaptureQRFlow } from "./components/ScreenCaptureQRFlow";
import { AddTokenDialog } from "./components/AddTokenDialog";
import { SettingsPage } from "./components/SettingsPage";
import { UnlockScreen } from "./components/UnlockScreen";
import "./App.css";

type Page = "tokens" | "settings";

interface GroupData {
  name: string;
  icon?: string;
}

function App() {
  const { t } = useTranslation();
  const { entries, ready, resetReady } = useCodeStore();
  const {
    vaultStatus,
    setVaultStatus,
    handleLock,
    handlePasswordSet,
    handlePasswordRemoved,
  } = useVaultState(resetReady);
  const {
    nudgeDismissed,
    setNudgeDismissed,
    sortOrder,
    sortDirection,
    autoLockTimeout,
    handleSortChange,
    handleAutoLockChange,
  } = useAppSettings();
  const {
    undoToast,
    lockMessage,
    clipboardCleared,
    showLockMessage,
    showUndoToast,
    dismissUndoToast,
  } = useToast();

  const importRef = useRef<ImportAreaHandle>(null);
  const [importResult, setImportResult] = useState<ImportCounts | null>(null);
  const [showEncryptionNudge, setShowEncryptionNudge] = useState(false);
  const [activePage, setActivePage] = useState<Page>("tokens");
  const [editingEntryId, setEditingEntryId] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<{
    id: string;
    name: string;
  } | null>(null);
  const [confirmDeleteGroup, setConfirmDeleteGroup] = useState<string | null>(null);
  const [showAddToken, setShowAddToken] = useState(false);
  const [showFileQR, setShowFileQR] = useState(false);
  const [showManualEntry, setShowManualEntry] = useState(false);
  const [showURIPaste, setShowURIPaste] = useState(false);
  const [showScreenCapture, setShowScreenCapture] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedGroup, setSelectedGroup] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [groups, setGroups] = useState<GroupData[]>([]);

  // Stable fingerprint: only changes when entries are added/removed/edited,
  // not on every codes:tick (which only updates code + remaining).
  const entryFingerprint = useMemo(
    () => entries.map((e) => `${e.id}:${e.issuer}:${e.name}:${e.group}`).join("\n"),
    [entries]
  );

  // Load groups only when the entry set actually changes
  useEffect(() => {
    GetEntryGroups().then((g) => setGroups(g || [])).catch(() => {});
  }, [entryFingerprint]);

  // Reset to "All" if selected group no longer exists
  useEffect(() => {
    if (selectedGroup && !groups.some(g => g.name === selectedGroup)) {
      setSelectedGroup("");
    }
  }, [groups, selectedGroup]);

  const handleGroupsChanged = useCallback(async (info: { oldName?: string; newName: string }) => {
    // RNAM-03: sync active filter on rename BEFORE updating groups list
    // This prevents the useEffect from resetting selectedGroup to ""
    if (info.oldName && selectedGroup === info.oldName) {
      setSelectedGroup(info.newName);
    }
    const updated = await GetEntryGroups();
    setGroups(updated || []);
  }, [selectedGroup]);

  const handleConfirmDelete = useCallback(async () => {
    if (!confirmDelete) return;
    const { id, name } = confirmDelete;
    setConfirmDelete(null);
    showUndoToast(name);
    try {
      await DeleteEntry(id);
    } catch (e: unknown) {
      console.error("DeleteEntry failed:", e instanceof Error ? e.message : e);
      dismissUndoToast();
    }
  }, [confirmDelete, showUndoToast, dismissUndoToast]);

  const handleConfirmDeleteGroup = useCallback(async () => {
    if (!confirmDeleteGroup) return;
    const groupName = confirmDeleteGroup;
    setConfirmDeleteGroup(null);
    // D-05: reset filter BEFORE delete to avoid blank token view
    if (selectedGroup === groupName) {
      setSelectedGroup("");
    }
    try {
      await DeleteGroup(groupName);
      const updated = await GetEntryGroups();
      setGroups(updated || []);
    } catch (e: unknown) {
      console.error("DeleteGroup failed:", e instanceof Error ? e.message : e);
    }
  }, [confirmDeleteGroup, selectedGroup]);

  const handleDismissToast = useCallback(() => {
    dismissUndoToast();
  }, [dismissUndoToast]);

  const handleUndo = useCallback(async () => {
    try {
      await UndoDelete();
    } catch (e: unknown) {
      console.error("UndoDelete failed:", e instanceof Error ? e.message : e);
    }
    dismissUndoToast();
  }, [dismissUndoToast]);

  const handleImportResult = useCallback(async (counts: ImportCounts) => {
    setImportResult(counts);
    const status = await GetVaultStatus();
    if (status.enabled) {
      setShowEncryptionNudge(false);
      return;
    }
    const dismissed = await GetSetting("nudge_dismissed");
    if (dismissed === "true") {
      setShowEncryptionNudge(false);
      return;
    }
    setShowEncryptionNudge(true);
  }, []);

  const handleSetupEncryption = useCallback(() => {
    setImportResult(null);
    setShowEncryptionNudge(false);
    setNudgeDismissed(true);
    setActivePage("settings");
    SetSetting("nudge_dismissed", "true").catch(() => {});
  }, [setNudgeDismissed]);

  const showSecurityNudge =
    vaultStatus !== null &&
    !vaultStatus.enabled &&
    entries.length > 0 &&
    nudgeDismissed === false;

  const handleDismissNudge = useCallback(() => {
    setNudgeDismissed(true);
    SetSetting("nudge_dismissed", "true").catch(() => {});
  }, [setNudgeDismissed]);

  const handleLockDisabled = useCallback(() => {
    showLockMessage();
  }, [showLockMessage]);

  const isVaultUnlocked =
    vaultStatus !== null && vaultStatus.enabled && vaultStatus.unlocked;
  useIdleLock(isVaultUnlocked, autoLockTimeout);

  const dialogFallback =
    (onClose: () => void) =>
    ({
      resetErrorBoundary,
    }: {
      error: Error;
      resetErrorBoundary: () => void;
    }) => (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
        <div className="bg-[rgb(var(--color-modal-bg))] rounded-2xl shadow-card p-6 w-full max-w-sm mx-4">
          <p className="mb-4 text-[rgb(var(--color-text-primary))]">
            This dialog encountered an error
          </p>
          <button
            aria-label="Close dialog"
            onClick={() => {
              resetErrorBoundary();
              onClose();
            }}
            className="px-4 py-2 rounded-lg bg-gradient-to-br from-primary to-primary-container text-on-primary hover:opacity-90 cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    );

  // Wait for vault status before rendering anything
  if (vaultStatus === null) {
    return <div className="h-screen bg-[rgb(var(--color-bg))]" />;
  }

  // Show unlock screen when vault is locked
  if (vaultStatus.enabled && !vaultStatus.unlocked) {
    return (
      <UnlockScreen
        onUnlocked={() => {
          setVaultStatus({ enabled: true, unlocked: true });
        }}
      />
    );
  }

  return (
    <div id="app-content" className="flex h-screen overflow-hidden bg-bg text-text-primary font-sans">
      {/* Sidebar — always visible on lg+, toggleable on mobile */}
      <Sidebar
        activePage={activePage}
        onNavigate={setActivePage}
        groups={groups}
        selectedGroup={selectedGroup}
        onGroupChange={setSelectedGroup}
        onAddToken={() => setShowAddToken(true)}
        open={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
        onGroupsChanged={handleGroupsChanged}
        onDeleteGroup={(groupName) => setConfirmDeleteGroup(groupName)}
      />

      {/* Full-width top navbar */}
      <NavBar
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        onToggleSidebar={() => setSidebarOpen((o) => !o)}
        onResult={handleImportResult}
        vaultEnabled={vaultStatus.enabled}
        onLock={handleLock}
        onLockDisabled={handleLockDisabled}
        showBadge={showSecurityNudge}
        activePage={activePage}
        onNavigate={setActivePage}
        importRef={importRef}
      />

      {/* Main content — below navbar, offset past sidebar on lg+ */}
      <div className="flex-1 flex flex-col min-h-0 lg:ml-sidebar" style={{ paddingTop: 'var(--navbar-height)' }}>
        {/* Tokens page */}
        {activePage === "tokens" && (
          <TokensPage
            entries={entries}
            ready={ready}
            sortOrder={sortOrder}
            sortDirection={sortDirection}
            onSortChange={handleSortChange}
            onEdit={(entryId) => setEditingEntryId(entryId)}
            onDelete={(entryId, name) => setConfirmDelete({ id: entryId, name })}
            searchQuery={searchQuery}
            onOpenAddToken={() => setShowAddToken(true)}
            selectedGroup={selectedGroup}
            onGroupChange={setSelectedGroup}
          />
        )}

        {/* Settings page */}
        {activePage === "settings" && (
          <div className="flex-1 flex flex-col min-h-0">
            <SettingsPage
              showBanner={showSecurityNudge}
              onDismissBanner={handleDismissNudge}
              onPasswordSet={handlePasswordSet}
              onPasswordRemoved={handlePasswordRemoved}
              onAutoLockChange={handleAutoLockChange}
            />
          </div>
        )}
      </div>

      {/* Add Token dialog */}
      {showAddToken && (
        <ErrorBoundary
          fallbackRender={dialogFallback(() => setShowAddToken(false))}
        >
          <AddTokenDialog
            onSelectManual={() => {
              setShowAddToken(false);
              setShowManualEntry(true);
            }}
            onSelectScanFile={() => {
              setShowAddToken(false);
              setShowFileQR(true);
            }}
            onSelectScanScreen={() => {
              setShowAddToken(false);
              setShowScreenCapture(true);
            }}
            onSelectPasteURI={() => {
              setShowAddToken(false);
              setShowURIPaste(true);
            }}
            onImportBackup={async () => {
              const picked = await importRef.current?.triggerImport();
              if (picked) setShowAddToken(false);
            }}
            onClose={() => setShowAddToken(false)}
          />
        </ErrorBoundary>
      )}

      {importResult && (
        <ErrorBoundary
          fallbackRender={dialogFallback(() => {
            setImportResult(null);
            setShowEncryptionNudge(false);
          })}
        >
          <ImportResultDialog
            added={importResult.added}
            skipped={importResult.skipped}
            format={importResult.format}
            onClose={() => {
              setImportResult(null);
              setShowEncryptionNudge(false);
            }}
            showEncryptionNotice={showEncryptionNudge}
            onSetupEncryption={handleSetupEncryption}
          />
        </ErrorBoundary>
      )}

      {editingEntryId && (
        <ErrorBoundary
          fallbackRender={dialogFallback(() => setEditingEntryId(null))}
        >
          <EditDialog
            entryId={editingEntryId}
            onClose={() => setEditingEntryId(null)}
            onSaved={() => setEditingEntryId(null)}
          />
        </ErrorBoundary>
      )}

      {confirmDelete && (
        <ErrorBoundary
          fallbackRender={dialogFallback(() => setConfirmDelete(null))}
        >
          <ConfirmDialog
            title={t("deleteAccount.title")}
            message={t("deleteAccount.message", { name: confirmDelete.name })}
            confirmLabel={t("deleteAccount.confirm")}
            onConfirm={handleConfirmDelete}
            onCancel={() => setConfirmDelete(null)}
          />
        </ErrorBoundary>
      )}

      {confirmDeleteGroup && (
        <ErrorBoundary
          fallbackRender={dialogFallback(() => setConfirmDeleteGroup(null))}
        >
          <ConfirmDialog
            title={t("sidebar.contextMenu.confirmDeleteTitle")}
            message={t("sidebar.contextMenu.confirmDeleteMessage", { groupName: confirmDeleteGroup })}
            confirmLabel={t("sidebar.contextMenu.confirmDeleteTitle")}
            onConfirm={handleConfirmDeleteGroup}
            onCancel={() => setConfirmDeleteGroup(null)}
          />
        </ErrorBoundary>
      )}

      {undoToast && (
        <ErrorBoundary fallbackRender={dialogFallback(handleDismissToast)}>
          <UndoToast
            message={t("deleteAccount.undoMessage", { name: undoToast.name })}
            onUndo={handleUndo}
            onDismiss={handleDismissToast}
          />
        </ErrorBoundary>
      )}

      {showFileQR && (
        <ErrorBoundary
          fallbackRender={dialogFallback(() => setShowFileQR(false))}
        >
          <FileQRFlow
            onSaved={() => setShowFileQR(false)}
            onCancel={() => {
              setShowFileQR(false);
              setShowAddToken(true);
            }}
          />
        </ErrorBoundary>
      )}

      {showManualEntry && (
        <ErrorBoundary
          fallbackRender={dialogFallback(() => setShowManualEntry(false))}
        >
          <ManualEntryFlow
            onSaved={() => setShowManualEntry(false)}
            onCancel={() => {
              setShowManualEntry(false);
              setShowAddToken(true);
            }}
          />
        </ErrorBoundary>
      )}

      {showURIPaste && (
        <ErrorBoundary
          fallbackRender={dialogFallback(() => setShowURIPaste(false))}
        >
          <URIPasteFlow
            onSaved={() => setShowURIPaste(false)}
            onCancel={() => {
              setShowURIPaste(false);
              setShowAddToken(true);
            }}
          />
        </ErrorBoundary>
      )}

      {showScreenCapture && (
        <ErrorBoundary
          fallbackRender={dialogFallback(() => setShowScreenCapture(false))}
        >
          <ScreenCaptureQRFlow
            onSaved={() => setShowScreenCapture(false)}
            onCancel={() => {
              setShowScreenCapture(false);
              setShowAddToken(true);
            }}
          />
        </ErrorBoundary>
      )}

      {lockMessage && (
        <div className="fixed bottom-4 left-1/2 -translate-x-1/2 bg-[rgb(var(--color-surface))] rounded-xl px-4 py-3 shadow-card text-sm text-[rgb(var(--color-text-primary))] z-50">
          {lockMessage}
        </div>
      )}

      {clipboardCleared && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 bg-[rgb(var(--color-surface))] rounded-xl px-4 py-2 shadow-card text-sm text-[rgb(var(--color-text-primary))]">
          {t("clipboard.cleared")}
        </div>
      )}
    </div>
  );
}

export default App;
