// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import i18n from "../i18n";
import {
  GetVaultStatus,
  SetPassword,
  ChangeVaultPassword,
  RemovePassword,
  GetSetting,
  SetSetting,
  GetBackupSettings,
  SetBackupSettings,
  PickBackupDir,
  ExportNow,
} from "../../wailsjs/go/main/App";
import { useTheme } from "../hooks/useTheme";
import { useDensity } from "../hooks/useDensity";
import { goErrorToKey } from "../utils/errorKeys";
import { extractErrorMessage } from "../utils/extractErrorMessage";
import appIcon from "../assets/images/app-icon.png";

interface SettingsPageProps {
  showBanner?: boolean;
  onDismissBanner?: () => void;
  onPasswordSet?: () => void;
  onPasswordRemoved?: () => void;
  onAutoLockChange?: (val: string) => void;
}

export function SettingsPage({
  showBanner,
  onDismissBanner,
  onPasswordSet,
  onPasswordRemoved,
  onAutoLockChange,
}: SettingsPageProps) {
  const { t } = useTranslation();
  const { theme, toggleTheme } = useTheme();
  const { density, setDensity } = useDensity();
  const [vaultEnabled, setVaultEnabled] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Set password form
  const [password, setPasswordField] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  // Change password form
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");

  // Remove password form
  const [removePassword, setRemovePassword] = useState("");

  // Language selector state
  const [currentLang, setCurrentLang] = useState(i18n.language);

  // Auto-lock timeout state
  const [autoLockTimeout, setAutoLockTimeout] = useState("never");

  // Clipboard clear timeout state
  const [clipboardTimeout, setClipboardTimeout] = useState("30");

  // Backup state
  const [backupDir, setBackupDir] = useState("");
  const [backupSchedule, setBackupSchedule] = useState("off");
  const [backupRetention, setBackupRetention] = useState("5");
  const [backupLastBackup, setBackupLastBackup] = useState("");
  const [backupError, setBackupError] = useState("");
  const [backupSettingsLoaded, setBackupSettingsLoaded] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [exportSuccess, setExportSuccess] = useState(false);
  const [browsing, setBrowsing] = useState(false);

  useEffect(() => {
    GetVaultStatus().then((status) => setVaultEnabled(status.enabled));
    GetSetting("auto_lock_timeout")
      .then((val) => {
        if (val && ["1", "5", "15", "30", "never"].includes(val)) {
          setAutoLockTimeout(val);
        }
      })
      .catch(() => {});
    GetSetting("clipboard_clear_timeout")
      .then((val) => {
        if (val && ["10", "20", "30", "60", "never"].includes(val)) {
          setClipboardTimeout(val);
        }
      })
      .catch(() => {});
    GetBackupSettings()
      .then((bs) => {
        setBackupDir(bs.dir);
        setBackupSchedule(bs.schedule || "off");
        setBackupRetention(bs.retention || "5");
        setBackupLastBackup(bs.lastBackup);
        setBackupError(bs.lastError);
        setBackupSettingsLoaded(true);
      })
      .catch(() => {
        setBackupSettingsLoaded(true);
      });
  }, []);

  // Auto-clear success message
  useEffect(() => {
    if (!success) return;
    const timer = setTimeout(() => setSuccess(null), 3000);
    return () => clearTimeout(timer);
  }, [success]);

  function clearError() {
    if (error) setError(null);
  }

  function handleLanguageChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const lang = e.target.value;
    i18n.changeLanguage(lang);
    localStorage.setItem("language", lang);
    SetSetting("language", lang).catch(() => {}); // fire-and-forget, same pattern as sort_order
    setCurrentLang(lang);
  }

  function handleAutoLockChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const val = e.target.value;
    setAutoLockTimeout(val);
    SetSetting("auto_lock_timeout", val).catch(() => {});
    onAutoLockChange?.(val);
  }

  function handleClipboardTimeoutChange(
    e: React.ChangeEvent<HTMLSelectElement>
  ) {
    const val = e.target.value;
    setClipboardTimeout(val);
    SetSetting("clipboard_clear_timeout", val).catch(() => {});
  }

  async function handleBrowse() {
    if (browsing) return;
    setBrowsing(true);
    setBackupError("");
    try {
      const dir = await PickBackupDir();
      if (dir) {
        setBackupDir(dir);
      }
    } catch (err: unknown) {
      const raw = extractErrorMessage(err);
      if (!raw.includes("cancel")) {
        setBackupError(t(goErrorToKey(raw, "settings.backupBrowseError")));
      }
    } finally {
      setBrowsing(false);
    }
  }

  function handleScheduleChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const val = e.target.value;
    setBackupSchedule(val);
    SetBackupSettings(val, backupRetention).catch(() => {});
  }

  function handleRetentionChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const val = e.target.value;
    setBackupRetention(val);
    SetBackupSettings(backupSchedule, val).catch(() => {});
  }

  async function handleExportNow() {
    if (exporting) return;
    setExporting(true);
    setBackupError("");
    try {
      await ExportNow();
      setExportSuccess(true);
      GetBackupSettings()
        .then((bs) => {
          setBackupLastBackup(bs.lastBackup);
          setBackupError(bs.lastError);
        })
        .catch(() => {});
      setTimeout(() => setExportSuccess(false), 2500);
    } catch (err: unknown) {
      setBackupError(
        t(goErrorToKey(extractErrorMessage(err), "settings.backupExportError"))
      );
    } finally {
      setExporting(false);
    }
  }

  async function handleSetPassword(e: React.FormEvent) {
    e.preventDefault();
    if (!password || password !== confirmPassword || saving) return;
    setSaving(true);
    setError(null);
    try {
      await SetPassword(password);
      setVaultEnabled(true);
      setSuccess(t("settings.setPasswordSuccess"));
      setPasswordField("");
      setConfirmPassword("");
      onPasswordSet?.();
    } catch (err: unknown) {
      setError(
        t(goErrorToKey(extractErrorMessage(err), "settings.setPasswordError"))
      );
    } finally {
      setSaving(false);
    }
  }

  async function handleChangePassword(e: React.FormEvent) {
    e.preventDefault();
    if (
      !currentPassword ||
      !newPassword ||
      newPassword !== confirmNewPassword ||
      saving
    )
      return;
    setSaving(true);
    setError(null);
    try {
      await ChangeVaultPassword(currentPassword, newPassword);
      setSuccess(t("settings.changePasswordSuccess"));
      setCurrentPassword("");
      setNewPassword("");
      setConfirmNewPassword("");
    } catch (err: unknown) {
      setError(
        t(
          goErrorToKey(extractErrorMessage(err), "settings.changePasswordError")
        )
      );
    } finally {
      setSaving(false);
    }
  }

  async function handleRemovePassword(e: React.FormEvent) {
    e.preventDefault();
    if (!removePassword || saving) return;
    setSaving(true);
    setError(null);
    try {
      await RemovePassword(removePassword);
      setVaultEnabled(false);
      onPasswordRemoved?.();
      setSuccess(t("settings.removePasswordSuccess"));
      setRemovePassword("");
    } catch (err: unknown) {
      setError(
        t(
          goErrorToKey(extractErrorMessage(err), "settings.removePasswordError")
        )
      );
    } finally {
      setSaving(false);
    }
  }

  const inputClass =
    "w-full px-4 py-2.5 bg-surface-container-lowest rounded-lg text-sm text-on-surface placeholder:text-outline/50 focus:outline-none focus:ring-1 focus:ring-primary/40 disabled:opacity-50 mb-3";

  return (
    <div className="flex-1 overflow-y-auto p-8 max-w-[1600px] mx-auto w-full">
      {showBanner && (
        <div className="max-w-lg mx-auto flex items-start gap-3 p-4 rounded-lg bg-surface-container-high border-l-4 border-l-warning mb-8">
          <span className="text-lg select-none shrink-0">
            {"\uD83D\uDD12"}
          </span>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-on-surface">
              {t("settings.bannerTitle")}
            </p>
            <p className="text-xs text-outline mt-1">
              {t("settings.bannerDesc")}{" "}
              <button
                onClick={() =>
                  document
                    .getElementById("security-section")
                    ?.scrollIntoView({ behavior: "smooth" })
                }
                className="text-primary hover:text-primary/80 underline bg-transparent border-none cursor-pointer p-0 text-xs"
              >
                {t("settings.bannerLink")}
              </button>{" "}
              {t("settings.bannerDescSuffix")}
            </p>
          </div>
          <button
            onClick={onDismissBanner}
            className="shrink-0 p-1 rounded text-outline hover:text-on-surface hover:bg-surface-container-high bg-transparent border-none cursor-pointer transition-colors"
            aria-label={t("settings.bannerDismiss")}
            title={t("settings.bannerDismiss")}
          >
            {"\u2715"}
          </button>
        </div>
      )}

      {/* Page heading */}
      <div style={{ marginBottom: 'var(--density-section-gap)' }}>
        <h2 className="font-extrabold text-on-surface mb-2 font-headline" style={{ fontSize: 'var(--text-page-title)', lineHeight: 'var(--lh-page-title)' }}>
          {t("settings.vaultConfigTitle")}
        </h2>
        <p className="text-outline">{t("settings.vaultConfigSubtitle")}</p>
      </div>

      {/* Flat grid — all four sections are direct grid children */}
      <div
        className="grid grid-cols-1 lg:grid-cols-12"
        style={{ gap: 'var(--density-section-gap)' }}
      >

          {/* PERSONALISATION SECTION */}
          <section
            className="card-surface lg:col-span-7 lg:row-start-1"
            style={{ padding: 'var(--density-card-py) var(--density-card-px)' }}
          >
            <div className="flex items-center gap-3" style={{ marginBottom: 'var(--density-card-gap)' }}>
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="20"
                height="20"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="text-primary"
              >
                <circle cx="13.5" cy="6.5" r=".5" />
                <circle cx="17.5" cy="10.5" r=".5" />
                <circle cx="8.5" cy="7.5" r=".5" />
                <circle cx="6.5" cy="12.5" r=".5" />
                <path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z" />
              </svg>
              <h3 className="text-xl font-bold font-headline text-on-surface">
                {t("settings.personalisation")}
              </h3>
            </div>
            <div className="space-y-6">
              {/* Theme row */}
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-semibold text-on-surface">{t("settings.theme")}</p>
                  <p className="text-xs text-outline">{t("settings.themeDesc")}</p>
                </div>
                <div className="flex bg-surface-container-lowest p-1 rounded-lg">
                  <button
                    onClick={() => theme !== "dark" && toggleTheme()}
                    className={
                      theme === "dark"
                        ? "px-4 py-1.5 text-xs font-bold rounded-md bg-surface-container-high text-primary shadow-sm"
                        : "px-4 py-1.5 text-xs font-bold rounded-md text-outline hover:text-on-surface transition-colors"
                    }
                  >
                    {t("settings.themeDark")}
                  </button>
                  <button
                    onClick={() => theme !== "light" && toggleTheme()}
                    className={
                      theme === "light"
                        ? "px-4 py-1.5 text-xs font-bold rounded-md bg-surface-container-high text-primary shadow-sm"
                        : "px-4 py-1.5 text-xs font-bold rounded-md text-outline hover:text-on-surface transition-colors"
                    }
                  >
                    {t("settings.themeLight")}
                  </button>
                </div>
              </div>

              {/* Language row */}
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-semibold text-on-surface">{t("settings.language")}</p>
                  <p className="text-xs text-outline">{t("settings.languageDesc")}</p>
                </div>
                <select
                  value={currentLang}
                  onChange={handleLanguageChange}
                  className="select-card bg-surface-container-lowest border-none rounded-lg text-sm px-4 py-2 focus:ring-1 focus:ring-primary/40 min-w-[140px]"
                >
                  <option value="en">{t("settings.languageEnglish")}</option>
                  <option value="es">{t("settings.languageSpanish")}</option>
                </select>
              </div>

              {/* Density row */}
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-semibold text-on-surface">{t("settings.displayDensity")}</p>
                  <p className="text-xs text-outline">{t("settings.displayDensityDesc")}</p>
                </div>
                <div className="flex bg-surface-container-lowest p-1 rounded-lg">
                  {(["compact", "default", "comfortable"] as const).map((option) => (
                    <button
                      key={option}
                      onClick={() => setDensity(option)}
                      className={
                        density === option
                          ? "px-3 py-1.5 text-xs font-bold rounded-md bg-surface-container-high text-primary shadow-sm"
                          : "px-3 py-1.5 text-xs font-bold rounded-md text-outline hover:text-on-surface transition-colors"
                      }
                    >
                      {option === "compact"
                        ? t("settings.densityCompact")
                        : option === "comfortable"
                          ? t("settings.densityComfortable")
                          : t("settings.densityDefault")}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </section>

          {/* SECURITY SECTION */}
          <section
            className="card-surface lg:col-start-8 lg:col-span-5 lg:row-start-1 lg:row-span-2"
            style={{ padding: 'var(--density-card-py) var(--density-card-px)' }}
          >
            <div className="flex items-center gap-3" style={{ marginBottom: 'var(--density-card-gap)' }}>
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="20"
                height="20"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="text-primary"
              >
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              <h3 className="text-xl font-bold font-headline text-on-surface">
                {t("settings.security")}
              </h3>
            </div>

            <div className="space-y-6">
              {/* Scroll anchor for banner link */}
              <div id="security-section" />

              {/* Password form status messages */}
              {error && (
                <div className="rounded-lg px-4 py-3 bg-surface-container border border-error/30 text-sm text-error mb-3">
                  {error}
                </div>
              )}
              {success && (
                <div className="rounded-lg px-4 py-3 bg-surface-container border border-success/30 text-sm text-success mb-3">
                  {success}
                </div>
              )}

              {!vaultEnabled ? (
                /* Set Password card */
                <div className="bg-surface-container p-6 rounded-lg border-l-4 border-primary">
                  <h4 className="text-sm font-bold uppercase tracking-widest text-primary mb-4">
                    {t("settings.setPasswordHeading")}
                  </h4>
                  <p className="text-xs text-outline mb-4">{t("settings.setPasswordDesc")}</p>
                  <form onSubmit={handleSetPassword}>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <input
                        type="password"
                        value={password}
                        onChange={(e) => {
                          setPasswordField(e.target.value);
                          clearError();
                        }}
                        placeholder={t("settings.setPasswordNew")}
                        disabled={saving}
                        className={inputClass}
                        autoComplete="off"
                      />
                      <input
                        type="password"
                        value={confirmPassword}
                        onChange={(e) => {
                          setConfirmPassword(e.target.value);
                          clearError();
                        }}
                        placeholder={t("settings.setPasswordConfirm")}
                        disabled={saving}
                        className={inputClass}
                        autoComplete="off"
                      />
                    </div>
                    {confirmPassword.length > 0 && password !== confirmPassword && (
                      <p className="text-sm text-error mb-3">
                        {t("settings.setPasswordMismatch")}
                      </p>
                    )}
                    <button
                      type="submit"
                      disabled={
                        saving ||
                        !password ||
                        !confirmPassword ||
                        password !== confirmPassword
                      }
                      className="mt-4 px-6 py-2.5 bg-gradient-to-br from-primary to-primary-container text-on-primary rounded-lg font-bold text-sm transition-all hover:opacity-90 active:scale-95 disabled:opacity-50"
                    >
                      {saving
                        ? t("settings.setPasswordSubmitting")
                        : t("settings.setPasswordSubmit")}
                    </button>
                  </form>
                </div>
              ) : (
                /* Change Password + Remove Password cards */
                <>
                  <div className="bg-surface-container p-6 rounded-lg border-l-4 border-primary">
                    <h4 className="text-sm font-bold uppercase tracking-widest text-primary mb-4">
                      {t("settings.changePasswordHeading")}
                    </h4>
                    <form onSubmit={handleChangePassword}>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <input
                          type="password"
                          value={currentPassword}
                          onChange={(e) => {
                            setCurrentPassword(e.target.value);
                            clearError();
                          }}
                          placeholder={t("settings.changePasswordCurrent")}
                          disabled={saving}
                          className={inputClass}
                          autoComplete="off"
                        />
                        <input
                          type="password"
                          value={newPassword}
                          onChange={(e) => {
                            setNewPassword(e.target.value);
                            clearError();
                          }}
                          placeholder={t("settings.changePasswordNew")}
                          disabled={saving}
                          className={inputClass}
                          autoComplete="off"
                        />
                        <input
                          type="password"
                          value={confirmNewPassword}
                          onChange={(e) => {
                            setConfirmNewPassword(e.target.value);
                            clearError();
                          }}
                          placeholder={t("settings.changePasswordConfirm")}
                          disabled={saving}
                          className={inputClass}
                          autoComplete="off"
                        />
                      </div>
                      {confirmNewPassword.length > 0 &&
                        newPassword !== confirmNewPassword && (
                          <p className="text-sm text-error mb-3">
                            {t("settings.changePasswordMismatch")}
                          </p>
                        )}
                      <button
                        type="submit"
                        disabled={
                          saving ||
                          !currentPassword ||
                          !newPassword ||
                          !confirmNewPassword ||
                          newPassword !== confirmNewPassword
                        }
                        className="mt-4 px-6 py-2.5 bg-gradient-to-br from-primary to-primary-container text-on-primary rounded-lg font-bold text-sm transition-all hover:opacity-90 active:scale-95 disabled:opacity-50"
                      >
                        {saving
                          ? t("settings.changePasswordSubmitting")
                          : t("settings.changePasswordSubmit")}
                      </button>
                    </form>
                  </div>

                  <div className="bg-surface-container p-6 rounded-lg border-l-4 border-primary">
                    <h4 className="text-sm font-bold uppercase tracking-widest text-primary mb-4">
                      {t("settings.removePasswordHeading")}
                    </h4>
                    <p className="text-xs text-outline mb-4">{t("settings.removePasswordDesc")}</p>
                    <form onSubmit={handleRemovePassword}>
                      <input
                        type="password"
                        value={removePassword}
                        onChange={(e) => {
                          setRemovePassword(e.target.value);
                          clearError();
                        }}
                        placeholder={t("settings.removePasswordCurrent")}
                        disabled={saving}
                        className={inputClass}
                        autoComplete="off"
                      />
                      <button
                        type="submit"
                        disabled={saving || !removePassword}
                        className="mt-4 px-6 py-2.5 bg-error text-on-primary rounded-lg font-bold text-sm transition-all hover:brightness-110 active:scale-95 disabled:opacity-50"
                      >
                        {saving
                          ? t("settings.removePasswordSubmitting")
                          : t("settings.removePasswordSubmit")}
                      </button>
                    </form>
                  </div>
                </>
              )}

              {/* Auto-lock row */}
              <div className={`flex items-center justify-between ${!vaultEnabled ? "opacity-50" : ""}`}>
                <div>
                  <p className="font-semibold text-on-surface">{t("settings.autoLock")}</p>
                  <p className="text-xs text-outline">{t("settings.autoLockDesc")}</p>
                </div>
                <select
                  value={autoLockTimeout}
                  onChange={handleAutoLockChange}
                  disabled={!vaultEnabled}
                  className="select-card bg-surface-container-lowest border-none rounded-lg text-sm px-4 py-2 focus:ring-1 focus:ring-primary/40 min-w-[140px]"
                >
                  <option value="1">{t("settings.autoLock1min")}</option>
                  <option value="5">{t("settings.autoLock5min")}</option>
                  <option value="15">{t("settings.autoLock15min")}</option>
                  <option value="30">{t("settings.autoLock30min")}</option>
                  <option value="never">{t("settings.autoLockNever")}</option>
                </select>
              </div>

              {/* Clipboard clear row */}
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-semibold text-on-surface">{t("settings.clipboardClear")}</p>
                  <p className="text-xs text-outline">{t("settings.clipboardClearDesc")}</p>
                </div>
                <select
                  value={clipboardTimeout}
                  onChange={handleClipboardTimeoutChange}
                  className="select-card bg-surface-container-lowest border-none rounded-lg text-sm px-4 py-2 focus:ring-1 focus:ring-primary/40 min-w-[140px]"
                >
                  <option value="10">{t("settings.clipboardClear10s")}</option>
                  <option value="20">{t("settings.clipboardClear20s")}</option>
                  <option value="30">{t("settings.clipboardClear30s")}</option>
                  <option value="60">{t("settings.clipboardClear60s")}</option>
                  <option value="never">{t("settings.clipboardClearNever")}</option>
                </select>
              </div>
            </div>
          </section>

          {/* BACKUP SECTION */}
          <section
            className="card-surface lg:col-span-7 lg:row-start-2"
            style={{ padding: 'var(--density-card-py) var(--density-card-px)' }}
          >
            <div className="flex items-center gap-3" style={{ marginBottom: 'var(--density-card-gap)' }}>
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="20"
                height="20"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="text-primary"
              >
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                <polyline points="7 10 12 15 17 10" />
                <line x1="12" y1="15" x2="12" y2="3" />
              </svg>
              <h3 className="text-xl font-bold font-headline text-on-surface">
                {t("settings.backup")}
              </h3>
            </div>
            <div className="space-y-6">
              {/* Last backup status card */}
              <div className="p-4 bg-surface-container-lowest rounded-lg border border-outline-variant/10">
                <div className="flex justify-between items-start mb-3">
                  <div>
                    <p className="text-[10px] uppercase font-bold tracking-tighter text-outline mb-1">
                      {t("settings.backupLastBackup")}
                    </p>
                    <p className="text-sm font-mono text-secondary tabular-nums">
                      {backupLastBackup || t("settings.backupLastBackupNever")}
                    </p>
                  </div>
                </div>
                <button
                  onClick={handleExportNow}
                  disabled={!backupDir || exporting}
                  className="w-full py-2 bg-surface-container-highest text-on-surface text-xs font-bold rounded-md hover:bg-outline-variant/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-1.5"
                >
                  {exporting ? (
                    <>
                      <svg
                        className="animate-spin h-3.5 w-3.5"
                        viewBox="0 0 24 24"
                        fill="none"
                      >
                        <circle
                          className="opacity-25"
                          cx="12"
                          cy="12"
                          r="10"
                          stroke="currentColor"
                          strokeWidth="4"
                        />
                        <path
                          className="opacity-75"
                          fill="currentColor"
                          d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                        />
                      </svg>
                      {t("settings.backupExporting")}
                    </>
                  ) : exportSuccess ? (
                    t("settings.backupExported")
                  ) : (
                    t("settings.backupExportNow")
                  )}
                </button>
              </div>

              {/* Directory row */}
              <div>
                <label className="text-xs font-semibold text-outline block mb-1.5">
                  {t("settings.backupDirectory")}
                </label>
                <div className="flex gap-2">
                  <div className="flex-1 bg-surface-container-lowest px-3 py-2 rounded-lg text-xs font-mono text-outline truncate">
                    {backupDir || t("settings.backupDirectoryNone")}
                  </div>
                  <button
                    onClick={handleBrowse}
                    disabled={browsing}
                    className="px-3 py-2 bg-surface-container-high text-on-surface text-xs font-bold rounded-lg hover:bg-surface-container-highest transition-colors disabled:opacity-50"
                  >
                    {t("settings.backupBrowse")}
                  </button>
                </div>
              </div>

              {/* Backup error */}
              {backupError && (
                <div className="rounded-lg px-4 py-3 bg-surface-container border border-error/30 text-xs text-error">
                  {backupError}
                </div>
              )}

              {/* Schedule + Retention side-by-side */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-semibold text-outline block mb-1.5">
                    {t("settings.backupSchedule")}
                  </label>
                  <select
                    value={backupSchedule}
                    onChange={handleScheduleChange}
                    disabled={!backupSettingsLoaded}
                    className="select-card w-full bg-surface-container-lowest border-none rounded-lg text-sm px-4 py-2 focus:ring-1 focus:ring-primary/40"
                  >
                    <option value="off">{t("settings.backupScheduleOff")}</option>
                    <option value="daily">{t("settings.backupScheduleDaily")}</option>
                    <option value="weekly">{t("settings.backupScheduleWeekly")}</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs font-semibold text-outline block mb-1.5">
                    {t("settings.backupRetention")}
                  </label>
                  <select
                    value={backupRetention}
                    onChange={handleRetentionChange}
                    disabled={!backupSettingsLoaded}
                    className="select-card w-full bg-surface-container-lowest border-none rounded-lg text-sm px-4 py-2 focus:ring-1 focus:ring-primary/40"
                  >
                    <option value="3">{t("settings.backupRetention3")}</option>
                    <option value="5">{t("settings.backupRetention5")}</option>
                    <option value="10">{t("settings.backupRetention10")}</option>
                  </select>
                </div>
              </div>
            </div>
          </section>

          {/* ABOUT SECTION */}
          <section
            className="bg-primary-container/10 rounded-xl relative overflow-hidden lg:col-start-8 lg:col-span-5 lg:row-start-3"
            style={{ padding: 'var(--density-card-py) var(--density-card-px)' }}
          >
            <div className="absolute -right-10 -top-10 w-32 h-32 bg-primary/10 rounded-full blur-3xl" />
            <div className="relative z-10 flex flex-col items-center text-center">
              <img src={appIcon} alt="deskOTP app icon" className="w-16 h-16 object-contain mb-4" />
              <h3 className="text-2xl font-black font-headline text-primary tracking-tighter uppercase mb-1">
                deskOTP
              </h3>
              <p className="text-sm font-bold text-on-surface/70 mb-6">
                Open Source 2FA Manager
              </p>
              <div className="w-full pt-6 border-t border-primary/10 space-y-1">
                <div className="flex justify-between text-[11px] font-bold uppercase tracking-widest text-outline">
                  <span>{t("settings.version")}</span>
                  <span className="text-primary">{__APP_VERSION__}</span>
                </div>
                <p className="text-[10px] text-outline/50 mt-4 italic">
                  {t("settings.copyright")}
                </p>
              </div>
            </div>
          </section>
      </div>
    </div>
  );
}
