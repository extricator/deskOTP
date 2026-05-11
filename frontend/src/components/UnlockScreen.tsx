// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useRef, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { UnlockVault } from "../../wailsjs/go/main/App";
import { extractErrorMessage } from "../utils/extractErrorMessage";
import appIcon from "../assets/images/app-icon.png";

interface UnlockScreenProps {
  onUnlocked: () => void;
}

export function UnlockScreen({ onUnlocked }: UnlockScreenProps) {
  const { t } = useTranslation();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [unlocking, setUnlocking] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!password.trim() || unlocking) return;

    setUnlocking(true);
    setError(null);
    try {
      await UnlockVault(password);
      onUnlocked();
    } catch (err: unknown) {
      const raw = extractErrorMessage(err);
      if (raw === "incorrect password") {
        setError(t("unlockScreen.incorrectPassword"));
      } else {
        setError(t("unlockScreen.genericError"));
      }
      setPassword("");
    } finally {
      setUnlocking(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg">
      <div className="w-full max-w-md mx-4 flex flex-col items-center space-y-8">
        {/* Branded header */}
        <div className="flex flex-col items-center space-y-3">
          <img src={appIcon} alt="deskOTP app icon" className="w-16 h-16 object-contain" />
          {/* Brand wordmark */}
          <h1 className="text-2xl font-black font-headline text-primary tracking-tighter uppercase">
            {t("common.appName")}
          </h1>
          {/* Version badge */}
          <div className="text-[10px] font-bold uppercase tracking-widest text-outline bg-surface-container-low px-2 py-0.5 rounded">
            v{__APP_VERSION__}
          </div>
        </div>

        {/* Glass gradient panel */}
        <div className="w-full rounded-2xl bg-surface-container p-8 relative overflow-hidden">
          {/* Gradient overlay */}
          <div className="absolute inset-0 card-surface rounded-2xl pointer-events-none" />
          {/* Content above gradient */}
          <div className="relative z-10 flex flex-col space-y-6">
            {/* Heading */}
            <div className="text-center space-y-2">
              <h2 className="text-2xl font-bold font-headline text-on-surface">
                {t("unlockScreen.vaultLocked")}
              </h2>
              <p className="text-sm text-outline">
                {t("unlockScreen.description")}
              </p>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit} className="flex flex-col space-y-4">
              {/* Password input with visibility toggle */}
              <div>
                <div className="relative">
                  <input
                    ref={inputRef}
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => { setPassword(e.target.value); setError(null); }}
                    placeholder={t("unlockScreen.placeholder")}
                    disabled={unlocking}
                    autoComplete="off"
                    className={`w-full h-14 bg-surface-container-lowest rounded-xl pl-4 pr-12 text-on-surface font-mono tracking-[0.15em] focus:outline-none placeholder:text-outline disabled:opacity-50 ${
                      error
                        ? "ring-2 ring-error/40"
                        : "focus:ring-2 focus:ring-primary/40"
                    }`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-4 top-1/2 -translate-y-1/2 text-outline hover:text-on-surface transition-colors"
                    tabIndex={-1}
                    aria-label={showPassword ? t("unlockScreen.hidePassword") : t("unlockScreen.showPassword")}
                  >
                    {showPassword ? (
                      /* eye-off SVG */
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" className="w-5 h-5">
                        <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94" />
                        <path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19" />
                        <line x1="1" y1="1" x2="23" y2="23" />
                      </svg>
                    ) : (
                      /* eye SVG */
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" className="w-5 h-5">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                        <circle cx="12" cy="12" r="3" />
                      </svg>
                    )}
                  </button>
                </div>

                {/* Error display */}
                {error && (
                  <div className="flex items-center gap-2 text-error text-sm mt-2">
                    <svg viewBox="0 0 24 24" fill="currentColor" className="w-4 h-4 flex-shrink-0">
                      <path fillRule="evenodd" d="M12 2.25c-5.385 0-9.75 4.365-9.75 9.75s4.365 9.75 9.75 9.75 9.75-4.365 9.75-9.75S17.385 2.25 12 2.25zm-1.72 6.97a.75.75 0 10-1.06 1.06L10.94 12l-1.72 1.72a.75.75 0 101.06 1.06L12 13.06l1.72 1.72a.75.75 0 101.06-1.06L13.06 12l1.72-1.72a.75.75 0 10-1.06-1.06L12 10.94l-1.72-1.72z" clipRule="evenodd" />
                    </svg>
                    <span>{error}</span>
                  </div>
                )}
              </div>

              {/* Unlock button */}
              <button
                type="submit"
                disabled={unlocking || !password.trim()}
                className="w-full py-3.5 bg-primary text-on-primary font-bold rounded-xl flex items-center justify-center gap-2 hover:shadow-lg hover:shadow-primary/20 active:scale-[0.98] transition-all disabled:opacity-50"
              >
                {unlocking ? (
                  <>
                    <svg className="animate-spin w-5 h-5" viewBox="0 0 24 24" fill="none">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    <span>{t("unlockScreen.submitting")}</span>
                  </>
                ) : (
                  <>
                    {/* lock_open SVG */}
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" className="w-5 h-5">
                      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                      <path d="M7 11V7a5 5 0 019.9-1" />
                    </svg>
                    <span>{t("unlockScreen.submit")}</span>
                  </>
                )}
              </button>
            </form>
          </div>
        </div>

        {/* Footer metadata */}
        <div className="flex items-center justify-center gap-4 text-[10px] font-bold uppercase tracking-widest text-outline">
          <span>{t("unlockScreen.aesLabel")}</span>
          <div className="w-px h-3 bg-outline-variant/20" />
          <span>{t("unlockScreen.scryptLabel")}</span>
        </div>
      </div>
    </div>
  );
}
