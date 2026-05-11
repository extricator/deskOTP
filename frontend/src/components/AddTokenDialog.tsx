// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { Environment } from "../../wailsjs/runtime/runtime";
import { Modal } from "./Modal";

interface AddTokenDialogProps {
  onSelectManual: () => void;
  onSelectScanFile: () => void;
  onSelectScanScreen: () => void;
  onSelectPasteURI: () => void;
  onImportBackup: () => void;
  onClose: () => void;
}

export function AddTokenDialog({
  onSelectManual,
  onSelectScanFile,
  onSelectScanScreen,
  onSelectPasteURI,
  onImportBackup,
  onClose,
}: AddTokenDialogProps) {
  const { t } = useTranslation();
  const [isLinux, setIsLinux] = useState(false);

  useEffect(() => {
    Environment()
      .then((info) => setIsLinux(info.platform === "linux"))
      .catch(() => setIsLinux(false));
  }, []);

  return (
    <Modal
      onClose={onClose}
      noContainer={true}
      blurContent={true}
      backdropClassName="bg-black/40"
    >
      <div className="w-full max-w-2xl bg-surface-container-low rounded-2xl border border-outline-variant/20 shadow-2xl flex flex-col overflow-hidden mx-4">
        {/* Header */}
        <div className="flex items-center justify-between px-8 py-6 border-b border-outline-variant/10">
          <div className="flex items-center gap-4">
            <div className="bg-primary-container/30 p-2.5 rounded-xl">
              <svg viewBox="0 0 24 24" fill="currentColor" className="w-6 h-6 text-primary">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm5 11h-4v4h-2v-4H7v-2h4V7h2v4h4v2z"/>
              </svg>
            </div>
            <div>
              <h2 className="text-2xl font-black font-headline tracking-tight text-on-surface">{t("addToken.heading")}</h2>
              <p className="text-sm text-on-surface-variant font-body">{t("addToken.headerSubtitle")}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-surface-container-highest rounded-full transition-colors text-outline"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-5 h-5">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        {/* Method Tile Grid */}
        <div className="p-8">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Manual Entry */}
            <button
              type="button"
              onClick={onSelectManual}
              className="group relative flex flex-col p-6 rounded-xl bg-surface-container hover:bg-surface-container-high transition-all duration-200 cursor-pointer border border-transparent hover:border-primary/20 w-full text-left"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="p-3 bg-surface-container-low rounded-lg text-primary group-hover:bg-primary-container/40 transition-colors">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6">
                    <rect x="2" y="6" width="20" height="12" rx="2"/>
                    <path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M8 14h8"/>
                  </svg>
                </div>
                <div className="opacity-0 group-hover:opacity-100 translate-x-2 group-hover:translate-x-0 transition-all text-outline-variant">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
                    <polyline points="9 18 15 12 9 6" />
                  </svg>
                </div>
              </div>
              <p className="font-bold font-headline text-lg mb-1">{t("addToken.tileManual")}</p>
              <p className="text-sm text-on-surface-variant leading-relaxed">{t("addToken.tileManualDesc")}</p>
            </button>

            {/* Scan QR Image */}
            <button
              type="button"
              onClick={onSelectScanFile}
              className="group relative flex flex-col p-6 rounded-xl bg-surface-container hover:bg-surface-container-high transition-all duration-200 cursor-pointer border border-transparent hover:border-primary/20 w-full text-left"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="p-3 bg-surface-container-low rounded-lg text-primary group-hover:bg-primary-container/40 transition-colors">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6">
                    <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                    <circle cx="8.5" cy="8.5" r="1.5"/>
                    <polyline points="21 15 16 10 5 21"/>
                  </svg>
                </div>
                <div className="opacity-0 group-hover:opacity-100 translate-x-2 group-hover:translate-x-0 transition-all text-outline-variant">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
                    <polyline points="9 18 15 12 9 6" />
                  </svg>
                </div>
              </div>
              <p className="font-bold font-headline text-lg mb-1">{t("addToken.tileScanFile")}</p>
              <p className="text-sm text-on-surface-variant leading-relaxed">{t("addToken.tileScanFileDesc")}</p>
            </button>

            {/* Scan Screen — Linux only */}
            {isLinux && (
              <button
                type="button"
                onClick={onSelectScanScreen}
                className="group relative flex flex-col p-6 rounded-xl bg-surface-container hover:bg-surface-container-high transition-all duration-200 cursor-pointer border border-transparent hover:border-primary/20 w-full text-left"
              >
                <div className="flex items-start justify-between mb-4">
                  <div className="p-3 bg-surface-container-low rounded-lg text-primary group-hover:bg-primary-container/40 transition-colors">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6">
                      <rect x="2" y="3" width="20" height="14" rx="2"/>
                      <path d="M8 21h8M12 17v4"/>
                    </svg>
                  </div>
                  <div className="opacity-0 group-hover:opacity-100 translate-x-2 group-hover:translate-x-0 transition-all text-outline-variant">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
                      <polyline points="9 18 15 12 9 6" />
                    </svg>
                  </div>
                </div>
                <p className="font-bold font-headline text-lg mb-1">{t("addToken.tileScanScreen")}</p>
                <p className="text-sm text-on-surface-variant leading-relaxed">{t("addToken.tileScanScreenDesc")}</p>
              </button>
            )}

            {/* Paste URI */}
            <button
              type="button"
              onClick={onSelectPasteURI}
              className="group relative flex flex-col p-6 rounded-xl bg-surface-container hover:bg-surface-container-high transition-all duration-200 cursor-pointer border border-transparent hover:border-primary/20 w-full text-left"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="p-3 bg-surface-container-low rounded-lg text-primary group-hover:bg-primary-container/40 transition-colors">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6">
                    <path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/>
                    <path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/>
                  </svg>
                </div>
                <div className="opacity-0 group-hover:opacity-100 translate-x-2 group-hover:translate-x-0 transition-all text-outline-variant">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
                    <polyline points="9 18 15 12 9 6" />
                  </svg>
                </div>
              </div>
              <p className="font-bold font-headline text-lg mb-1">{t("addToken.tilePasteURI")}</p>
              <p className="text-sm text-on-surface-variant leading-relaxed">{t("addToken.tilePasteURIDesc")}</p>
            </button>
          </div>
        </div>

        {/* Footer */}
        <div className="px-8 py-6 bg-surface-container-low/50 flex justify-between items-center mt-auto">
          <div />
          <div className="flex gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-5 py-2.5 rounded-lg font-bold text-sm text-on-surface-variant hover:bg-surface-container transition-colors"
            >
              {t("addToken.cancel")}
            </button>
            <button
              type="button"
              onClick={onImportBackup}
              className="px-6 py-2.5 rounded-lg bg-primary text-on-primary font-bold text-sm shadow-lg shadow-primary/10 hover:brightness-110 active:scale-95 transition-all"
            >
              {t("addToken.importBackup")}
            </button>
          </div>
        </div>
      </div>
    </Modal>
  );
}
