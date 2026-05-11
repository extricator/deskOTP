// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useEffect, useRef, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { ScanQRScreen } from "../../wailsjs/go/main/App";
import { main } from "../../wailsjs/go/models";
import { ReviewForm } from "./ReviewForm";
import { goErrorToKey } from "../utils/errorKeys";
import { extractErrorMessage } from "../utils/extractErrorMessage";
import { Modal } from "./Modal";

type FlowState =
  | { stage: "idle" }
  | { stage: "scanning" }
  | { stage: "error"; message: string }
  | { stage: "reviewing"; preview: main.URIPreview };

interface ScreenCaptureQRFlowProps {
  onSaved: () => void;
  onCancel: () => void;
}

export function ScreenCaptureQRFlow({
  onSaved,
  onCancel,
}: ScreenCaptureQRFlowProps) {
  const { t } = useTranslation();
  const [flow, setFlow] = useState<FlowState>({ stage: "idle" });

  const handleScan = useCallback(async () => {
    setFlow({ stage: "scanning" });
    try {
      const preview = await ScanQRScreen();
      // User cancelled portal dialog — Go returns empty URIPreview (empty secret)
      if (!preview.secret) {
        onCancel();
        return;
      }
      setFlow({ stage: "reviewing", preview });
    } catch (e: unknown) {
      setFlow({ stage: "error", message: extractErrorMessage(e) });
    }
  }, [onCancel]);

  // Auto-trigger on mount — useRef guard prevents double-invocation in React StrictMode
  const triggered = useRef(false);
  useEffect(() => {
    if (triggered.current) return;
    triggered.current = true;
    void handleScan();
  }, [handleScan]);

  // Escape key closes the flow when not reviewing (ReviewForm handles its own escape)
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape" && flow.stage !== "reviewing") {
        onCancel();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [flow.stage, onCancel]);

  function handleClose() {
    if (flow.stage === "idle" || flow.stage === "error") {
      onCancel();
    }
  }

  const isReviewing = flow.stage === "reviewing";

  return (
    <Modal onClose={handleClose} noContainer={isReviewing}>
      {isReviewing && flow.stage === "reviewing" ? (
        <ReviewForm
          initialPreview={flow.preview}
          onSaved={onSaved}
          onCancel={() => onCancel()}
        />
      ) : (
        <>
          <h2 className="text-token-heading font-semibold text-[rgb(var(--color-text-primary))] mb-2">
            {t("screenQR.title")}
          </h2>
          <p className="text-token-body text-[rgb(var(--color-text-secondary))] mb-4">
            {t("screenQR.description")}
          </p>

          {flow.stage === "error" && (
            <p className="text-token-body text-[rgb(var(--color-error))] mb-4">
              {t(goErrorToKey(flow.message, "screenQR.scanError"))}
            </p>
          )}

          <div className="flex gap-2 justify-end">
            <button
              type="button"
              onClick={onCancel}
              className="px-4 py-2 rounded-lg text-[rgb(var(--color-text-secondary))] hover:text-[rgb(var(--color-text-primary))] hover:bg-[rgb(var(--color-surface-hover))] transition-colors"
            >
              {t("reviewForm.cancel")}
            </button>
            <button
              type="button"
              onClick={handleScan}
              disabled={flow.stage === "scanning"}
              className="px-4 py-2 rounded-lg bg-gradient-to-br from-primary to-primary-container text-on-primary hover:opacity-90 font-medium disabled:opacity-50"
            >
              {flow.stage === "scanning"
                ? t("screenQR.scanning")
                : flow.stage === "error"
                  ? t("screenQR.tryAgain")
                  : t("screenQR.scanButton")}
            </button>
          </div>
        </>
      )}
    </Modal>
  );
}
