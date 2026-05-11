// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { ParseAndPreviewURI } from "../../wailsjs/go/main/App";
import { main } from "../../wailsjs/go/models";
import { ReviewForm } from "./ReviewForm";
import { goErrorToKey } from "../utils/errorKeys";
import { extractErrorMessage } from "../utils/extractErrorMessage";
import { BASE_INPUT_CLASS } from "../utils/inputClass";
import { Modal } from "./Modal";

type PasteFlowState =
  | { stage: "entering" }
  | { stage: "parsing" }
  | { stage: "error"; message: string }
  | { stage: "reviewing"; preview: main.URIPreview };

interface URIPasteFlowProps {
  onSaved: () => void;
  onCancel: () => void;
}

export function URIPasteFlow({ onSaved, onCancel }: URIPasteFlowProps) {
  const { t } = useTranslation();
  const [flow, setFlow] = useState<PasteFlowState>({ stage: "entering" });
  const [uriText, setUriText] = useState("");

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
    if (flow.stage !== "reviewing" && flow.stage !== "parsing") {
      onCancel();
    }
  }

  async function handleParse() {
    setFlow({ stage: "parsing" });
    try {
      const preview = await ParseAndPreviewURI(uriText);
      if (!preview || !preview.secret) {
        setFlow({ stage: "error", message: "uriPaste.parseError" });
        return;
      }
      setFlow({ stage: "reviewing", preview });
    } catch (e: unknown) {
      setFlow({ stage: "error", message: extractErrorMessage(e) });
    }
  }

  const isReviewing = flow.stage === "reviewing";

  return (
    <Modal onClose={handleClose} noContainer={isReviewing}>
      {isReviewing && flow.stage === "reviewing" ? (
        <ReviewForm
          initialPreview={flow.preview}
          onSaved={onSaved}
          onCancel={() => setFlow({ stage: "entering" })}
        />
      ) : (
        <>
          <h2 className="text-token-heading font-semibold text-[rgb(var(--color-text-primary))] mb-2">
            {t("uriPaste.title")}
          </h2>
          <p className="text-token-body text-[rgb(var(--color-text-secondary))] mb-4">
            {t("uriPaste.description")}
          </p>

          <textarea
            value={uriText}
            onChange={(e) => setUriText(e.target.value)}
            placeholder={t("uriPaste.placeholder")}
            rows={3}
            spellCheck={false}
            autoComplete="off"
            className={`${BASE_INPUT_CLASS} mb-4 resize-none font-mono text-token-body`}
          />

          {flow.stage === "error" && (
            <p className="text-token-body text-[rgb(var(--color-error))] mb-4">
              {t(goErrorToKey(flow.message, "uriPaste.parseError"))}
            </p>
          )}

          <div className="flex gap-2 justify-end">
            <button
              type="button"
              onClick={onCancel}
              className="px-4 py-2 rounded-lg text-[rgb(var(--color-text-secondary))] hover:text-[rgb(var(--color-text-primary))] hover:bg-[rgb(var(--color-surface-hover))] transition-colors"
            >
              {t("uriPaste.cancel")}
            </button>
            <button
              type="button"
              onClick={handleParse}
              disabled={flow.stage === "parsing" || !uriText.trim()}
              className="px-4 py-2 rounded-lg bg-gradient-to-br from-primary to-primary-container text-on-primary hover:opacity-90 font-medium disabled:opacity-50"
            >
              {flow.stage === "parsing"
                ? t("uriPaste.parsing")
                : t("uriPaste.parse")}
            </button>
          </div>
        </>
      )}
    </Modal>
  );
}
