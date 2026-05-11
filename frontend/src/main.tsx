// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import React from "react";
import { createRoot } from "react-dom/client";
import "./style.css";
import "./i18n";
import App from "./App";
import { ErrorBoundary } from "./components/ErrorBoundary";

// Prevent browser from navigating to dropped files
document.addEventListener("dragover", (e) => e.preventDefault());
document.addEventListener("drop", (e) => e.preventDefault());

const container = document.getElementById("root");
if (!container) throw new Error("Root element not found");

const root = createRoot(container);

root.render(
  <React.StrictMode>
    <ErrorBoundary
      fallbackRender={({ error }) => (
        <div className="h-screen flex flex-col items-center justify-center bg-[rgb(var(--color-bg))] text-[rgb(var(--color-text-primary))]">
          <h1 className="text-xl font-semibold mb-2">deskOTP</h1>
          <p className="mb-4">Something went wrong</p>
          <details className="mb-4 max-w-md text-sm text-[rgb(var(--color-text-secondary))]">
            <summary>Error details</summary>
            <pre className="mt-2 whitespace-pre-wrap">{error.message}</pre>
          </details>
          <button
            aria-label="Reload application"
            onClick={() => window.location.reload()}
            className="px-4 py-2 rounded-lg bg-gradient-to-br from-primary to-primary-container text-on-primary hover:opacity-90 cursor-pointer"
          >
            Reload
          </button>
        </div>
      )}
    >
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);
