// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

// Source: https://react.i18next.com/guides/quick-start
import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import { en } from "./locales/en";
import { es } from "./locales/es";

export const defaultNS = "translation" as const;

export const resources = {
  en: { translation: en },
  es: { translation: es },
} as const;

// Sync read prevents language flash on startup.
// Go settings reconciliation happens in App.tsx mount effect (async).
const savedLang = localStorage.getItem("language") ?? "en";

i18n.use(initReactI18next).init({
  resources,
  lng: savedLang,
  fallbackLng: "en",
  defaultNS,
  interpolation: {
    escapeValue: false, // React already escapes values
  },
});

export default i18n;
