# Adding a New Language to deskOTP

This guide explains how to add a new translation to deskOTP. Follow all steps in order.

## Prerequisites

- A working local development environment (Go 1.21+ and Node 18+)
- Basic TypeScript familiarity (you will be editing a `.ts` file)
- Human-reviewed translations — machine translation alone is not accepted for this security-sensitive application

---

## Steps

### 1. Copy the template

Copy `frontend/src/locales/es.ts` (or `en.ts`) to a new file named after your locale code:

```bash
cp frontend/src/locales/es.ts frontend/src/locales/fr.ts
```

Open the new file and rename the exported constant to match the locale code:

```typescript
// frontend/src/locales/fr.ts
// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import type { LocaleShape } from "./en";

export const fr = {
  // ... translated strings
} satisfies LocaleShape;
```

---

### 2. Translate all string values

Open the new locale file and translate every string value. Observe these rules strictly:

- **Keep all object keys unchanged.** Keys (e.g., `tokens`, `heading`, `saveError`) are the stable contract between the translation file and the components. Never rename or remove a key.
- **Keep all `{{variableName}}` interpolation placeholders unchanged.** For example, `'{{added}} añadidas, {{skipped}} ya existían'` must keep `{{added}}` and `{{skipped}}` with exactly those names — only translate the surrounding text. Changing a placeholder name silently produces empty output at runtime.
- **Keep product names unchanged.** `deskOTP` is a proper noun and must not be translated.
- **Keep the `satisfies LocaleShape` assertion** at the end of the object.
- **Human review is required.** This app handles passwords and OTP secrets. Machine translation alone produces errors that could mislead users during security-critical flows (unlock screen, password management). Native or fluent speaker review is required before merging.

Example of correct interpolation handling:

```typescript
// English source
addedAndSkipped: '{{added}} added, {{skipped}} already existed',

// Correct French translation (placeholders unchanged)
addedAndSkipped: '{{added}} ajoutés, {{skipped}} existaient déjà',

// WRONG — placeholder names changed (produces empty output)
addedAndSkipped: '{{ajoutes}} ajoutés, {{ignores}} existaient déjà',
```

---

### 3. Register the language in i18n.ts

Open `frontend/src/i18n.ts` and add your locale:

```typescript
import { en } from './locales/en'
import { es } from './locales/es'
import { fr } from './locales/fr'  // add this line

export const resources = {
  en: { translation: en },
  es: { translation: es },
  fr: { translation: fr },  // add this entry
} as const
```

---

### 4. Add the language option in SettingsPage.tsx

Open `frontend/src/components/SettingsPage.tsx` and find the language `<select>` element. Add a new option for your locale:

```tsx
<option value="fr">{t('settings.languageFrench')}</option>
```

Then add the corresponding translation key to `en.ts`:

```typescript
// frontend/src/locales/en.ts — settings section
languageFrench: 'French',
```

Add the same key to all existing locale files:

```typescript
// frontend/src/locales/es.ts — settings section
languageFrench: 'Francés',

// frontend/src/locales/fr.ts — settings section
languageFrench: 'Français',
```

---

### 5. Add the locale to validLangs in App.tsx

Open `frontend/src/App.tsx` and find the `validLangs` array. Add your locale code:

```typescript
const validLangs = ['en', 'es', 'fr']
```

This guard ensures the persisted language setting is never set to an unsupported value.

---

### 6. Verify

Run the TypeScript compiler to check that no keys are missing or misnamed:

```bash
cd frontend && npm run typecheck
```

A clean compile means all keys are present and correctly typed. Any missing or extra key will produce a compile error.

Then test manually in the running application:

1. Start the app (`wails dev` or `wails build`)
2. Go to Settings and switch to your new language
3. Verify every screen in the new language:
   - Tokens page (including search, sort dropdown, empty state)
   - Settings page (all three sections: Personalisation, Security, About)
   - Import flow (import button, password modal, import result dialog)
   - Edit dialog (basic fields and advanced fields)
   - Unlock screen (if vault has a master password set)
4. Test all error paths:
   - Wrong vault password at unlock screen
   - Wrong backup password in the password modal
   - Mismatched passwords when setting/changing the master password
5. Resize the window to 400px wide and verify no text overflows or breaks the layout

---

### 7. Submit a PR

Open a pull request with your changes. CI runs `npm run typecheck` in a step labeled **TypeScript type check and i18n key completeness** — any missing or extra key in your locale file will fail this step and block the PR.

Include in your PR description:
- The locale code and language name
- How the translations were produced (human-authored, machine-translated + human-reviewed, etc.)
- Screenshots of the key screens (tokens page, settings page, unlock screen)

---

## Tips

- **Spanish strings are typically 20-40% longer than English.** Keep translations concise where possible, especially for labels that appear in tight UI areas (nav bar, sort dropdown, button labels).
- **Test the sort dropdown especially.** The toggle button renders the sort label + option + direction concatenated (e.g., "Sort: Date added (Oldest)"). Long translations can overflow at narrow widths.
- **The `truncate` CSS class** on card text (issuer, account name) handles overflow gracefully — long strings are clipped with an ellipsis. Verify visually that important information is still visible.
- **Copyright notice** (`settings.copyright`): Keep this in English (e.g., `'2026 deskOTP contributors'`) — copyright notices conventionally remain in the original language.
- **Runtime fallback:** If a key is missing in your locale file during development (before running the type check), i18next falls back to the English value automatically (`fallbackLng: "en"` in `i18n.ts`). The `satisfies LocaleShape` check prevents missing keys from shipping, but during incremental translation work the app remains functional.

---

## File Structure Reference

```
frontend/src/
  locales/
    en.ts              # English (base language — do not modify keys)
    es.ts              # Spanish
    {locale}.ts        # Your new language
  i18n.ts              # Language registration (resources object)
  App.tsx              # validLangs array (language reconciliation guard)
  components/
    SettingsPage.tsx   # Language selector dropdown
TRANSLATING.md         # This file
```
