# deskOTP Icon Generation Prompt

## What is deskOTP?

deskOTP is a cross-platform desktop OTP (one-time password) authenticator, primarily targeting Linux but built to run on macOS and Windows too. It lives permanently on the desktop — in a taskbar, pinned to a launcher, or docked to a panel. It is the gatekeeper between you and your second-factor codes: a vault of rotating secrets that regenerates every thirty seconds, ready to unlock any service you trust it with.

It imports backup files from sixteen different authenticator families — Aegis, Google Authenticator, Authy, and more — so it is cosmopolitan by nature: a neutral, trusted intermediary that speaks every format. It stores those secrets behind AES-256-GCM encryption and presents them in a clean Material Design 3 interface with dark and light modes.

It is not a mobile app. It is a desktop citizen. Serious, calm, precise. Built for the kind of person who has a terminal always open and knows what a TOTP seed is.

---

## The Creative Brief

Design an application icon for deskOTP that feels like it belongs on a modern desktop — whether that's GNOME, KDE Plasma, macOS, or Windows. The icon should be at home beside other polished, geometry-forward desktop app icons. It should not look like a phone app or a web service.

The icon should evoke these ideas — not necessarily all at once, and not literally. These are the soul of the app:

**Time and rotation.** TOTP codes count down on a 30-second cycle. There is always urgency and precision: the code is valid now, and then it is not. Something about the icon should hint at this rhythm — rotation, a sweep, a cycle, a moment captured mid-turn.

**Security and trust without paranoia.** This is not a warning icon or a lock-down-everything icon. It is more like a safe that you own: it holds your secrets and you trust it completely. The feeling is confident, not anxious. Calm authority, not alarm.

**A vault that is also alive.** The codes inside are not static — they breathe. Every thirty seconds the numbers change. Think of something sealed that also pulses or glows or turns.

**Desktop-native precision.** Clean geometry. Crisp edges. The kind of icon that was drawn on a grid. Material Design 3 sensibility: layered surfaces, tonal depth, considered use of shadow and elevation.

---

## Visual Direction

Lean into the Material Design 3 tonal palette. The primary color family should sit in the blue-teal-cyan range — these are the colors of trust, clarity, and security. Think of a deep ocean blue or a sharp cyan, not the corporate blues of banking software. A warm accent (amber, gold, or orange) could represent the ticking countdown, the moment before the code expires, the warmth of something just generated.

The icon should read well at all sizes: from a 16x16 system tray icon to a 512x512 store listing. The core shape must be recognizable when reduced to a small square with no label. Avoid fine detail that collapses at small sizes.

It should look good on both dark and light desktop backgrounds. Consider whether the icon needs a contained background shape (a rounded square, a circle, a squircle) or whether it can live as a freestanding mark.

---

## What to Avoid

- Generic padlock icons — too common, too static, too warning-adjacent
- Smartphone or mobile imagery — this app is proudly not on your phone
- Shields with checkmarks — overused in security branding
- QR code imagery — that is the import flow, not the identity
- Complexity that disappears below 64x64 — the small size is a real constraint
- Clock faces that look like alarm clocks — too literal, too anxious
- Key icons — overused and not specific enough

---

## The Feeling

If deskOTP were an object, it might be a precision instrument: a watch movement, a cryptographic chip, a well-made combination lock. Not flashy, but beautiful in its exactness. It does one thing and it does it with complete reliability. The icon should feel like that: the satisfaction of a thing that works, every thirty seconds, without fail.

Feel free to interpret these ideas unexpectedly. The best icon might combine elements nobody else has thought to combine. Surprise is welcome as long as the result feels trustworthy and desktop-native.

---

## Technical Specifications

- **Size range:** Must be legible and visually coherent at 16x16, 32x32, 64x64, 128x128, 256x256, and 512x512 pixels
- **Format:** Suitable for export as PNG (with transparency) and SVG
- **Background:** Should work on both dark (#1c1b1f or similar) and light (#fffbfe or similar) desktop backgrounds
- **Shape language:** Prefer clean, rounded geometry consistent with Material Design 3 icon guidelines
- **Color depth:** Should feel vibrant and modern, not flat and corporate — tonal layering is encouraged
