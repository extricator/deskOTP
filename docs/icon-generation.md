# Icon Generation

This document explains how to regenerate the deskOTP icon build assets from the canonical source PNG.

---

## Overview

- `build/appicon.png` is the **canonical source** — a 1024x1024 PNG with alpha channel.
  It is used directly by Wails for Linux and macOS builds.
- `build/windows/icon.ico` is **derived from it** using ImageMagick. It contains six resolution
  layers: 256, 128, 64, 48, 32, and 16 pixels.
- **Wails does NOT auto-regenerate `icon.ico` when it already exists.** If you update
  `build/appicon.png`, you must run the ImageMagick command below to regenerate `icon.ico`
  explicitly.

---

## Prerequisites

ImageMagick must be installed on the host system.

**Debian/Ubuntu:**
```
sudo apt install imagemagick
```

**Fedora/RHEL:**
```
sudo dnf install imagemagick
```

**macOS:**
```
brew install imagemagick
```

Check which version you have:
- ImageMagick 7: `magick --version`
- ImageMagick 6: `convert --version`

---

## Generate All Icon Files

### Step 1 — Place source PNG

Copy your 1024x1024 icon into the build directory, overwriting the existing file:

```
cp /path/to/your-icon-1024x1024.png build/appicon.png
```

The source image must be exactly 1024x1024 pixels and must include an alpha channel (transparency).
See `ICON_PROMPT.md` for the creative brief used to generate the source artwork.

### Step 2 — Generate multi-resolution ICO (ImageMagick 7)

```
magick build/appicon.png \
  -define icon:auto-resize="256,128,64,48,32,16" \
  build/windows/icon.ico
```

### Step 3 — ImageMagick 6 fallback (older distros)

If `magick` is not available (e.g., Ubuntu 20.04 or earlier), use `convert` instead:

```
convert build/appicon.png \
  -define icon:auto-resize="256,128,64,48,32,16" \
  build/windows/icon.ico
```

---

## Verify

Run the verification script to confirm both files meet the build specification:

```
python3 scripts/verify-icons.py
```

Expected output:

```
Verifying deskOTP icon build assets...

OK: build/appicon.png is 1024x1024 (NNN KB)
OK: build/windows/icon.ico has 6 layers: [16, 32, 48, 64, 128, 256]

All checks passed.
```

---

## Notes

- **Do NOT use `-alpha off`** — preserve transparency for proper rendering on both light and dark
  desktop backgrounds.
- **ICO format does not support sizes above 256** — do not add larger values to the
  `icon:auto-resize` list.
- The 256px ICO layer is stored as PNG-in-ICO (Windows Vista+ format) — this is correct per spec
  and expected by Wails.
- Reference `ICON_PROMPT.md` for the creative brief used to generate the source artwork.
