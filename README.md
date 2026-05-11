# deskOTP

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Build](https://github.com/extricator/deskOTP/actions/workflows/ci.yml/badge.svg)](https://github.com/extricator/deskOTP/actions)
[![Release](https://img.shields.io/github/v/release/extricator/deskOTP)](https://github.com/extricator/deskOTP/releases/latest)

<!-- screenshot: main-view -->
<!-- screenshot: import-flow -->
<!-- TODO: Replace these comments with actual screenshot images before publishing -->

deskOTP is a cross-platform desktop OTP authenticator that imports backup files from phone authenticator apps and displays rotating codes on your desktop. It targets Linux primarily, with macOS and Windows also supported. It is not a mobile app — it is a desktop citizen built for the kind of person who has a terminal always open.

## How It Works

1. Import a backup file from your phone's authenticator app
2. Codes appear on your desktop, rotating every 30 seconds
3. Click any code to copy it to your clipboard, ready to paste

## Features

### Import Formats

Import tokens from 16 authenticator app families:

- **Aegis** — plain and encrypted backups
- **AndOTP** — plain and encrypted backups
- **Authy** — plain and encrypted backups
- **Battle.net Authenticator**
- **Bitwarden**
- **deskOTP** — plain and encrypted backups
- **Duo**
- **FreeOTP**
- **FreeOTP+**
- **Google Authenticator**
- **Proton Pass**
- **Steam Guard**
- **Stratum (Authenticator Pro)** — plain and encrypted backups
- **TOTP Authenticator** — plain and encrypted backups
- **2FAS** — plain and encrypted backups
- **WinAuth**

### OTP Types

TOTP, HOTP, and Steam Guard

### Security

- AES-256-GCM vault encryption for stored OTP secrets
- App lock with system authentication integration
- Master password protection with configurable auto-lock timeout

### Add Tokens

- Import from backup files
- Scan QR code images
- Manual entry
- Paste an `otpauth://` URI

### Interface

- Material Design 3 with dark and light themes
- Adjustable display density (compact, default, comfortable)
- Drag-and-drop account reordering
- Search and multi-criteria sort
- Click-to-copy codes

### Icons

800+ brand logos from [aegis-icons](https://github.com/aegis-icons/aegis-icons) with automatic issuer matching

### Internationalization

English and Spanish. See [TRANSLATING.md](TRANSLATING.md) for how to add a new language.

## Install

Download the latest release from the [Releases page](https://github.com/extricator/deskOTP/releases/latest).

**Linux runtime dependencies:** The Linux binary requires `libwebkit2gtk-4.1` and `libgtk-3` at runtime. Most desktop distributions include these. If not:

```bash
# Ubuntu/Debian
sudo apt-get install libgtk-3-0 libwebkit2gtk-4.1-0

# Fedora/RHEL
sudo dnf install gtk3 webkit2gtk4.1

# Arch
sudo pacman -S gtk3 webkit2gtk-4.1
```

`.deb` and `.rpm` packages will be available in a future release.

## Build from Source

### Prerequisites

- **Go 1.23+** — https://go.dev/dl/
- **Node.js 20+** — https://nodejs.org/
- **Wails CLI** — `go install github.com/wailsapp/wails/v2/cmd/wails@latest`
- **System libraries (Linux)**:
  - Ubuntu/Debian: `sudo apt-get install libgtk-3-dev libwebkit2gtk-4.1-dev pkg-config build-essential`
  - Fedora/RHEL: `sudo dnf install gtk3-devel webkit2gtk4.1-devel`
  - Arch: `sudo pacman -S gtk3 webkit2gtk-4.1`

### Build

```bash
git clone https://github.com/extricator/deskOTP.git
cd deskOTP
cd frontend && npm install && cd ..
wails build
```

Output: `./build/bin/deskOTP`

### Development with hot reload

```bash
wails dev
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions, code style, and PR guidelines.

## Security

To report a security vulnerability, see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

Copyright 2026 deskOTP contributors.
