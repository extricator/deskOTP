# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.1] - 2026-05-12

### Fixed

- `SHA256SUMS` manifest now lists the `deskOTP` binary by its basename instead of the in-CI build path `build/bin/deskOTP`. The published hash in v0.7.0 was already correct; only the filename token was wrong, which caused the canonical `sha256sum -c SHA256SUMS` verification to fail on the binary line. No application code changed.

## [0.7.0] - 2026-XX-XX

<!-- TODO: Replace XX-XX with the actual release date -->

### Added

- Import OTP tokens from 16 authenticator app formats: Aegis, AndOTP, Authy, Battle.net Authenticator, Bitwarden, deskOTP, Duo, FreeOTP, FreeOTP+, Google Authenticator, Proton Pass, Steam Guard, Stratum (Authenticator Pro), TOTP Authenticator, 2FAS, and WinAuth
- Encrypted backup support for Aegis, AndOTP, Authy, deskOTP, Stratum, TOTP Authenticator, and 2FAS
- TOTP, HOTP, and Steam Guard OTP types
- Click-to-copy token display with countdown timer
- Material Design 3 interface with dark and light themes
- Adjustable display density (compact, default, comfortable)
- Drag-and-drop account reordering
- Account grouping with custom icons
- Search and multi-criteria sort
- Add tokens via QR code image scan, manual entry, or otpauth:// URI paste
- 800+ brand logo icons from aegis-icons with automatic issuer matching
- Clipboard auto-clear after configurable timeout
- Export and backup in deskOTP format (plain or encrypted)
- Internationalization support (English, Spanish)

### Security

- AES-256-GCM vault encryption for stored OTP secrets
- App lock with system authentication integration (xdg-desktop-portal on Linux)
- Master password protection with configurable auto-lock timeout

[Unreleased]: https://github.com/extricator/deskOTP/compare/v0.7.1...HEAD
[0.7.1]: https://github.com/extricator/deskOTP/releases/tag/v0.7.1
[0.7.0]: https://github.com/extricator/deskOTP/releases/tag/v0.7.0
