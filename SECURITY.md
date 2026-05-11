# Security Policy

deskOTP is a security-sensitive application that handles OTP secrets and encrypted vault data. We take all vulnerability reports seriously.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.7.x   | Yes       |
| < 0.7   | No        |

## Reporting a Vulnerability

**Primary method:** Use GitHub's "Report a vulnerability" button on the [Security tab](https://github.com/extricator/deskOTP/security/advisories/new) of this repository. This uses GitHub's Private Vulnerability Reporting and keeps the report confidential.

**Alternative:** Email `extricator@users.noreply.github.com` with a description of the vulnerability, steps to reproduce, and any relevant details.

> **Note for maintainer:** The "Report a vulnerability" button requires Private Vulnerability Reporting to be enabled in the repository's Security settings (Settings > Code security > Private vulnerability reporting). Enable this after creating the public repository.

## Response Timeline

- **Acknowledgment:** Within 7 days of receiving the report
- **Assessment:** Remediation plan communicated within 30 days
- **Fix:** Released within 90 days of a confirmed vulnerability

## Scope

**In scope:**

- Vault encryption and decryption (AES-256-GCM + scrypt KDF)
- Import file parsing (especially encrypted formats — AES-GCM, AES-CBC, Argon2id, PBKDF2)
- OTP secret storage and handling in memory
- App lock and authentication bypass
- Clipboard handling of OTP codes
- Any path that processes untrusted input (backup files, QR codes, URIs)

**Out of scope:**

- UI cosmetic issues
- Feature requests
- Issues in upstream dependencies (report to the dependency maintainer directly)
- Denial of service via resource exhaustion on local machine

## Disclosure

We follow coordinated disclosure. Please do not publish vulnerability details until a fix has been released. We will credit reporters in the release notes unless they prefer to remain anonymous.
