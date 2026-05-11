// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

export interface SupportedFormat {
  name: string;
  extensions: string;
}

export const SUPPORTED_FORMATS: SupportedFormat[] = [
  { name: "Aegis", extensions: ".json / .json.age" },
  { name: "Aegis (Encrypted)", extensions: ".json" },
  { name: "2FAS", extensions: ".json / .2fas" },
  { name: "2FAS (Encrypted)", extensions: ".2fas" },
  { name: "andOTP", extensions: ".json" },
  { name: "andOTP (Encrypted)", extensions: ".bin" },
  { name: "Authy", extensions: ".xml" },
  { name: "Authy (Encrypted)", extensions: ".xml" },
  { name: "Bitwarden", extensions: ".json / .csv" },
  { name: "Battle.net", extensions: ".xml" },
  { name: "deskOTP Backup", extensions: ".json" },
  { name: "deskOTP Backup (Encrypted)", extensions: ".json" },
  { name: "Duo", extensions: ".json" },
  { name: "FreeOTP", extensions: ".xml" },
  { name: "FreeOTP+", extensions: ".json" },
  { name: "Google Authenticator", extensions: ".txt" },
  { name: "Proton Authenticator", extensions: ".json" },
  { name: "Steam Guard", extensions: ".json" },
  { name: "Stratum", extensions: ".json" },
  { name: "Stratum (Encrypted)", extensions: ".bin" },
  { name: "TOTP Authenticator", extensions: ".xml" },
  { name: "TOTP Authenticator (Encrypted)", extensions: ".bin" },
  { name: "WinAuth", extensions: ".txt" },
];
