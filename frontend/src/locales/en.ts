// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

/**
 * English translation keys for deskOTP.
 *
 * Key naming convention: `section.semanticPurpose`
 * - Section: camelCase component name or feature area (e.g., `nav`, `settings`, `editDialog`)
 * - Purpose: describes what the string means, not how it looks (e.g., `heading` not `bigText`)
 * - Nesting: max 2 levels (section.key), never deeper
 *
 * Keys with interpolation use {{variableName}} syntax:
 *   'importResult.addedAndSkipped': '{{added}} added, {{skipped}} already existed'
 */

export const en = {
  // sidebar
  sidebar: {
    allTokens: "All Tokens",
    settings: "Settings",
    addNewToken: "Add New Token",
    vault: "Vault",
    groups: "Groups",
    newGroup: "New Group",
    noIcon: "No icon",
    contextMenu: {
      rename: "Edit",
      moveUp: "Move Up",
      moveDown: "Move Down",
      delete: "Delete",
      confirmDeleteTitle: "Delete Group",
      confirmDeleteMessage: 'Delete "{{groupName}}"? All tokens will become ungrouped.',
      newGroupPlaceholder: "Group name",
    },
  },
  // nav
  nav: {
    tokens: "Accounts",
    settings: "Settings",
    addToken: "Add token",
    addTokenTooltip: "Add a new token",
    importBackup: "Import backup file",
    lock: "Lock",
    lockTooltip: "Lock app",
    lockDisabledTooltip: "Set a master password to enable locking",
    lockDisabledMessage: "Set a master password in Settings to enable locking.",
    themeDark: "Switch to light mode",
    themeLight: "Switch to dark mode",
  },
  // tokens page
  tokensPage: {
    heading: "Accounts",
    noAccounts: "No accounts yet",
    noAccountsHint: "Click Import in the toolbar above to get started",
    noMatches: "No matching accounts",
    searchPlaceholder: "Search accounts",
    copied: "Copied!",
    secureVaultHeading: "Tokens",
    activeTokenCount: "{{count}} active tokens",
    managingTokens: "Managing {{count}} secure access tokens across your platforms.",
    addNewToken: "Add New Token",
  },
  // group filter bar
  groupFilterBar: {
    all: "All",
  },
  // sort dropdown
  sort: {
    label: "Sort",
    issuer: "Issuer",
    name: "Name",
    dateAdded: "Date added",
    usageCount: "Usage",
    ascending: "A-Z",
    descending: "Z-A",
    oldest: "Oldest",
    newest: "Newest",
    least: "Least",
    most: "Most",
  },
  // import area
  importArea: {
    importFailed: "Import failed",
    openFileFailed: "Failed to open file dialog",
    incorrectPassword: "Incorrect password. Please try again.",
    decryptionFailed: "Decryption failed",
    importButton: "Import Backup",
    importing: "Importing...",
    hint: "Import a backup file to get started",
  },
  importResult: {
    title: "Import Complete",
    addedAndSkipped: "{{added}} added, {{skipped}} already existed",
    addedAndSkippedFormat:
      "{{added}} added, {{skipped}} already existed ({{formatName}})",
    addedOnly: "{{added}} added",
    addedOnlyFormat: "{{added}} added from {{formatName}}",
    allExisted: "All {{skipped}} already existed",
    noneFound: "No accounts found in file",
    noTokensFound: "No tokens found in this {{formatName}} backup",
    encryptionNotice: "Your tokens are stored without encryption.",
    setupEncryption: "Set up a master password",
  },
  // password modal
  passwordModal: {
    title: "Encrypted Backup",
    description:
      "This backup is encrypted. Enter the password you set when creating the backup.",
    placeholder: "Backup password",
    cancel: "Cancel",
    unlock: "Unlock",
    unlocking: "Decrypting...",
  },
  // unlock screen
  unlockScreen: {
    title: "deskOTP",
    description: "Enter your master password to unlock",
    placeholder: "Master password",
    submit: "Unlock Vault",
    submitting: "Unlocking...",
    incorrectPassword: "Incorrect password",
    genericError: "Failed to unlock vault",
    vaultLocked: "Vault Locked",
    showPassword: "Show password",
    hidePassword: "Hide password",
    aesLabel: "AES-256-GCM",
    scryptLabel: "scrypt KDF",
  },
  // settings page
  settings: {
    heading: "Settings",
    vaultConfigTitle: "Vault Configuration",
    vaultConfigSubtitle: "Adjust security thresholds and interface parameters for your encrypted environment.",
    // sections
    personalisation: "Personalisation",
    security: "Security",
    about: "About",
    // personalisation rows
    theme: "Theme",
    themeDesc: "Switch between light and dark mode",
    themeDark: "Dark",
    themeLight: "Light",
    language: "Language",
    languageDesc: "Change display language",
    languageEnglish: "English",
    languageSpanish: "Spanish",
    displayDensity: "Display density",
    displayDensityDesc: "Adjust card size and spacing",
    densityCompact: "Compact",
    densityDefault: "Default",
    densityComfortable: "Comfortable",
    // security
    setPasswordHeading: "Set Master Password",
    setPasswordDesc:
      "Encrypt your vault with a master password. You will need to enter it each time you open the app.",
    setPasswordNew: "New password",
    setPasswordConfirm: "Confirm password",
    setPasswordMismatch: "Passwords do not match",
    setPasswordSubmit: "Set Password",
    setPasswordSubmitting: "Setting...",
    setPasswordSuccess: "Password set successfully",
    changePasswordHeading: "Change Password",
    changePasswordCurrent: "Current password",
    changePasswordNew: "New password",
    changePasswordConfirm: "Confirm new password",
    changePasswordMismatch: "Passwords do not match",
    changePasswordSubmit: "Change Password",
    changePasswordSubmitting: "Changing...",
    changePasswordSuccess: "Password changed successfully",
    removePasswordHeading: "Remove Password",
    removePasswordDesc:
      "Remove encryption and revert to plain storage. This cannot be undone.",
    removePasswordCurrent: "Current password",
    removePasswordSubmit: "Remove Password",
    removePasswordSubmitting: "Removing...",
    removePasswordSuccess: "Password removed",
    setPasswordError: "Failed to set password",
    changePasswordError: "Failed to change password",
    removePasswordError: "Failed to remove password",
    incorrectPassword: "Incorrect password",
    autoLock: "Auto-lock",
    autoLockDesc: "Lock vault after inactivity",
    autoLock1min: "1 minute",
    autoLock5min: "5 minutes",
    autoLock15min: "15 minutes",
    autoLock30min: "30 minutes",
    autoLockNever: "Never",
    clipboardClear: "Clipboard auto-clear",
    clipboardClearDesc: "Clear clipboard after copying a code",
    clipboardClear10s: "10 seconds",
    clipboardClear20s: "20 seconds",
    clipboardClear30s: "30 seconds",
    clipboardClear60s: "60 seconds",
    clipboardClearNever: "Never",
    version: "Version",
    copyright: "2026 deskOTP contributors",
    // security banner
    bannerTitle: "Protect your tokens with a master password",
    bannerDesc: "Your vault is unencrypted. Set a master password in the",
    bannerLink: "Security section",
    bannerDescSuffix: "below to encrypt your tokens.",
    bannerDismiss: "Dismiss recommendation",
    // backup section
    backup: "Backup",
    backupDirectory: "Backup directory",
    backupDirectoryDesc: "Where backup files are saved",
    backupDirectoryNone: "No directory selected",
    backupBrowse: "Browse",
    backupSchedule: "Schedule",
    backupScheduleDesc: "Auto-backup frequency",
    backupScheduleOff: "Off",
    backupScheduleDaily: "Daily",
    backupScheduleWeekly: "Weekly",
    backupRetention: "Keep",
    backupRetentionDesc: "Number of backups to keep",
    backupRetention3: "3 backups",
    backupRetention5: "5 backups",
    backupRetention10: "10 backups",
    backupLastBackup: "Last backup",
    backupLastBackupNever: "Never",
    backupExportNow: "Export Now",
    backupExporting: "Exporting...",
    backupExported: "Exported",
    backupExportError: "Export failed",
    backupBrowseError: "Could not open directory picker",
    backupExportDisabledTooltip: "Set a backup directory first",
    backupError: "Backup error",
  },
  // edit dialog
  editDialog: {
    title: "Edit Account",
    loading: "Loading...",
    loadError: "Failed to load entry details",
    close: "Close",
    changeIconTitle: "Change icon",
    labelName: "Name",
    placeholderName: "Account name",
    labelIssuer: "Issuer",
    placeholderIssuer: "Service provider",
    labelGroup: "Group",
    placeholderGroup: "Group name",
    groupHint: "Type to create a new group or select an existing one",
    labelNote: "Note",
    placeholderNote: "Optional note",
    showAdvanced: "Show Advanced",
    hideAdvanced: "Hide Advanced",
    labelType: "Type",
    labelAlgorithm: "Algorithm",
    labelPeriod: "Period",
    labelDigits: "Digits",
    labelSecret: "Secret",
    placeholderSecret: "Enter new secret",
    changeSecret: "Change Secret",
    cancelSecretChange: "Cancel",
    labelUsageCount: "Usage Count",
    saveError: "Failed to save changes",
    cancel: "Cancel",
    save: "Save",
    saving: "Saving...",
  },
  // group picker
  groupPicker: {
    placeholder: "No group",
    none: "None",
    createButton: "Create",
    creating: "Creating...",
    createError: "Failed to create group",
    duplicateError: "Group already exists",
  },
  // confirm dialog
  confirmDialog: {
    cancel: "Cancel",
  },
  // delete flow
  deleteAccount: {
    title: "Delete account",
    message:
      'Are you sure you want to delete "{{name}}"?\n\nThis will remove the account and its secret key.',
    confirm: "Delete",
    undoMessage: "Deleted {{name}}",
    undo: "Undo",
  },
  // context menu
  contextMenu: {
    copy: "Copy",
    edit: "Edit",
    delete: "Delete",
  },
  // icon picker
  iconPicker: {
    title: "Choose Icon",
    searchPlaceholder: "Search icons...",
    noMatches: 'No icons match "{{query}}"',
    removeIcon: "Remove icon",
    revertConfirm: "Revert to letter avatar?",
    cancel: "Cancel",
    remove: "Remove",
    suggested: "Suggested",
  },
  // group edit dialog
  groupEditDialog: {
    titleCreate: "New Group",
    titleRename: "Edit Group",
    chooseIcon: "Choose group icon",
  },
  // group icon picker
  groupIconPicker: {
    title: "Choose Group Icon",
    searchPlaceholder: "Search icons...",
    noMatches: 'No icons match "{{query}}"',
    removeIcon: "Remove icon",
    revertConfirm: "Revert to folder icon?",
    cancel: "Cancel",
    remove: "Remove",
  },
  // review form (shared by all add-token flows)
  reviewForm: {
    title: "Review Token",
    labelIssuer: "Issuer",
    placeholderIssuer: "Service provider",
    labelName: "Name",
    placeholderName: "Account name",
    labelGroup: "Group",
    changeIconTitle: "Change icon",
    showAdvanced: "Show Advanced",
    hideAdvanced: "Hide Advanced",
    labelType: "Type",
    labelAlgorithm: "Algorithm",
    labelPeriod: "Period (seconds)",
    labelDigits: "Digits",
    labelSecret: "Secret",
    labelCounter: "Counter",
    save: "Save",
    saving: "Saving...",
    cancel: "Cancel",
    saveError: "Failed to save token",
    duplicateTitle: "Duplicate token",
    duplicateMessage:
      'A token for "{{issuer}}" / "{{name}}" already exists. Add it anyway?',
    duplicateConfirm: "Add anyway",
  },
  // file QR flow
  fileQR: {
    title: "Add from QR image",
    description: "Select an image file containing a QR code to add a token.",
    scanFile: "Scan file",
    scanning: "Scanning...",
    scanError: "Failed to read QR code from image",
    tryAgain: "Try again",
  },
  // manual entry form
  manualEntry: {
    title: "Add Token Manually",
    labelIssuer: "Issuer",
    placeholderIssuer: "Service provider (e.g. GitHub)",
    labelName: "Account name",
    placeholderName: "your@email.com",
    labelSecret: "Secret key",
    placeholderSecret: "Base32 encoded secret",
    labelGroup: "Group",
    secretHint: "Found in your account's 2FA settings",
    secretInvalidBase32: "Invalid secret key. Use only A-Z and 2-7 characters.",
    proceed: "Continue",
    cancel: "Cancel",
    showAdvanced: "Show Advanced",
    hideAdvanced: "Hide Advanced",
    labelType: "Type",
    labelAlgorithm: "Algorithm",
    labelPeriod: "Period (seconds)",
    labelDigits: "Digits",
    labelCounter: "Counter",
  },
  // uri paste flow
  uriPaste: {
    title: "Add from URI",
    description: "Paste an otpauth:// URI to add a token.",
    placeholder: "otpauth://totp/...",
    parse: "Parse URI",
    parsing: "Parsing...",
    parseError: "Invalid URI. Please paste a valid otpauth:// URI.",
    cancel: "Cancel",
  },
  // screen QR capture flow
  screenQR: {
    title: "Scan Screen",
    description:
      "The screenshot dialog will open. Capture the area containing the QR code.",
    scanning: "Waiting for screenshot...",
    scanButton: "Capture screen",
    tryAgain: "Try again",
    noQRFound:
      "No QR code found in the captured image. Make sure the QR code is visible on screen and try again.",
    scanError: "Scan failed. Make sure xdg-desktop-portal is installed.",
  },
  // go error sentinel mapping
  errors: {
    incorrectPassword: "Incorrect password",
    passwordRequired: "Password required",
    noParserFound: "No supported backup format found",
    fileEmpty: "File is empty",
    fileTooLarge: "File is too large to import",
    notABackupFile: "This does not appear to be a backup file",
    generic: "An error occurred. Please try again.",
  },
  // format help
  formatHelp: {
    heading: "Supported backup formats",
    showFormats: "Supported formats",
    hideFormats: "Hide formats",
  },
  // add token page
  addToken: {
    heading: "Add New Token",
    headerSubtitle: "Securely import or create a new two-factor authentication key",
    footerSecurityNote: "End-to-end encrypted storage",
    importBackup: "Import Backup",
    cancel: "Cancel",
    tileManual: "Enter manually",
    tileManualDesc: "Type in the secret key and account details",
    tileScanFile: "Scan QR image",
    tileScanFileDesc: "Select an image file containing a QR code",
    tileScanScreen: "Scan screen",
    tileScanScreenDesc: "Capture a QR code from your screen",
    tilePasteURI: "Paste URI",
    tilePasteURIDesc: "Paste an otpauth:// URI directly",
  },
  // clipboard
  clipboard: {
    cleared: "Clipboard cleared",
  },
  // common shared strings
  common: {
    ok: "OK",
    dismiss: "Dismiss",
    appName: "deskOTP",
  },
} as const;

export type TranslationKeys = typeof en;

/**
 * Structural shape of a locale object: same key tree as TranslationKeys but
 * with all leaf values widened to `string`. Use `satisfies LocaleShape` in
 * translation files to enforce key parity without requiring exact English
 * string values.
 */
type WidenLeaves<T> = {
  [K in keyof T]: T[K] extends string ? string : WidenLeaves<T[K]>;
};
export type LocaleShape = WidenLeaves<TranslationKeys>;
