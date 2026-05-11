// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

/**
 * Spanish (es) translations for deskOTP.
 *
 * Mirrors the structure of en.ts exactly — all keys must be present.
 * Key parity is enforced at compile time via `satisfies TranslationKeys`,
 * so any missing or extra key in `es` will surface as a type error at build time.
 *
 * Rules for translators:
 *   - Keep all object keys unchanged (keys are the stable contract)
 *   - Keep all {{variableName}} interpolation placeholders unchanged
 *   - Keep product names unchanged (deskOTP)
 */

import type { LocaleShape } from "./en";

export const es = {
  // sidebar
  sidebar: {
    allTokens: "Todos los Tokens",
    settings: "Configuración",
    addNewToken: "Agregar Nuevo Token",
    vault: "Bóveda",
    groups: "Grupos",
    newGroup: "Nuevo Grupo",
    noIcon: "Sin icono",
    contextMenu: {
      rename: "Editar",
      moveUp: "Subir",
      moveDown: "Bajar",
      delete: "Eliminar",
      confirmDeleteTitle: "Eliminar Grupo",
      confirmDeleteMessage: 'Eliminar "{{groupName}}"? Los tokens quedaran sin grupo.',
      newGroupPlaceholder: "Nombre del grupo",
    },
  },
  // nav
  nav: {
    tokens: "Cuentas",
    settings: "Configuración",
    addToken: "Añadir token",
    addTokenTooltip: "Añadir un nuevo token",
    importBackup: "Importar copia de seguridad",
    lock: "Bloquear",
    lockTooltip: "Bloquear aplicaci\u00f3n",
    lockDisabledTooltip:
      "Establece una contrase\u00f1a maestra para habilitar el bloqueo",
    lockDisabledMessage:
      "Establece una contrase\u00f1a maestra en Configuraci\u00f3n para habilitar el bloqueo.",
    themeDark: "Cambiar a modo claro",
    themeLight: "Cambiar a modo oscuro",
  },
  // tokens page
  tokensPage: {
    heading: "Cuentas",
    noAccounts: "Aún no hay cuentas",
    noAccountsHint:
      "Haz clic en Importar en la barra de herramientas para comenzar",
    noMatches: "No hay cuentas coincidentes",
    searchPlaceholder: "Buscar cuentas",
    copied: "¡Copiado!",
    secureVaultHeading: "Tokens",
    activeTokenCount: "{{count}} tokens activos",
    managingTokens: "Gestionando {{count}} tokens de acceso seguros en tus plataformas.",
    addNewToken: "Agregar Nuevo Token",
  },
  // group filter bar
  groupFilterBar: {
    all: "Todos",
  },
  // sort dropdown
  sort: {
    label: "Ordenar",
    issuer: "Emisor",
    name: "Nombre",
    dateAdded: "Fecha de adición",
    usageCount: "Uso",
    ascending: "A-Z",
    descending: "Z-A",
    oldest: "Más antiguo",
    newest: "Más reciente",
    least: "Menos",
    most: "Más",
  },
  // import area
  importArea: {
    importFailed: "Error al importar",
    openFileFailed: "Error al abrir el diálogo de archivo",
    incorrectPassword: "Contraseña incorrecta. Por favor, inténtalo de nuevo.",
    decryptionFailed: "Error al descifrar",
    importButton: "Importar copia de seguridad",
    importing: "Importando...",
    hint: "Importa un archivo de copia de seguridad para comenzar",
  },
  importResult: {
    title: "Importación completa",
    addedAndSkipped: "{{added}} añadidas, {{skipped}} ya existían",
    addedAndSkippedFormat:
      "{{added}} agregadas, {{skipped}} ya existian ({{formatName}})",
    addedOnly: "{{added}} añadidas",
    addedOnlyFormat: "{{added}} agregadas de {{formatName}}",
    allExisted: "Las {{skipped}} ya existían",
    noneFound: "No se encontraron cuentas en el archivo",
    noTokensFound: "No se encontraron tokens en esta copia de {{formatName}}",
    encryptionNotice: "Tus tokens se almacenan sin cifrado.",
    setupEncryption: "Configurar una contraseña maestra",
  },
  // password modal
  passwordModal: {
    title: "Copia de seguridad cifrada",
    description:
      "Esta copia de seguridad está cifrada. Introduce la contraseña que estableciste al crearla.",
    placeholder: "Contraseña de la copia",
    cancel: "Cancelar",
    unlock: "Desbloquear",
    unlocking: "Descifrando...",
  },
  // unlock screen
  unlockScreen: {
    title: "deskOTP",
    description: "Introduce tu contraseña maestra para desbloquear",
    placeholder: "Contraseña maestra",
    submit: "Desbloquear Boveda",
    submitting: "Desbloqueando...",
    incorrectPassword: "Contraseña incorrecta",
    genericError: "Error al desbloquear el almacén",
    vaultLocked: "Boveda Bloqueada",
    showPassword: "Mostrar contrasena",
    hidePassword: "Ocultar contrasena",
    aesLabel: "AES-256-GCM",
    scryptLabel: "scrypt KDF",
  },
  // settings page
  settings: {
    heading: "Configuración",
    vaultConfigTitle: "Configuracion del Vault",
    vaultConfigSubtitle: "Ajusta los umbrales de seguridad y los parametros de interfaz para tu entorno cifrado.",
    // sections
    personalisation: "Personalización",
    security: "Seguridad",
    about: "Acerca de",
    // personalisation rows
    theme: "Tema",
    themeDesc: "Cambiar entre modo claro y oscuro",
    themeDark: "Oscuro",
    themeLight: "Claro",
    language: "Idioma",
    languageDesc: "Cambiar idioma de visualización",
    languageEnglish: "Inglés",
    languageSpanish: "Español",
    displayDensity: "Densidad de visualización",
    displayDensityDesc: "Ajustar tamaño y espaciado de tarjetas",
    densityCompact: "Compacto",
    densityDefault: "Predeterminado",
    densityComfortable: "Cómodo",
    // security
    setPasswordHeading: "Establecer contraseña maestra",
    setPasswordDesc:
      "Cifra tu almacén con una contraseña maestra. Deberás introducirla cada vez que abras la aplicación.",
    setPasswordNew: "Nueva contraseña",
    setPasswordConfirm: "Confirmar contraseña",
    setPasswordMismatch: "Las contraseñas no coinciden",
    setPasswordSubmit: "Establecer contraseña",
    setPasswordSubmitting: "Estableciendo...",
    setPasswordSuccess: "Contraseña establecida correctamente",
    changePasswordHeading: "Cambiar contraseña",
    changePasswordCurrent: "Contraseña actual",
    changePasswordNew: "Nueva contraseña",
    changePasswordConfirm: "Confirmar nueva contraseña",
    changePasswordMismatch: "Las contraseñas no coinciden",
    changePasswordSubmit: "Cambiar contraseña",
    changePasswordSubmitting: "Cambiando...",
    changePasswordSuccess: "Contraseña cambiada correctamente",
    removePasswordHeading: "Eliminar contraseña",
    removePasswordDesc:
      "Eliminar el cifrado y volver al almacenamiento sin protección. Esta acción no se puede deshacer.",
    removePasswordCurrent: "Contraseña actual",
    removePasswordSubmit: "Eliminar contraseña",
    removePasswordSubmitting: "Eliminando...",
    removePasswordSuccess: "Contraseña eliminada",
    setPasswordError: "Error al establecer la contraseña",
    changePasswordError: "Error al cambiar la contraseña",
    removePasswordError: "Error al eliminar la contraseña",
    incorrectPassword: "Contraseña incorrecta",
    autoLock: "Bloqueo automático",
    autoLockDesc: "Bloquear almacén por inactividad",
    autoLock1min: "1 minuto",
    autoLock5min: "5 minutos",
    autoLock15min: "15 minutos",
    autoLock30min: "30 minutos",
    autoLockNever: "Nunca",
    clipboardClear: "Limpieza del portapapeles",
    clipboardClearDesc: "Limpiar portapapeles después de copiar un código",
    clipboardClear10s: "10 segundos",
    clipboardClear20s: "20 segundos",
    clipboardClear30s: "30 segundos",
    clipboardClear60s: "60 segundos",
    clipboardClearNever: "Nunca",
    version: "Versión",
    copyright: "2026 deskOTP contributors",
    // security banner
    bannerTitle: "Protege tus tokens con una contraseña maestra",
    bannerDesc:
      "Tu almacén no está cifrado. Establece una contraseña maestra en la",
    bannerLink: "sección de Seguridad",
    bannerDescSuffix: "a continuación para cifrar tus tokens.",
    bannerDismiss: "Descartar recomendación",
    // backup section
    backup: "Copia de seguridad",
    backupDirectory: "Directorio",
    backupDirectoryDesc: "Donde se guardan las copias",
    backupDirectoryNone: "Sin directorio",
    backupBrowse: "Explorar",
    backupSchedule: "Programar",
    backupScheduleDesc: "Frecuencia de copia automática",
    backupScheduleOff: "Desactivado",
    backupScheduleDaily: "Diario",
    backupScheduleWeekly: "Semanal",
    backupRetention: "Conservar",
    backupRetentionDesc: "Copias a conservar",
    backupRetention3: "3 copias",
    backupRetention5: "5 copias",
    backupRetention10: "10 copias",
    backupLastBackup: "Última copia",
    backupLastBackupNever: "Nunca",
    backupExportNow: "Exportar ahora",
    backupExporting: "Exportando...",
    backupExported: "Exportado",
    backupExportError: "Error de exportación",
    backupBrowseError: "No se pudo abrir el selector de carpetas",
    backupExportDisabledTooltip: "Establece un directorio primero",
    backupError: "Error de copia",
  },
  // edit dialog
  editDialog: {
    title: "Editar cuenta",
    loading: "Cargando...",
    loadError: "Error al cargar los detalles",
    close: "Cerrar",
    changeIconTitle: "Cambiar icono",
    labelName: "Nombre",
    placeholderName: "Nombre de la cuenta",
    labelIssuer: "Emisor",
    placeholderIssuer: "Proveedor del servicio",
    labelGroup: "Grupo",
    placeholderGroup: "Nombre del grupo",
    groupHint: "Escribe para crear un grupo nuevo o seleccionar uno existente",
    labelNote: "Nota",
    placeholderNote: "Nota opcional",
    showAdvanced: "Mostrar avanzado",
    hideAdvanced: "Ocultar avanzado",
    labelType: "Tipo",
    labelAlgorithm: "Algoritmo",
    labelPeriod: "Periodo",
    labelDigits: "Dígitos",
    labelSecret: "Secreto",
    placeholderSecret: "Introducir nuevo secreto",
    changeSecret: "Cambiar secreto",
    cancelSecretChange: "Cancelar",
    labelUsageCount: "Contador de uso",
    saveError: "Error al guardar los cambios",
    cancel: "Cancelar",
    save: "Guardar",
    saving: "Guardando...",
  },
  // group picker
  groupPicker: {
    placeholder: "Sin grupo",
    none: "Ninguno",
    createButton: "Crear",
    creating: "Creando...",
    createError: "Error al crear el grupo",
    duplicateError: "El grupo ya existe",
  },
  // confirm dialog
  confirmDialog: {
    cancel: "Cancelar",
  },
  // delete flow
  deleteAccount: {
    title: "Eliminar cuenta",
    message:
      '¿Estás seguro de que quieres eliminar "{{name}}"?\n\nSe eliminará la cuenta y su clave secreta.',
    confirm: "Eliminar",
    undoMessage: "Se eliminó {{name}}",
    undo: "Deshacer",
  },
  // context menu
  contextMenu: {
    copy: "Copiar",
    edit: "Editar",
    delete: "Eliminar",
  },
  // icon picker
  iconPicker: {
    title: "Elegir icono",
    searchPlaceholder: "Buscar iconos...",
    noMatches: 'No hay iconos que coincidan con "{{query}}"',
    removeIcon: "Quitar icono",
    revertConfirm: "¿Volver al avatar de letra?",
    cancel: "Cancelar",
    remove: "Quitar",
    suggested: "Sugeridos",
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
    title: "Revisar token",
    labelIssuer: "Emisor",
    placeholderIssuer: "Proveedor del servicio",
    labelName: "Nombre",
    placeholderName: "Nombre de la cuenta",
    labelGroup: "Grupo",
    changeIconTitle: "Cambiar icono",
    showAdvanced: "Mostrar avanzado",
    hideAdvanced: "Ocultar avanzado",
    labelType: "Tipo",
    labelAlgorithm: "Algoritmo",
    labelPeriod: "Periodo (segundos)",
    labelDigits: "Digitos",
    labelSecret: "Secreto",
    labelCounter: "Contador",
    save: "Guardar",
    saving: "Guardando...",
    cancel: "Cancelar",
    saveError: "Error al guardar el token",
    duplicateTitle: "Token duplicado",
    duplicateMessage:
      'Ya existe un token para "{{issuer}}" / "{{name}}". Agregarlo de todas formas?',
    duplicateConfirm: "Agregar de todos modos",
  },
  // file QR flow
  fileQR: {
    title: "Agregar desde imagen QR",
    description:
      "Selecciona un archivo de imagen que contenga un codigo QR para agregar un token.",
    scanFile: "Escanear archivo",
    scanning: "Escaneando...",
    scanError: "No se pudo leer el codigo QR de la imagen",
    tryAgain: "Intentar de nuevo",
  },
  // manual entry form
  manualEntry: {
    title: "Agregar token manualmente",
    labelIssuer: "Emisor",
    placeholderIssuer: "Proveedor del servicio (ej. GitHub)",
    labelName: "Nombre de la cuenta",
    placeholderName: "tu@correo.com",
    labelSecret: "Clave secreta",
    placeholderSecret: "Secreto codificado en Base32",
    labelGroup: "Grupo",
    secretHint: "Se encuentra en la configuracion 2FA de tu cuenta",
    secretInvalidBase32:
      "Clave secreta invalida. Usa solo caracteres A-Z y 2-7.",
    proceed: "Continuar",
    cancel: "Cancelar",
    showAdvanced: "Mostrar avanzado",
    hideAdvanced: "Ocultar avanzado",
    labelType: "Tipo",
    labelAlgorithm: "Algoritmo",
    labelPeriod: "Periodo (segundos)",
    labelDigits: "Digitos",
    labelCounter: "Contador",
  },
  // uri paste flow
  uriPaste: {
    title: "Agregar desde URI",
    description: "Pega una URI otpauth:// para agregar un token.",
    placeholder: "otpauth://totp/...",
    parse: "Analizar URI",
    parsing: "Analizando...",
    parseError: "URI no valida. Pega una URI otpauth:// valida.",
    cancel: "Cancelar",
  },
  // screen QR capture flow
  screenQR: {
    title: "Captura de pantalla",
    description:
      "Se abrira el dialogo de captura. Selecciona el area que contiene el codigo QR.",
    scanning: "Esperando captura de pantalla...",
    scanButton: "Capturar pantalla",
    tryAgain: "Intentar de nuevo",
    noQRFound:
      "No se encontro un codigo QR en la imagen capturada. Asegurate de que el codigo QR sea visible en pantalla e intentalo de nuevo.",
    scanError:
      "Escaneo fallido. Asegurate de que xdg-desktop-portal esta instalado.",
  },
  // go error sentinel mapping
  errors: {
    incorrectPassword: "Contraseña incorrecta",
    passwordRequired: "Se requiere contraseña",
    noParserFound: "No se encontro un formato de copia de seguridad compatible",
    fileEmpty: "El archivo esta vacio",
    fileTooLarge: "El archivo es demasiado grande para importar",
    notABackupFile: "Este archivo no parece ser una copia de seguridad",
    generic: "Se produjo un error. Por favor, inténtalo de nuevo.",
  },
  // format help
  formatHelp: {
    heading: "Formatos de copia de seguridad compatibles",
    showFormats: "Formatos compatibles",
    hideFormats: "Ocultar formatos",
  },
  // add token page
  addToken: {
    heading: "Agregar Nuevo Token",
    headerSubtitle: "Importa o crea una nueva clave de autenticacion de dos factores de forma segura",
    footerSecurityNote: "Almacenamiento cifrado de extremo a extremo",
    importBackup: "Importar Respaldo",
    cancel: "Cancelar",
    tileManual: "Ingresar manualmente",
    tileManualDesc: "Escribe la clave secreta y los datos de la cuenta",
    tileScanFile: "Escanear imagen QR",
    tileScanFileDesc:
      "Selecciona un archivo de imagen que contenga un codigo QR",
    tileScanScreen: "Captura de pantalla",
    tileScanScreenDesc: "Captura un codigo QR de tu pantalla",
    tilePasteURI: "Pegar URI",
    tilePasteURIDesc: "Pega una URI otpauth:// directamente",
  },
  // clipboard
  clipboard: {
    cleared: "Portapapeles limpiado",
  },
  // common shared strings
  common: {
    ok: "Aceptar",
    dismiss: "Cerrar",
    appName: "deskOTP",
  },
} satisfies LocaleShape;
