import defaultTheme from "tailwindcss/defaultTheme.js";

export default {
  darkMode: "selector",
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      screens: {
        compact: "480px",
      },
      gridTemplateColumns: {
        "card-grid": "repeat(auto-fill, minmax(min(100%, 300px), 1fr))",
      },
      fontFamily: {
        sans: ["InterVariable", ...defaultTheme.fontFamily.sans],
        display: ["ManropeVariable", ...defaultTheme.fontFamily.sans],
        headline: ["ManropeVariable", ...defaultTheme.fontFamily.sans],
      },
      fontSize: {
        'token-page-title': ['var(--text-page-title)', { lineHeight: 'var(--lh-page-title)' }],
        'token-heading': ['var(--text-heading)', { lineHeight: 'var(--lh-heading)' }],
        'token-label':   ['var(--text-label)',   { lineHeight: 'var(--lh-label)' }],
        'token-body':    ['var(--text-body)',     { lineHeight: 'var(--lh-body)' }],
        'token-caption': ['var(--text-caption)', { lineHeight: 'var(--lh-caption)' }],
        'token-code':    ['var(--text-code)',     { lineHeight: 'var(--lh-code)' }],
      },
      spacing: {
        'density-icon':      'var(--density-icon-size)',
        'density-avatar':    'var(--density-avatar-size)',
        'density-navbar-py': 'var(--density-navbar-py)',
        'sidebar':           'var(--sidebar-width)',
      },
      width: {
        'sidebar': 'var(--sidebar-width)',
      },
      borderRadius: {
        'card': '1rem',
      },
      boxShadow: {
        'card': '0px 12px 32px rgba(25, 28, 30, 0.06)',
      },
      colors: {
        'bg':                'rgb(var(--color-bg) / <alpha-value>)',
        'surface-lowest':    'rgb(var(--color-surface-lowest) / <alpha-value>)',
        'surface-low':       'rgb(var(--color-surface-low) / <alpha-value>)',
        'surface':           'rgb(var(--color-surface) / <alpha-value>)',
        'surface-hover':     'rgb(var(--color-surface-hover) / <alpha-value>)',
        'surface-active':    'rgb(var(--color-surface-active) / <alpha-value>)',
        'surface-container':         'rgb(var(--color-surface) / <alpha-value>)',
        'surface-container-high':    'rgb(var(--color-surface-hover) / <alpha-value>)',
        'surface-container-highest': 'rgb(var(--color-surface-active) / <alpha-value>)',
        'surface-container-lowest':  'rgb(var(--color-surface-lowest) / <alpha-value>)',
        'surface-container-low':     'rgb(var(--color-surface-low) / <alpha-value>)',
        'on-surface':                'rgb(var(--color-text-primary) / <alpha-value>)',
        'on-surface-variant':        'rgb(var(--color-text-secondary) / <alpha-value>)',
        'outline':                   'rgb(var(--color-text-secondary) / <alpha-value>)',
        'outline-variant':           'rgb(var(--color-border) / <alpha-value>)',
        'border-color':      'rgb(var(--color-border) / <alpha-value>)',
        'text-primary':      'rgb(var(--color-text-primary) / <alpha-value>)',
        'text-secondary':    'rgb(var(--color-text-secondary) / <alpha-value>)',
        'text-muted':        'rgb(var(--color-text-muted) / <alpha-value>)',
        'primary':           'rgb(var(--color-primary) / <alpha-value>)',
        'on-primary':        'rgb(var(--color-on-primary) / <alpha-value>)',
        'primary-container': 'rgb(var(--color-primary-container) / <alpha-value>)',
        'secondary':         'rgb(var(--color-secondary) / <alpha-value>)',
        'tertiary':          'rgb(var(--color-tertiary) / <alpha-value>)',
        'error':             'rgb(var(--color-error) / <alpha-value>)',
        'modal-bg':          'rgb(var(--color-modal-bg) / <alpha-value>)',
        'input-bg':          'rgb(var(--color-input-bg) / <alpha-value>)',
        'success':           'rgb(var(--color-success) / <alpha-value>)',
        'warning':           'rgb(var(--color-warning) / <alpha-value>)',
      },
    },
  },
  plugins: [],
};
