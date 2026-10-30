/**
 * Custom Vuetify theme: dark, gold #FFD700 primary on deep navy surfaces.
 * Exported as a `createVuetify` config object so each tool just spreads it
 * into its own Vuetify factory call (and can override defaults if needed).
 */
export const walletToolsTheme = {
  defaultTheme: 'dark',
  themes: {
    dark: {
      colors: {
        primary: '#FFD700',
        secondary: '#1E1E2E',
        surface: '#1E1E2E',
        background: '#121220',
        'surface-variant': '#2A2A3E',
        'on-surface': '#FFFFFF',
        'on-background': '#FFFFFF',
        'on-surface-variant': '#FFFFFF',
        'on-primary': '#000000',
      },
    },
  },
}

export const walletToolsDefaults = {
  VCard: { variant: 'flat', color: 'surface' },
  VBtn: { variant: 'tonal' },
}
