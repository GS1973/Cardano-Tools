import { defineConfig, type ProxyOptions } from 'vite'
import vue from '@vitejs/plugin-vue'
import vuetify from 'vite-plugin-vuetify'
import path from 'node:path'
import { readFileSync } from 'node:fs'
const pkg = JSON.parse(readFileSync(path.resolve(__dirname, 'package.json'), 'utf-8'))

// Proxy target defaults to :8401 (the README quickstart port; the binary
// itself has no default: --listen is mandatory); override via
// WALLET_TOOLS_SIGNER_PROXY when the binary listens elsewhere.
const signerProxyTarget = process.env.WALLET_TOOLS_SIGNER_PROXY ?? 'http://localhost:8401'

// The string-shorthand proxy rewrites only the Host header (changeOrigin);
// the browser's `Origin: http://localhost:5174` is forwarded untouched, and
// the backend's CSRF guard only accepts its own origin, so every proxied
// POST/PUT/DELETE would 403. Rewrite Origin to the backend's own origin so
// the dev proxy passes the guard without weakening it.
const proxyToBackend: ProxyOptions = {
  target: signerProxyTarget,
  changeOrigin: true,
  configure: (proxy) => {
    proxy.on('proxyReq', (proxyReq) => proxyReq.setHeader('origin', signerProxyTarget))
  },
}

export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  plugins: [
    vue(),
    vuetify({ autoImport: true }),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5174,
    proxy: {
      '/api': proxyToBackend,
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
