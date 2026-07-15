import { defineConfig, type ProxyOptions } from 'vite'
import vue from '@vitejs/plugin-vue'
import vuetify from 'vite-plugin-vuetify'
import path from 'node:path'
import { readFileSync } from 'node:fs'
const pkg = JSON.parse(readFileSync(path.resolve(__dirname, 'package.json'), 'utf-8'))

// During `npm run dev`, Vite serves on :5173 and proxies /api to the Axum
// backend. Default target :8300; override with DREP_TOOLS_ONLINE_PROXY.
// In production the binary serves dist/ directly.
const onlineProxyTarget = process.env.DREP_TOOLS_ONLINE_PROXY ?? 'http://localhost:8300'

// The string-shorthand proxy rewrites only the Host header (changeOrigin);
// the browser's `Origin: http://localhost:5173` is forwarded untouched, and
// the backend's CSRF guard only accepts its own origin — so every proxied
// POST/PUT/DELETE would 403. Rewrite Origin to the backend's own origin so
// the dev proxy passes the guard without weakening it.
const proxyToBackend: ProxyOptions = {
  target: onlineProxyTarget,
  changeOrigin: true,
  configure: (proxy) => {
    proxy.on('proxyReq', (proxyReq) => proxyReq.setHeader('origin', onlineProxyTarget))
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
    port: 5173,
    proxy: {
      '/api': proxyToBackend,
      '/health': proxyToBackend,
      '/status': proxyToBackend,
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Offline single-page tool: one self-contained bundle is intentional, so
    // raise Vite's 500 kB advisory above the Vuetify-driven size rather than
    // code-split (an air-gapped tool gains nothing from lazy chunks).
    chunkSizeWarningLimit: 2000,
  },
})
