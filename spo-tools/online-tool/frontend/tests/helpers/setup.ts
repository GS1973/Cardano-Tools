import { config } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createPinia } from 'pinia'
import { vi } from 'vitest'

const vuetify = createVuetify({ components, directives })
config.global.plugins = [vuetify, createPinia()]

if (typeof window !== 'undefined' && !window.matchMedia) {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }),
  })
}

if (typeof window !== 'undefined' && !('ResizeObserver' in window)) {
  ;(window as unknown as { ResizeObserver: unknown }).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
}

if (typeof window !== 'undefined' && !window.crypto?.randomUUID) {
  Object.assign(window.crypto ?? {}, {
    randomUUID: () => 'test-uuid-' + Math.random().toString(36).slice(2),
  })
}

// jsdom does not implement scrollIntoView; stub it for tests that touch it.
if (typeof Element !== "undefined") {
  HTMLElement.prototype.scrollIntoView = function () {}
}

// jsdom does not implement visualViewport; Vuetify VOverlay (used by v-dialog)
// reads it during positioning. Stub minimal shape so dialogs can mount.
if (typeof window !== 'undefined' && !('visualViewport' in window)) {
  Object.defineProperty(window, 'visualViewport', {
    writable: true,
    value: {
      width: 1024,
      height: 768,
      offsetLeft: 0,
      offsetTop: 0,
      pageLeft: 0,
      pageTop: 0,
      scale: 1,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    },
  })
}

if (typeof Element !== "undefined") {
  HTMLElement.prototype.scrollIntoView = function () {}
}
