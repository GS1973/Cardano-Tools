import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises, RouterLinkStub } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'

vi.mock('qrcode', () => ({
  default: { toDataURL: vi.fn().mockResolvedValue('data:image/png;base64,fake') },
  toDataURL: vi.fn().mockResolvedValue('data:image/png;base64,fake'),
}))

vi.mock('@drep-tools/shared-frontend/components/QRScanner.vue', () => ({
  default: { name: 'QRScanner', template: '<div data-stub="qr-scanner"></div>' },
}))

import SignView from '../../src/views/SignView.vue'

function makeRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: SignView },
      { path: '/pairing', component: { template: '<div/>' } },
      { path: '/setup', component: { template: '<div/>' } },
    ],
  })
}

describe('SignView mount', () => {
  beforeEach(() => {
    document.body.innerHTML = ''
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url.startsWith('/api/signer-config')) {
        return new Response(JSON.stringify({
          saved: true,
          paired: true,
          pairing_fingerprint: '01-02-03-04-05-06-07-08',
          validation: {
            drep_skey: { status: 'valid' },
            payment_skey: { status: 'valid' },
          },
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response('not mocked: ' + url, { status: 404 })
    }) as typeof fetch
  })

  it('mounts and shows the input area for pasting UR fragments', async () => {
    const router = makeRouter()
    await router.push('/')
    const w = mount(SignView, {
      global: {
        plugins: [router],
        stubs: { 'router-link': RouterLinkStub },
      },
    })
    await flushPromises()
    const textareas = w.findAll('textarea')
    expect(textareas.length, 'paste textarea rendered').toBeGreaterThanOrEqual(1)
  })

  it('renders the heading row indicating it is the signer side', async () => {
    const router = makeRouter()
    await router.push('/')
    const w = mount(SignView, {
      global: {
        plugins: [router],
        stubs: { 'router-link': RouterLinkStub },
      },
    })
    await flushPromises()
    expect(w.text()).toMatch(/Awaiting request|UR fragments|Submit/i)
  })
})
