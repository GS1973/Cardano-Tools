import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises, RouterLinkStub } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'
import poolCurrent from '../fixtures/pool-current.json'

vi.mock('qrcode', () => ({
  default: { toDataURL: vi.fn().mockResolvedValue('data:image/png;base64,fake') },
  toDataURL: vi.fn().mockResolvedValue('data:image/png;base64,fake'),
}))

vi.mock('@spo-tools/shared-frontend/components/QRScanner.vue', () => ({
  default: {
    name: 'QRScanner',
    template: '<div data-stub="qr-scanner"></div>',
  },
}))

import PoolParamsView from '../../src/views/PoolParamsView.vue'

function makeRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { template: '<div/>' } },
      { path: '/pool-params', component: PoolParamsView },
      { path: '/setup', component: { template: '<div/>' } },
      { path: '/pairing', component: { template: '<div/>' } },
    ],
  })
}

function mockFetch(handlers: Record<string, (url: string, init?: RequestInit) => unknown>) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    for (const [pattern, handler] of Object.entries(handlers)) {
      if (url.startsWith(pattern)) {
        const result = handler(url, init)
        return new Response(JSON.stringify(result), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
    }
    return new Response('not mocked: ' + url, { status: 404 })
  })
}

describe('PoolParamsView (baseline)', () => {
  beforeEach(() => {
    globalThis.fetch = mockFetch({
      '/api/pool/current': () => poolCurrent,
      '/api/pool/pledge-precheck': () => ({
        owner_stake_address: poolCurrent.owners[0],
        owner_balance_lovelace: 200_000_000_000,
        pledge_lovelace: poolCurrent.pledge_lovelace,
        meets_pledge: true,
        shortfall_lovelace: 0,
      }),
    }) as typeof fetch
  })

  async function mountView() {
    const router = makeRouter()
    await router.push('/pool-params')
    const w = mount(PoolParamsView, {
      global: {
        plugins: [router],
        stubs: { 'router-link': RouterLinkStub },
      },
    })
    await flushPromises()
    return w
  }

  function findSendToSigner(w: ReturnType<typeof mount>) {
    return w
      .findAll('button')
      .find((b) => b.text().includes('Send to Signer'))
  }

  it('mounts and fetches /api/pool/current', async () => {
    const w = await mountView()
    expect(w.text()).toContain('Pool parameter update')
    const calls = (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls
    const urls = calls.map((c) => (typeof c[0] === 'string' ? c[0] : c[0].toString()))
    expect(urls.some((u) => u.includes('/api/pool/current'))).toBe(true)
  })

  it('renders the current pool values once fetched', async () => {
    const w = await mountView()
    expect(w.text().toLowerCase()).toContain('pledge')
    expect(w.text().toLowerCase()).toContain('fixed cost')
    expect(w.text().toLowerCase()).toContain('margin')
  })

  it('disables Send-to-Signer when fixed cost is below the protocol minimum', async () => {
    globalThis.fetch = mockFetch({
      '/api/pool/current': () => ({ ...poolCurrent, fixed_cost_lovelace: 1_000_000 }),
    }) as typeof fetch
    const w = await mountView()
    const btn = findSendToSigner(w)
    expect(btn).toBeDefined()
    expect(btn!.classes()).toContain('v-btn--disabled')
  })

  it('disables Send-to-Signer when payment UTXO cannot cover the fee', async () => {
    globalThis.fetch = mockFetch({
      '/api/pool/current': () => ({ ...poolCurrent, can_cover_fee: false }),
    }) as typeof fetch
    const w = await mountView()
    const btn = findSendToSigner(w)
    expect(btn).toBeDefined()
    expect(btn!.classes()).toContain('v-btn--disabled')
  })

  it('shows a NotPaired card when /api/pool/current returns not_paired', async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response(
        JSON.stringify({ code: 'not_paired', message: 'pair first' }),
        { status: 428, headers: { 'Content-Type': 'application/json' } },
      ),
    ) as typeof fetch
    const w = await mountView()
    expect(w.text().toLowerCase()).toMatch(/pair(ing|ed)/)
  })

  it('shows a NotConfigured card when /api/pool/current returns not_configured', async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response(
        JSON.stringify({ code: 'not_configured', message: 'pool not configured' }),
        { status: 412, headers: { 'Content-Type': 'application/json' } },
      ),
    ) as typeof fetch
    const w = await mountView()
    expect(w.text().toLowerCase()).toContain('pool not configured')
  })
})
