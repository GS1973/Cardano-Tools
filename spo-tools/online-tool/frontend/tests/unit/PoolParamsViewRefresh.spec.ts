import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises, RouterLinkStub } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'
import poolCurrent from '../fixtures/pool-current.json'

vi.mock('qrcode', () => ({
  default: { toDataURL: vi.fn().mockResolvedValue('data:image/png;base64,fake') },
  toDataURL: vi.fn().mockResolvedValue('data:image/png;base64,fake'),
}))

vi.mock('@spo-tools/shared-frontend/components/QRScanner.vue', () => ({
  default: { name: 'QRScanner', template: '<div data-stub="qr-scanner"></div>' },
}))

import PoolParamsView from '../../src/views/PoolParamsView.vue'
import type { ChainContext } from '@spo-tools/shared-frontend/types/core'
import type { PoolUpdateRequest, PoolUpdateResult } from '@spo-tools/shared-frontend/types/wire'

// Typed as the ts-rs-generated wire types so tsc catches serializer/shape
// regressions (u64 fields are wire-encoded as strings).
const chainContext: ChainContext = {
  current_slot: '100',
  current_epoch: '1',
  current_kes_period: '0',
  epoch_ends_at_unix: String(Math.floor(Date.now() / 1000) + 3600),
  opcert_expires_at_unix: null,
  built_at_unix: String(Math.floor(Date.now() / 1000)),
}

const buildRequest: PoolUpdateRequest = {
  kind: 'pool_update',
  tx_body_cbor_hex: 'aabb',
  fee_lovelace: '200000',
  change_to_payment_address_lovelace: '0',
  ttl_slot: '0',
  payment_address_bech32: 'addr_test',
  pool_id_bech32: poolCurrent.pool_id_bech32,
  vrf_keyhash_hex: '',
  pledge_lovelace: '100000000000',
  fixed_cost_lovelace: '170000000',
  margin_numerator: '1',
  margin_denominator: '100',
  reward_account_bech32: poolCurrent.owners[0],
  pool_owner_stake_addresses: poolCurrent.owners,
  relays: [],
  metadata_url: null,
  metadata_hash_hex: null,
  inputs: [{
    tx_hash_hex: 'aa'.repeat(32),
    tx_index: 0,
    amount_lovelace: '5000000000',
    address_bech32: 'addr_test',
  }],
  operator_pin_proof: '00000000',
  chain_context: chainContext,
}

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

describe('PoolParamsView refresh', () => {
  beforeEach(() => {
    document.body.innerHTML = ''
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url.startsWith('/api/pool/current')) {
        return new Response(JSON.stringify(poolCurrent), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      if (url.startsWith('/api/pool/pledge-precheck')) {
        return new Response(JSON.stringify({
          owner_stake_address: poolCurrent.owners[0],
          owner_balance_lovelace: 200_000_000_000,
          pledge_lovelace: poolCurrent.pledge_lovelace,
          meets_pledge: true,
          shortfall_lovelace: 0,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response('not mocked: ' + url, { status: 404 })
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

  it('Refresh-button click resets dirty form to server-side values', async () => {
    const w = await mountView()
    const pledgeInput = w
      .findAll('input[type="number"]')
      .find((i) => (i.element as HTMLInputElement).value === '100000')
    expect(pledgeInput, 'pledge input initially populated from fetch').toBeDefined()

    await pledgeInput!.setValue('999999')
    expect((pledgeInput!.element as HTMLInputElement).value).toBe('999999')

    const refreshBtn = w.findAll('button').find((b) => b.text() === 'Refresh')
    expect(refreshBtn, 'Refresh button present').toBeDefined()
    await refreshBtn!.trigger('click')
    await flushPromises()

    expect((pledgeInput!.element as HTMLInputElement).value).toBe('100000')
  })

  it('Receive-result flow shows Submit-to-chain card after pasting signed UR', async () => {
    const buildPayload = {
      request: buildRequest,
      ur_fragments: ['ur:spo-tools-action-v2/recv-test'],
    }
    const resultPayload: PoolUpdateResult = {
      body_hash_hex: 'cafebabe',
      witnesses: [{ role: 'owner_stake', vkey_hex: '00', signature_hex: '11' }],
    }

    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url.startsWith('/api/pool/current')) {
        return new Response(JSON.stringify(poolCurrent), { status: 200 })
      }
      if (url.startsWith('/api/pool/build')) {
        return new Response(JSON.stringify(buildPayload), { status: 200 })
      }
      if (url.startsWith('/api/pool/result')) {
        return new Response(JSON.stringify(resultPayload), { status: 200 })
      }
      return new Response('not mocked: ' + url, { status: 404 })
    }) as typeof fetch

    const w = await mountView()
    const sendBtn = w.findAll('button').find((b) => b.text() === 'Send to Signer')
    await sendBtn!.trigger('click')
    await flushPromises()
    // Modal opens — fill 4-digit PIN, then click its primary button.
    const pinField = document.querySelector('input[inputmode="numeric"]') as HTMLInputElement | null
    if (pinField) {
      pinField.value = '1234'
      pinField.dispatchEvent(new Event('input', { bubbles: true }))
      pinField.dispatchEvent(new Event('change', { bubbles: true }))
    }
    await flushPromises()
    const modalConfirm = document.querySelectorAll('button')
    const target = Array.from(modalConfirm).find((b) => b.textContent?.trim() === 'Send to signer')
    target?.click()
    await flushPromises()

    const recvBtn = w.findAll('button').find((b) => b.text() === 'Receive from Signer')
    await recvBtn!.trigger('click')
    await flushPromises()

    const textarea = w.find('textarea')
    expect(textarea.exists(), 'receive textarea visible').toBe(true)
    await textarea.setValue('ur:spo-tools-action-v2/signed-test')

    const recvResultBtn = w.findAll('button').find((b) => b.text() === 'Receive result')
    expect(recvResultBtn).toBeDefined()
    await recvResultBtn!.trigger('click')
    await flushPromises()

    expect(w.text(), 'Result-card with Submit-to-chain button rendered').toContain('Signed and ready to submit')
    expect(w.text()).toContain('Submit to chain')
  })

  it('Editing a form field after a build invalidates and hides the stale QR', async () => {
    const mockBuilt = {
      request: buildRequest,
      ur_fragments: ['ur:spo-tools-action-v2/staleguard-test'],
    }
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url.startsWith('/api/pool/current')) {
        return new Response(JSON.stringify(poolCurrent), { status: 200 })
      }
      if (url.startsWith('/api/pool/build')) {
        return new Response(JSON.stringify(mockBuilt), { status: 200 })
      }
      return new Response('not mocked: ' + url, { status: 404 })
    }) as typeof fetch

    const w = await mountView()
    const sendBtn = w.findAll('button').find((b) => b.text() === 'Send to Signer')
    await sendBtn!.trigger('click')
    await flushPromises()
    // Modal opens — fill 4-digit PIN, then click its primary button.
    const pinField = document.querySelector('input[inputmode="numeric"]') as HTMLInputElement | null
    if (pinField) {
      pinField.value = '1234'
      pinField.dispatchEvent(new Event('input', { bubbles: true }))
      pinField.dispatchEvent(new Event('change', { bubbles: true }))
    }
    await flushPromises()
    const modalConfirm = document.querySelectorAll('button')
    const target = Array.from(modalConfirm).find((b) => b.textContent?.trim() === 'Send to signer')
    target?.click()
    await flushPromises()
    expect(w.text(), 'send card visible after build').toContain('staleguard-test')

    // Now edit a form field — the stale QR must be discarded.
    const fixedCostInput = w
      .findAll('input[type="number"]')
      .find((i) => (i.element as HTMLInputElement).value === '170')
    expect(fixedCostInput, 'fixed-cost input present').toBeDefined()
    await fixedCostInput!.setValue('250')
    await flushPromises()

    expect(w.text(), 'stale QR hidden after form edit').not.toContain('staleguard-test')
  })

  it('Refresh-button hides any previously generated send-side QR card', async () => {
    // Override fetch so /api/pool/build returns a request + UR fragments.
    const mockBuilt = {
      request: buildRequest,
      ur_fragments: ['ur:spo-tools-action-v2/test1', 'ur:spo-tools-action-v2/test2'],
    }
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url.startsWith('/api/pool/current')) {
        return new Response(JSON.stringify(poolCurrent), { status: 200 })
      }
      if (url.startsWith('/api/pool/build')) {
        return new Response(JSON.stringify(mockBuilt), { status: 200 })
      }
      return new Response('not mocked: ' + url, { status: 404 })
    }) as typeof fetch

    const w = await mountView()
    expect(w.text()).not.toContain('ur:spo-tools-action-v2')

    // Click "Send to Signer" — this triggers /api/pool/build and renders a QR card.
    const sendBtn = w.findAll('button').find((b) => b.text() === 'Send to Signer')
    expect(sendBtn).toBeDefined()
    await sendBtn!.trigger('click')
    await flushPromises()
    // Modal opens — fill 4-digit PIN, then click its primary button.
    const pinField = document.querySelector('input[inputmode="numeric"]') as HTMLInputElement | null
    if (pinField) {
      pinField.value = '1234'
      pinField.dispatchEvent(new Event('input', { bubbles: true }))
      pinField.dispatchEvent(new Event('change', { bubbles: true }))
    }
    await flushPromises()
    const modalConfirm = document.querySelectorAll('button')
    const target = Array.from(modalConfirm).find((b) => b.textContent?.trim() === 'Send to signer')
    target?.click()
    await flushPromises()
    expect(w.text(), 'send card visible after build').toContain('ur:spo-tools-action-v2/test1')

    // Click Refresh — the send card / QR should be torn down.
    const refreshBtn = w.findAll('button').find((b) => b.text() === 'Refresh')
    await refreshBtn!.trigger('click')
    await flushPromises()
    expect(w.text(), 'send card hidden after Refresh').not.toContain('ur:spo-tools-action-v2/test1')
  })
})
