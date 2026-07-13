import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises, RouterLinkStub } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'

vi.mock('qrcode', () => ({
  default: { toDataURL: vi.fn().mockResolvedValue('data:image/png;base64,fake') },
  toDataURL: vi.fn().mockResolvedValue('data:image/png;base64,fake'),
}))

vi.mock('@spo-tools/shared-frontend/components/QRScanner.vue', () => ({
  default: { name: 'QRScanner', template: '<div data-stub="qr-scanner"></div>' },
}))

import WithdrawView from '../../src/views/WithdrawView.vue'
import type { ChainContext } from '@spo-tools/shared-frontend/types/core'
import type { WithdrawalRequest } from '@spo-tools/shared-frontend/types/wire'

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

const previewPayload = {
  pool_id_bech32: 'pool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8a7a2d',
  pool_reward_address: 'stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u',
  reward_receive_address: 'stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u',
  payment_address: 'addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw',
  rewards_available_lovelace: 5000000,
  payment_utxos: [{ tx_hash: 'aa'.repeat(32), tx_index: 0, lovelace: 10000000 }],
  payment_utxo_total_lovelace: 10000000,
  estimated_fee_lovelace: 200000,
  net_to_reward_address_lovelace: 5000000,
  change_to_payment_address_lovelace: 9800000,
  can_cover_fee: true,
  has_rewards: true,
  chain_context: chainContext,
}

const startRequest: WithdrawalRequest = {
  kind: 'withdrawal',
  tx_body_cbor_hex: 'aa',
  fee_lovelace: '200000',
  net_to_reward_address_lovelace: '5000000',
  change_to_payment_address_lovelace: '9800000',
  ttl_slot: '200',
  payment_address_bech32: previewPayload.payment_address,
  reward_receive_address_bech32: previewPayload.reward_receive_address,
  pool_reward_address_bech32: previewPayload.pool_reward_address,
  inputs: [{
    tx_hash_hex: 'aa'.repeat(32),
    tx_index: 0,
    amount_lovelace: '10000000',
    address_bech32: previewPayload.payment_address,
  }],
  operator_pin_proof: '00000000',
  chain_context: chainContext,
}

function makeRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { template: '<div/>' } },
      { path: '/withdraw', component: WithdrawView },
      { path: '/setup', component: { template: '<div/>' } },
      { path: '/pairing', component: { template: '<div/>' } },
    ],
  })
}

describe('WithdrawView confirm-send modal', () => {
  beforeEach(() => {
    document.body.innerHTML = ''
  })

  async function mountView() {
    const router = makeRouter()
    await router.push('/withdraw')
    const w = mount(WithdrawView, {
      global: {
        plugins: [router],
        stubs: { 'router-link': RouterLinkStub },
      },
    })
    await flushPromises()
    return w
  }

  it('opens the confirm-send modal on first click', async () => {
    const startCalls: Array<{ url: string; method: string; body: string | null }> = []
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url.startsWith('/api/withdraw/preview')) {
        return new Response(JSON.stringify(previewPayload), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      if (url.startsWith('/api/withdraw/start')) {
        startCalls.push({
          url,
          method: init?.method ?? 'GET',
          body: typeof init?.body === 'string' ? init.body : null,
        })
        return new Response(JSON.stringify({
          request: startRequest,
          body_hash_hex: 'bb',
          ur_fragments: ['ur:spo-tools-action-v2/test'],
          request_fingerprint: 'AA-BB-CC-DD',
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response('not mocked: ' + url, { status: 404 })
    }) as typeof fetch

    const w = await mountView()
    const sendBtn = w.findAll('button').find((b) => b.text() === 'Send to Signer')
    expect(sendBtn, 'Send-to-Signer button rendered').toBeDefined()

    await sendBtn!.trigger('click')
    await flushPromises()

    const dialogTitle = Array.from(document.querySelectorAll('*')).find(
      (el) => el.textContent?.trim() === 'Confirm reward withdrawal',
    )
    expect(dialogTitle, 'PreSendConfirm dialog title visible after first click').toBeTruthy()

    const pinField = document.querySelector('input[inputmode="numeric"]') as HTMLInputElement | null
    expect(pinField, 'PIN input rendered inside modal').toBeTruthy()
    pinField!.value = '1234'
    pinField!.dispatchEvent(new Event('input', { bubbles: true }))
    pinField!.dispatchEvent(new Event('change', { bubbles: true }))
    await flushPromises()

    const confirmBtn = Array.from(document.querySelectorAll('button')).find(
      (b) => b.textContent?.trim() === 'Send to signer',
    )
    expect(confirmBtn, 'modal confirm button found').toBeTruthy()
    confirmBtn!.click()
    await flushPromises()

    expect(startCalls.length, 'POST /api/withdraw/start fired').toBeGreaterThanOrEqual(1)
    const first = startCalls[0]
    expect(first.method, 'PIN must travel via POST body, not GET query').toBe('POST')
    expect(first.url).not.toContain('pin=')
    expect(first.body && JSON.parse(first.body).pin).toBe('1234')
  })
})
