import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises, RouterLinkStub } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'

vi.mock('qrcode', () => ({
  default: { toDataURL: vi.fn().mockResolvedValue('data:image/png;base64,fake') },
  toDataURL: vi.fn().mockResolvedValue('data:image/png;base64,fake'),
}))

vi.mock('@wallet-tools/shared-frontend/components/QRScanner.vue', () => ({
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
          wallets: [
            {
              label: 'Main',
              payment_skey_path: '/media/keys/payment.skey',
              stake_skey_path: '/media/keys/stake.skey',
              payment_skey: { status: 'valid' },
              stake_skey: { status: 'valid' },
              wallet_address: {
                base_address_bech32: 'addr1qtest',
                stake_address_bech32: 'stake1test',
                payment_keyhash_hex: '00'.repeat(28),
                stake_keyhash_hex: '11'.repeat(28),
              },
            },
          ],
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (url.startsWith('/api/sign/receive')) {
        return new Response(JSON.stringify({
          kind: 'withdraw-rewards',
          request_fingerprint: 'a37f-2c91-5be2-c8d4',
          request: {
            kind: 'withdraw_rewards',
            tx_body_cbor_hex: 'a400',
            rewards_lovelace: '50000000',
            fee_lovelace: '180000',
            change_lovelace: '52820000',
            change_assets: [],
            ttl_slot: '100',
            payment_address_bech32: 'addr1qtest',
            stake_address_bech32: 'stake1test',
            inputs: [{ tx_hash_hex: '09'.repeat(32), tx_index: 0, amount_lovelace: '3000000', address_bech32: 'addr1qtest' }],
            operator_pin_proof: '00',
            chain_context: {},
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

  it('shows a reward withdrawal with its amount, reward account and own-address guard', async () => {
    const router = makeRouter()
    await router.push('/')
    const w = mount(SignView, {
      global: {
        plugins: [router],
        stubs: { 'router-link': RouterLinkStub },
      },
    })
    await flushPromises()
    await w.find('textarea').setValue('ur:fragment/1')
    const submit = w.findAll('button').find((b) => b.text().includes('Submit'))
    expect(submit, 'Submit button rendered').toBeTruthy()
    await submit!.trigger('click')
    await flushPromises()
    const text = w.text()
    expect(text).toContain('Verify reward withdrawal before signing')
    expect(text).toContain('50 ₳')
    expect(text).toContain('stake1test')
    expect(text).toContain('addr1qtest')
    expect(text).toContain('Signing wallet: Main')
  })
})
