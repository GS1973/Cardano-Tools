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
      if (url.startsWith('/api/sign/receive')) {
        return new Response(JSON.stringify({
          kind: 'drep-witness',
          request_fingerprint: 'a37f-2c91-5be2-c8d4',
          request: {
            kind: 'drep_witness_doc',
            canonical_body: '_:c14n0 <https://x/#body> _:c14n1 .\n_:c14n1 <https://x/#comment> "I vote yes."@en-us .\nnot a statement\n',
            drep_id_bech32: 'drep1test',
            operator_pin_proof: '00',
            chain_context: {},
          },
          rationale: [
            { kind: 'node', subject: '_:c14n0', field: 'body', predicate: 'https://x/#body', value: '_:c14n1' },
            { kind: 'text', subject: '_:c14n1', field: 'comment', predicate: 'https://x/#comment', value: 'I vote yes.', language: 'en-us', datatype: null },
            { kind: 'unreadable', raw: 'not a statement' },
          ],
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

  it('shows the rationale text the signer read back, and flags a line it could not read', async () => {
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
    const read = w.find('.rationale-read')
    expect(read.exists(), 'rationale reading block rendered').toBe(true)
    expect(read.text()).toContain('comment')
    expect(read.text()).toContain('I vote yes.')
    const text = w.text()
    expect(text).toContain('What the rationale says')
    expect(text).toContain('1 line(s) of the canonical body could not be read')
    expect(text).toContain('not a statement')
    expect(text).toContain('Plus 1 statement(s) that only link')
    expect(text).toContain('drep1test')
  })
})
