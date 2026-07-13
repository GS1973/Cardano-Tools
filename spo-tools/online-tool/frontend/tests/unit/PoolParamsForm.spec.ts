import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { PLEDGE_PRECHECK_DEBOUNCE_MS } from '@spo-tools/shared-frontend/constants/timings'
import poolCurrent from '../fixtures/pool-current.json'

import PoolParamsForm from '../../src/components/PoolParamsForm.vue'
import type { PoolCurrent } from '../../src/types/pool-params'

type Relay = PoolCurrent['relays'][number]

const base = poolCurrent as unknown as PoolCurrent

function makeCurrent(overrides: Partial<PoolCurrent> = {}): PoolCurrent {
  return { ...base, ...overrides }
}

function mountForm(current: PoolCurrent) {
  return mount(PoolParamsForm, {
    props: {
      current,
      loading: false,
      error: null,
      mode: 'idle' as const,
      submitted: null,
      request: null,
    },
  })
}

function inputByLabel(w: ReturnType<typeof mountForm>, label: string) {
  const field = w.findAll('.v-input').find((f) => {
    const lbl = f.find('label.v-label')
    return lbl.exists() && lbl.text() === label
  })
  return field?.find('input')
}

function findSendToSigner(w: ReturnType<typeof mountForm>) {
  return w.findAll('button').find((b) => b.text().includes('Send to Signer'))
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

describe('PoolParamsForm relay classification', () => {
  it('keeps a port-less DNS relay classified as single_host_name and shows no relay diff', async () => {
    const relay: Relay = { dns: 'relay1.example.com', srv: null, ipv4: null, ipv6: null, port: null }
    const w = mountForm(makeCurrent({ relays: [relay] }))
    await flushPromises()

    // The row must be pre-selected as a DNS A record, not an SRV record.
    expect(w.text()).toContain('DNS A record + port')
    expect(w.text()).not.toContain('DNS SRV record')
    expect(inputByLabel(w, 'DNS hostname')?.element.value).toBe('relay1.example.com')
    // Round-trip is exact, so the diff hint must not fire.
    expect(w.text()).not.toContain('Relays differ')
    expect(w.findAll('.changed-field').length).toBe(0)
  })

  it('classifies srv-only relays as multi_host_name from the srv field alone', async () => {
    const relay: Relay = { dns: null, srv: '_cardano._tcp.example.com', ipv4: null, ipv6: null, port: null }
    const w = mountForm(makeCurrent({ relays: [relay] }))
    await flushPromises()

    expect(w.text()).toContain('DNS SRV record')
    expect(inputByLabel(w, 'DNS hostname')?.element.value).toBe('_cardano._tcp.example.com')
    expect(w.text()).not.toContain('Relays differ')
    expect(w.findAll('.changed-field').length).toBe(0)
  })

  it('round-trips a dual-stack relay including its IPv6 address', async () => {
    const relay: Relay = { dns: null, srv: null, ipv4: '1.2.3.4', ipv6: '2001:db8::1', port: 3001 }
    const w = mountForm(makeCurrent({ relays: [relay] }))
    await flushPromises()

    expect(inputByLabel(w, 'IPv4')?.element.value).toBe('1.2.3.4')
    expect(inputByLabel(w, 'IPv6')?.element.value).toBe('2001:db8::1')
    expect(w.text()).not.toContain('Relays differ')
    expect(w.findAll('.changed-field').length).toBe(0)
  })
})

describe('PoolParamsForm value population', () => {
  it('round-trips sub-ADA pledge and fixed cost exactly', async () => {
    const w = mountForm(makeCurrent({
      pledge_lovelace: 100_000_500_000,
      fixed_cost_lovelace: 170_123_456,
    }))
    await flushPromises()

    expect(inputByLabel(w, 'Pledge (₳)')?.element.value).toBe('100000.5')
    expect(inputByLabel(w, 'Fixed cost (₳)')?.element.value).toBe('170.123456')
    // Exact population means no field may carry the gold "changed" mark.
    expect(w.findAll('.changed-field').length).toBe(0)
  })
})

describe('PoolParamsForm pledge precheck failure', () => {
  it('warns and requires force-confirm when the precheck lookup fails', async () => {
    globalThis.fetch = vi.fn(async () => new Response('koios down', { status: 502 })) as typeof fetch

    const w = mountForm(makeCurrent())
    await flushPromises()

    const pledge = inputByLabel(w, 'Pledge (₳)')
    expect(pledge).toBeDefined()
    await pledge!.setValue('999999')
    await sleep(PLEDGE_PRECHECK_DEBOUNCE_MS + 100)
    await flushPromises()

    expect(w.text()).toContain('could not be verified')
    const send = findSendToSigner(w)
    expect(send).toBeDefined()
    expect(send!.classes()).toContain('v-btn--disabled')

    const alert = w.findAll('.v-alert').find((a) => a.text().includes('could not be verified'))
    expect(alert).toBeDefined()
    const confirm = alert!.find('input[type="checkbox"]')
    await confirm.setValue(true)
    await flushPromises()

    expect(findSendToSigner(w)!.classes()).not.toContain('v-btn--disabled')
  })
})

describe('PoolParamsForm margin rational round-trip', () => {
  beforeEach(() => {
    document.body.innerHTML = ''
  })

  it('prefills margin from the exact rational without a change mark', async () => {
    const w = mountForm(makeCurrent({
      margin: 1 / 3,
      margin_numerator: 1,
      margin_denominator: 3,
    }))
    await flushPromises()

    expect(inputByLabel(w, 'Margin (%)')?.element.value).toBe('33.333333')
    expect(w.findAll('.changed-field').length).toBe(0)
    expect(w.text()).not.toContain('could not be recovered')
  })

  it('sends the exact rational back when the margin field is untouched', async () => {
    const buildBodies: string[] = []
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url.startsWith('/api/pool/build')) {
        buildBodies.push(typeof init?.body === 'string' ? init.body : '')
        return new Response(JSON.stringify({
          request: {},
          body_hash_hex: 'bb',
          ur_fragments: ['ur:spo-tools-action-v2/test'],
          request_fingerprint: 'AA-BB-CC-DD',
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response('not mocked: ' + url, { status: 404 })
    }) as typeof fetch

    const w = mountForm(makeCurrent({
      margin: 1 / 3,
      margin_numerator: 1,
      margin_denominator: 3,
    }))
    await flushPromises()

    const send = findSendToSigner(w)
    expect(send, 'Send-to-Signer button rendered').toBeDefined()
    await send!.trigger('click')
    await flushPromises()

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

    expect(buildBodies.length, 'POST /api/pool/build fired').toBeGreaterThanOrEqual(1)
    const body = JSON.parse(buildBodies[0])
    // Untouched margin must round-trip the on-chain rational verbatim,
    // not the re-rounded percent (333333/1000000).
    expect(body.margin_numerator).toBe(1)
    expect(body.margin_denominator).toBe(3)
  })

  it('sends the re-rounded percent after the operator edits the margin', async () => {
    const buildBodies: string[] = []
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url.startsWith('/api/pool/build')) {
        buildBodies.push(typeof init?.body === 'string' ? init.body : '')
        return new Response(JSON.stringify({
          request: {},
          body_hash_hex: 'bb',
          ur_fragments: ['ur:spo-tools-action-v2/test'],
          request_fingerprint: 'AA-BB-CC-DD',
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response('not mocked: ' + url, { status: 404 })
    }) as typeof fetch

    const w = mountForm(makeCurrent({
      margin: 1 / 3,
      margin_numerator: 1,
      margin_denominator: 3,
    }))
    await flushPromises()

    const margin = inputByLabel(w, 'Margin (%)')
    expect(margin).toBeDefined()
    await margin!.setValue('2.5')
    await flushPromises()
    // Edited margin is a real change again.
    expect(w.findAll('.changed-field').length).toBeGreaterThan(0)

    const send = findSendToSigner(w)
    await send!.trigger('click')
    await flushPromises()

    const pinField = document.querySelector('input[inputmode="numeric"]') as HTMLInputElement | null
    expect(pinField).toBeTruthy()
    pinField!.value = '1234'
    pinField!.dispatchEvent(new Event('input', { bubbles: true }))
    pinField!.dispatchEvent(new Event('change', { bubbles: true }))
    await flushPromises()

    const confirmBtn = Array.from(document.querySelectorAll('button')).find(
      (b) => b.textContent?.trim() === 'Send to signer',
    )
    confirmBtn!.click()
    await flushPromises()

    expect(buildBodies.length).toBeGreaterThanOrEqual(1)
    const body = JSON.parse(buildBodies[0])
    expect(body.margin_numerator).toBe(25_000)
    expect(body.margin_denominator).toBe(1_000_000)
  })

  it('warns when no exact rational could be recovered from the float', async () => {
    const w = mountForm(makeCurrent({
      margin: 0.0123456789,
      margin_numerator: null,
      margin_denominator: null,
    }))
    await flushPromises()

    expect(w.text()).toContain('could not be recovered')
  })
})
