import { describe, it, expect } from 'vitest'
import { mount, RouterLinkStub } from '@vue/test-utils'
import NotConfiguredCard from '../../src/components/NotConfiguredCard.vue'

describe('NotConfiguredCard', () => {
  const mountOpts = {
    global: {
      stubs: { 'router-link': RouterLinkStub },
    },
  }

  it('renders the "DRep not configured" heading', () => {
    const w = mount(NotConfiguredCard, mountOpts)
    expect(w.text()).toContain('DRep not configured')
  })

  it('renders a Go to Setup button pointing at /setup', () => {
    const w = mount(NotConfiguredCard, mountOpts)
    const btn = w.find('a[href="/setup"], [to="/setup"], .v-btn')
    expect(btn.exists()).toBe(true)
    expect(w.text()).toContain('Go to Setup')
  })
})
