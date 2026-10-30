import { describe, it, expect } from 'vitest'
import { mount, RouterLinkStub } from '@vue/test-utils'
import NotConfiguredCard from '../../src/components/NotConfiguredCard.vue'

describe('NotConfiguredCard', () => {
  const mountOpts = {
    global: {
      stubs: { 'router-link': RouterLinkStub },
    },
  }

  it('renders the "No wallet configured" heading', () => {
    const w = mount(NotConfiguredCard, mountOpts)
    expect(w.text()).toContain('No wallet configured')
  })

  it('renders a Go to Address book button pointing at /address-book', () => {
    const w = mount(NotConfiguredCard, mountOpts)
    const btn = w.find('a[href="/address-book"], [to="/address-book"], .v-btn')
    expect(btn.exists()).toBe(true)
    expect(w.text()).toContain('Go to Address book')
  })
})
