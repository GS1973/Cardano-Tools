import { describe, it, expect } from 'vitest'
import { fmtTtl } from '@drep-tools/shared-frontend/utils/format'

describe('fmtTtl', () => {
  it('shows the Shelley anchor slot at its UTC time', () => {
    const now = (1_596_059_091 - 2 * 3600) * 1000
    expect(fmtTtl(4_492_800, now)).toBe('4,492,800 (2020-07-29 21:44 UTC, in 2 h 0 min)')
  })

  it('says how long ago an expired TTL ran out', () => {
    const now = (1_596_059_091 + 5 * 60) * 1000
    expect(fmtTtl('4492800', now)).toBe('4,492,800 (2020-07-29 21:44 UTC, expired 5 min ago)')
  })

  it('leaves an unreadable value as it is', () => {
    expect(fmtTtl('abc')).toBe('abc')
  })
})
