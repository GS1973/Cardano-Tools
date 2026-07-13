import { describe, it, expect } from 'vitest'
import { extractError } from '@spo-tools/shared-frontend/utils/error'

describe('extractError', () => {
  it('parses a structured envelope from JSON body', async () => {
    const r = new Response(
      JSON.stringify({ code: 'not_paired', message: 'pair the signer' }),
      { status: 428, headers: { 'Content-Type': 'application/json' } },
    )
    const env = await extractError(r)
    expect(env.code).toBe('not_paired')
    expect(env.message).toBe('pair the signer')
  })

  it('falls back to internal + body text on plain-text 4xx', async () => {
    const r = new Response('something broke', { status: 500 })
    const env = await extractError(r)
    expect(env.code).toBe('internal')
    expect(env.message).toBe('something broke')
  })

  it('falls back to internal + status text on empty body', async () => {
    const r = new Response('', { status: 503 })
    const env = await extractError(r)
    expect(env.code).toBe('internal')
    expect(env.message).toBe('HTTP 503')
  })

  it('falls back to internal when body is not a valid envelope', async () => {
    const r = new Response(
      JSON.stringify({ unrelated: 'payload' }),
      { status: 502, headers: { 'Content-Type': 'application/json' } },
    )
    const env = await extractError(r)
    expect(env.code).toBe('internal')
    expect(env.message).toBe(JSON.stringify({ unrelated: 'payload' }))
  })

  it('narrows code via generic parameter', async () => {
    type AppCode = 'not_paired' | 'not_configured'
    const r = new Response(
      JSON.stringify({ code: 'not_configured', message: 'configure pool' }),
      { status: 412, headers: { 'Content-Type': 'application/json' } },
    )
    const env = await extractError<AppCode>(r)
    expect(env.code).toBe('not_configured')
  })
})
