import { describe, it, expect } from 'vitest'
import { canonicalBody, prepareRationale } from '../../src/canonicalize'
import exampleJson from '../fixtures/cip100-example.json?raw'
import expectedBodyNq from '../fixtures/cip100-example.body.nq?raw'

describe('CIP-100 canonicalization', () => {
  // The load-bearing check: the browser canonicalization must reproduce the
  // official CIP-0100 test vector's body exactly, so the blake2b-256 the
  // author witness signs matches what any conforming verifier reconstructs.
  it('reproduces the official CIP-0100 test-vector body byte-for-byte', async () => {
    expect(await canonicalBody(JSON.parse(exampleJson))).toBe(expectedBodyNq)
  })

  it('rewrites a references @type "Link" to "Other" and reports no blocking errors', () => {
    const doc: any = {
      hashAlgorithm: 'blake2b-256',
      authors: [{ name: 'Test' }],
      body: { summary: 's', references: [{ '@type': 'Link', label: 'x', uri: 'https://e.example' }] },
    }
    const checks = prepareRationale(doc)
    expect(checks.fixedLinkType).toBe(true)
    expect(doc.body.references[0]['@type']).toBe('Other')
    expect(checks.errors).toEqual([])
  })

  it('flags a present-but-non-array references block', () => {
    const doc: any = {
      hashAlgorithm: 'blake2b-256',
      authors: [{ name: 'Test' }],
      body: { summary: 's', references: { '@type': 'Other' } },
    }
    expect(prepareRationale(doc).errors.some((e) => e.includes('references'))).toBe(true)
  })

  it('refuses a body containing an @id-identified node', () => {
    const doc: any = {
      hashAlgorithm: 'blake2b-256',
      authors: [{ name: 'Test' }],
      body: {
        summary: 's',
        references: [{ '@type': 'Other', '@id': 'did:example:x', label: 'l', uri: 'https://e.example' }],
      },
    }
    expect(prepareRationale(doc).errors.some((e) => e.includes('@id'))).toBe(true)
  })
})
