import type { RelaySpec } from '../types/pool'

export function fmtAda(lovelace: number | string | null | undefined, maxDigits = 6): string {
  if (lovelace == null) return '—'
  const n = typeof lovelace === 'string' ? Number(lovelace) : lovelace
  if (!Number.isFinite(n)) return '—'
  return `${(n / 1_000_000).toLocaleString(undefined, { maximumFractionDigits: maxDigits })} ₳`
}

// One integer formatter for both sides of the air gap: the operator
// visually cross-checks slot/TTL numbers between the online tool and the
// signer, so both must group digits identically — no per-view hard-coded
// locale.
export function fmtInt(value: number | string | null | undefined): string {
  if (value == null) return '—'
  const n = typeof value === 'string' ? Number(value) : value
  if (!Number.isFinite(n)) return '—'
  return n.toLocaleString(undefined)
}

export function fmtMargin(num: number | string, den: number | string): string {
  const n = typeof num === 'string' ? Number(num) : num
  const d = typeof den === 'string' ? Number(den) : den
  if (!d || !Number.isFinite(n) || !Number.isFinite(d)) return '—'
  return `${((n / d) * 100).toLocaleString(undefined, { maximumFractionDigits: 4 })} %`
}

export function fmtRelays(relays: RelaySpec[]): string {
  if (!relays.length) return '(none)'
  return relays
    .map(r => {
      if (r.kind === 'single_host_addr') {
        const host = r.ipv4 ?? r.ipv6 ?? '?'
        return r.port ? `${host}:${r.port}` : host
      }
      if (r.kind === 'single_host_name') {
        return r.port ? `${r.dns}:${r.port}` : (r.dns ?? '?')
      }
      return `srv:${r.dns ?? '?'}`
    })
    .join(', ')
}
