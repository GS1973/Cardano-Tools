import type { RelaySpec } from '../types/pool'

export function fmtAda(lovelace: number | string | null | undefined, maxDigits = 6): string {
  if (lovelace == null) return 'n/a'
  const n = typeof lovelace === 'string' ? Number(lovelace) : lovelace
  if (!Number.isFinite(n)) return 'n/a'
  return `${(n / 1_000_000).toLocaleString(undefined, { maximumFractionDigits: maxDigits })} ₳`
}

// One integer formatter for both sides of the air gap: the operator
// visually cross-checks slot/TTL numbers between the online tool and the
// signer, so both must group digits identically: no per-view hard-coded
// locale.
export function fmtInt(value: number | string | null | undefined): string {
  if (value == null) return 'n/a'
  const n = typeof value === 'string' ? Number(value) : value
  if (!Number.isFinite(n)) return 'n/a'
  return n.toLocaleString(undefined)
}

export function fmtMargin(num: number | string, den: number | string): string {
  const n = typeof num === 'string' ? Number(num) : num
  const d = typeof den === 'string' ? Number(den) : den
  if (!d || !Number.isFinite(n) || !Number.isFinite(d)) return 'n/a'
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

/** Unix time of mainnet slot 0 on the one-slot-per-second clock that has run
 *  since Shelley (airgap-core `MAINNET_SLOT_ZERO_UNIX`). */
const MAINNET_SLOT_ZERO_UNIX = 1_591_566_291

/**
 * A TTL slot with the moment it expires, in UTC, and how far that lies from
 * this machine's clock, for example
 * "200,617,449 (2026-10-17 14:32 UTC, in 1 h 58 min)".
 */
export function fmtTtl(slot: number | string, nowMs: number = Date.now()): string {
  const n = Number(slot)
  if (!Number.isSafeInteger(n) || n < 0) return String(slot)
  const unix = n + MAINNET_SLOT_ZERO_UNIX
  const iso = new Date(unix * 1000).toISOString()
  const when = `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`
  const diffMin = Math.round((unix * 1000 - nowMs) / 60000)
  const abs = Math.abs(diffMin)
  const span = abs >= 60 ? `${Math.floor(abs / 60)} h ${abs % 60} min` : `${abs} min`
  const rel = diffMin >= 0 ? `in ${span}` : `expired ${span} ago`
  return `${n.toLocaleString('en-US')} (${when}, ${rel})`
}
