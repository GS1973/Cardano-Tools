// Locale decimal separator, resolved once. The integer half below is
// formatted with toLocaleString, so the hand-appended fraction half must
// use the same separator.
const DECIMAL_SEPARATOR =
  new Intl.NumberFormat().formatToParts(1.1).find((p) => p.type === 'decimal')?.value ?? '.'

/**
 * Format a lovelace amount as ADA. Amounts cross the wire as decimal-string
 * u64 precisely because `Number` loses precision above 2^53, so the split
 * into whole/fractional ADA is done with BigInt: the signer's verification
 * display must match the signed body to the lovelace. Fraction digits beyond
 * `maxDigits` are truncated, never rounded. Malformed input renders as 'n/a'.
 */
export function fmtAda(lovelace: number | string | bigint | null | undefined, maxDigits = 6): string {
  if (lovelace == null) return 'n/a'
  let n: bigint
  if (typeof lovelace === 'bigint') {
    n = lovelace
  } else if (typeof lovelace === 'number') {
    // A non-safe integer already lost precision upstream; refuse to render it.
    if (!Number.isSafeInteger(lovelace)) return 'n/a'
    n = BigInt(lovelace)
  } else {
    const s = lovelace.trim()
    if (!/^-?\d+$/.test(s)) return 'n/a'
    n = BigInt(s)
  }
  const sign = n < 0n ? '-' : ''
  const abs = n < 0n ? -n : n
  const digits = Math.max(0, Math.min(6, Math.trunc(maxDigits)))
  const frac = (abs % 1_000_000n).toString().padStart(6, '0').slice(0, digits).replace(/0+$/, '')
  const whole = (abs / 1_000_000n).toLocaleString()
  return `${sign}${whole}${frac ? DECIMAL_SEPARATOR + frac : ''} ₳`
}

export function fmtMargin(num: number | string, den: number | string): string {
  const n = typeof num === 'string' ? Number(num) : num
  const d = typeof den === 'string' ? Number(den) : den
  if (!d || !Number.isFinite(n) || !Number.isFinite(d)) return 'n/a'
  return `${((n / d) * 100).toLocaleString(undefined, { maximumFractionDigits: 4 })} %`
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
