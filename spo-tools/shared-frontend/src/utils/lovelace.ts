/**
 * Lovelace conversion helpers.
 *
 * Cardano amounts cross the Rust→TS boundary as decimal-string-encoded u64
 * (see ts-rs `#[ts(type = "string")]` annotations in `shared/src`). The
 * frontend should parse once at the boundary and operate on typed values
 * from there on.
 *
 * `Number` is the default representation: every realistic SPO amount fits
 * inside 2^53. Use the `*Bigint` variants only when working with values
 * that may overflow (large fixtures, theoretical maxima).
 *
 * Re-exports `fmtAda` from `./format` so a single import covers display.
 */

export { fmtAda } from './format'

export function parseLovelace(input: string | number): number {
  const n = typeof input === 'string' ? Number(input) : input
  if (!Number.isFinite(n)) {
    throw new Error(`invalid lovelace: ${String(input)}`)
  }
  return n
}

export function parseLovelaceBigint(input: string | number | bigint): bigint {
  if (typeof input === 'bigint') return input
  if (typeof input === 'number') {
    if (!Number.isFinite(input) || !Number.isInteger(input)) {
      throw new Error(`invalid lovelace: ${input}`)
    }
    return BigInt(input)
  }
  return BigInt(input)
}

export function lovelaceToAda(lovelace: string | number | bigint): number {
  const n = typeof lovelace === 'bigint' ? Number(lovelace) : parseLovelace(lovelace)
  return n / 1_000_000
}

export function adaToLovelace(ada: number): number {
  if (!Number.isFinite(ada)) {
    throw new Error(`invalid ada: ${ada}`)
  }
  return Math.round(ada * 1_000_000)
}
