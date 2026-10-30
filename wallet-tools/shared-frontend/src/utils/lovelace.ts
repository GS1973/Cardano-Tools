/**
 * Lovelace conversion helpers.
 *
 * Cardano amounts cross the Rust→TS boundary as decimal-string-encoded u64
 * (see ts-rs `#[ts(type = "string")]` annotations in `shared/src`) because a
 * JS `Number` loses precision above 2^53 lovelace (~9.007e9 ADA), and wallet
 * amounts, unlike typical pool fees, can plausibly exceed that. Parse wire
 * strings with `parseLovelaceBigint` at the boundary and operate on `bigint`
 * from there on.
 *
 * Re-exports `fmtAda` from `./format` so a single import covers display.
 */

export { fmtAda } from './format'

export function parseLovelaceBigint(input: string | number | bigint): bigint {
  if (typeof input === 'bigint') return input
  if (typeof input === 'number') {
    if (!Number.isSafeInteger(input)) {
      throw new Error(`invalid lovelace: ${input}`)
    }
    return BigInt(input)
  }
  // BigInt('') === 0n and BigInt('0x10') === 16n: require plain decimal digits.
  if (!/^\d+$/.test(input)) {
    throw new Error(`invalid lovelace: ${input}`)
  }
  return BigInt(input)
}

export function adaToLovelace(ada: number): number {
  if (!Number.isFinite(ada)) {
    throw new Error(`invalid ada: ${ada}`)
  }
  return Math.round(ada * 1_000_000)
}
