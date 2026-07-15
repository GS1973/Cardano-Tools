export function fmtAda(lovelace: number | string | null | undefined, maxDigits = 6): string {
  if (lovelace == null) return '—'
  const n = typeof lovelace === 'string' ? Number(lovelace) : lovelace
  if (!Number.isFinite(n)) return '—'
  return `${(n / 1_000_000).toLocaleString(undefined, { maximumFractionDigits: maxDigits })} ₳`
}

export function fmtMargin(num: number | string, den: number | string): string {
  const n = typeof num === 'string' ? Number(num) : num
  const d = typeof den === 'string' ? Number(den) : den
  if (!d || !Number.isFinite(n) || !Number.isFinite(d)) return '—'
  return `${((n / d) * 100).toLocaleString(undefined, { maximumFractionDigits: 4 })} %`
}
