// Timing constants used by views and components across both frontends.
// Centralised so a `grep` for the exact behaviour lands in one place
// instead of seven scattered `setInterval(..., 800)` literals.

/** Interval between animated QR frames during the send-side carousel. */
export const QR_CYCLE_INTERVAL_MS = 800

/** How often the KES countdown / status ticker repaints itself. */
export const COUNTDOWN_TICK_INTERVAL_MS = 1000

/** Debounce on the pool-pledge precheck: gives the SPO time to finish
 *  typing before fetching stake totals from Koios. */
export const PLEDGE_PRECHECK_DEBOUNCE_MS = 500

/** TopStatusBar (both binaries): how often the pairing chip refreshes. */
export const PAIRING_POLL_INTERVAL_MS = 30_000

/** Online-tool TopStatusBar: pool / KES / Koios status refresh cadence. */
export const ONLINE_STATUS_POLL_INTERVAL_MS = 90_000

/** Signer TopStatusBar: air-gap / chain-context refresh cadence. Faster
 *  than the online-tool's because air-gap state can change second-to-second. */
export const SIGNER_STATUS_POLL_INTERVAL_MS = 30_000

/** Default options for QRCode.toDataURL: keep the rendered QR sharp
 *  enough that a webcam decodes it from across the room. */
export const QRCODE_OPTIONS = {
  margin: 1,
  width: 800,
  errorCorrectionLevel: 'M' as const,
}
