import { ref } from 'vue'
import { useNotificationStore } from '@drep-tools/shared-frontend/stores/notification'
import { useQrCarousel } from '@drep-tools/shared-frontend/composables/useQrCarousel'
import { useScannerControl } from '@drep-tools/shared-frontend/composables/useScannerControl'
import { extractError } from '@drep-tools/shared-frontend/utils/error'
import type { ErrorCode } from '@drep-tools/shared-frontend/types/errors'

export interface SubmittedTx {
  tx_hash: string
  explorer_url: string
  signed_tx_size_bytes: number
}

/**
 * Shared build → QR → scan-result → submit machinery for the four DRep
 * operations. Each view owns its own preview + form; this composable owns
 * the air-gap round-trip against `${base}/start`, `${base}/result`,
 * `${base}/submit`. The view passes the start-body and wires the
 * not-configured / not-paired routing via `setGuards`.
 */
export function useSignFlow(base: string) {
  const notify = useNotificationStore()
  const qr = useQrCarousel()
  const scanner = useScannerControl()

  const mode = ref<'idle' | 'send' | 'receive'>('idle')
  const starting = ref(false)
  const submitting = ref(false)
  const finalSubmitting = ref(false)
  const startError = ref<string | null>(null)
  const resultError = ref<string | null>(null)
  const submitError = ref<string | null>(null)
  const request = ref<Record<string, any> | null>(null)
  const result = ref<Record<string, any> | null>(null)
  const submitted = ref<SubmittedTx | null>(null)
  const requestFingerprint = ref<string | null>(null)
  const bodyHashHex = ref<string | null>(null)
  const resultInput = ref('')
  const cameraEnlarged = ref(false)
  const rawOpen = ref<number | null>(null)

  let onNotConfigured = () => {}
  let onNotPaired = () => {}
  function setGuards(nc: () => void, np: () => void) {
    onNotConfigured = nc
    onNotPaired = np
  }

  function reset() {
    qr.reset()
    request.value = null
    result.value = null
    submitted.value = null
    resultInput.value = ''
    startError.value = null
    resultError.value = null
    submitError.value = null
    requestFingerprint.value = null
    bodyHashHex.value = null
    rawOpen.value = null
    mode.value = 'idle'
    qr.stopCycle()
  }

  /** Any form edit after a build invalidates the QR — scanning a stale
   *  request would sign something the operator no longer sees. */
  function invalidate() {
    if (!request.value && !result.value) return
    reset()
  }

  async function start(body: Record<string, unknown>) {
    reset()
    mode.value = 'send'
    starting.value = true
    try {
      const r = await fetch(`${base}/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!r.ok) {
        const err = await extractError<ErrorCode>(r)
        if (err.code === 'not_configured') { onNotConfigured(); return }
        if (err.code === 'not_paired') { onNotPaired(); return }
        throw new Error(err.message)
      }
      const data = await r.json()
      request.value = data.request
      bodyHashHex.value = data.body_hash_hex || null
      qr.fragments.value = data.ur_fragments
      requestFingerprint.value = data.request_fingerprint || null
      qr.index.value = 0
      await qr.renderCurrentFrame()
      qr.startCycle()
    } catch (e: unknown) {
      startError.value = e instanceof Error ? e.message : String(e)
    } finally {
      starting.value = false
    }
  }

  function enterReceive() {
    qr.reset()
    result.value = null
    resultInput.value = ''
    startError.value = null
    resultError.value = null
    mode.value = 'receive'
  }

  async function receive(fragments: string[]) {
    submitting.value = true
    resultError.value = null
    try {
      if (!fragments.length) throw new Error('no UR fragments to submit')
      const r = await fetch(`${base}/result`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ur_fragments: fragments }),
      })
      if (!r.ok) {
        const err = await extractError<ErrorCode>(r)
        if (err.code === 'not_configured') { onNotConfigured(); return }
        if (err.code === 'not_paired') { onNotPaired(); return }
        throw new Error(err.message)
      }
      const data = await r.json()
      // Correlate the result with the pending request: a leftover result for
      // an earlier (cancelled/rebuilt) request must not be shown as ready to
      // submit — its witnesses sign a different tx body.
      if (bodyHashHex.value && data.body_hash_hex !== bodyHashHex.value) {
        throw new Error('signed result does not match the pending request (tx body hash differs) — scan the result for the request shown above')
      }
      result.value = data
      notify.success(`Signed result received — ${result.value!.witnesses.length} witnesses`)
      qr.stopCycle()
    } catch (e: unknown) {
      resultError.value = e instanceof Error ? e.message : String(e)
    } finally {
      submitting.value = false
    }
  }

  async function submit() {
    if (!request.value || !result.value) return
    finalSubmitting.value = true
    submitError.value = null
    try {
      const r = await fetch(`${base}/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tx_body_cbor_hex: request.value.tx_body_cbor_hex,
          witnesses: result.value.witnesses,
        }),
      })
      if (!r.ok) {
        const err = await extractError<ErrorCode>(r)
        throw new Error(err.message)
      }
      submitted.value = await r.json()
      notify.success(`Tx submitted — ${submitted.value!.tx_hash.slice(0, 16)}…`)
    } catch (e: unknown) {
      submitError.value = e instanceof Error ? e.message : String(e)
    } finally {
      finalSubmitting.value = false
    }
  }

  async function submitPasted() {
    const fragments = resultInput.value.split('\n').map(s => s.trim()).filter(Boolean)
    await receive(fragments)
  }

  return {
    qr, scanner, mode, starting, submitting, finalSubmitting,
    startError, resultError, submitError, request, result, submitted,
    requestFingerprint, bodyHashHex, resultInput, cameraEnlarged, rawOpen,
    setGuards, reset, invalidate, start, enterReceive, receive, submit, submitPasted,
  }
}
