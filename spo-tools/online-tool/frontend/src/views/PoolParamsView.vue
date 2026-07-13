<template>
  <SignFlowLayout
    title="Pool parameter update"
    :not-configured="notConfigured"
    :not-paired="notPaired"
  >
    <PoolParamsForm
      :current="current"
      :loading="loading"
      :error="error"
      :mode="mode"
      :submitted="submitted"
      :request="request"
      @request-reset="resetForBuild"
      @request-built="onRequestBuilt"
      @start-error="onStartError"
      @receive="enterReceive"
      @refresh="startNewSession"
      @form-changed="onFormChanged"
      @not-configured="notConfigured = true"
      @not-paired="notPaired = true"
    />

    <v-card v-if="startError" class="mb-4">
      <v-card-text>
        <v-alert type="error" density="compact" variant="tonal">{{ startError }}</v-alert>
      </v-card-text>
    </v-card>
    <SendQrPanel
      v-if="request && mode === 'send'"
      ref="sendCardEl"
      :qr-data-url="qrDataUrl"
      :qr-fragments="qrFragments"
      :qr-index="qrIndex"
      :fingerprint="requestFingerprint"
      title="Request"
      @copy="copyUr"
    />
    <ReceiveQrPanel
      v-if="mode === 'receive'"
      ref="receiveCardEl"
      v-model:result-input="resultInput"
      v-model:camera-enlarged="cameraEnlarged"
      :retrying-camera="retryingCamera"
      :result-error="resultError"
      :submitting="submitting"
      title="Receive signed result"
      @scanner-complete="onScannerComplete"
      @scanner-complete-enlarged="onScannerCompleteEnlarged"
      @scanner-error="(m: string) => resultError = m"
      @retry-camera="retryCamera"
      @submit="submitPasted"
    />

    <PoolParamsResultCard
      ref="resultCardEl"
      :current="current"
      :request="request"
      :result="result"
      :submitted="submitted"
      :submit-error="submitError"
      :final-submitting="finalSubmitting"
      @submit="submitToChain"
      @start-new-session="startNewSession"
    />
  </SignFlowLayout>
</template>

<script setup lang="ts">
import { ref, onMounted, watch, nextTick } from 'vue'
import { useNotificationStore } from '@spo-tools/shared-frontend/stores/notification'
import SignFlowLayout from '../components/SignFlowLayout.vue'
import PoolParamsForm from '../components/PoolParamsForm.vue'
import PoolParamsResultCard from '../components/PoolParamsResultCard.vue'
import type {
  PoolCurrent,
  PoolUpdateRequest,
  PoolUpdateResult,
  SubmittedTx,
} from '../types/pool-params'
import type { ErrorCode } from '@spo-tools/shared-frontend/types/core'
import { extractError } from '@spo-tools/shared-frontend/utils/error'
import SendQrPanel from '@spo-tools/shared-frontend/components/SendQrPanel.vue'
import ReceiveQrPanel from '@spo-tools/shared-frontend/components/ReceiveQrPanel.vue'
import { useQrCarousel } from '@spo-tools/shared-frontend/composables/useQrCarousel'
import { useScannerControl } from '@spo-tools/shared-frontend/composables/useScannerControl'

const current = ref<PoolCurrent | null>(null)
const error = ref<string | null>(null)
const loading = ref(false)
const notConfigured = ref(false)
const notPaired = ref(false)

const {
  fragments: qrFragments,
  index: qrIndex,
  dataUrl: qrDataUrl,
  renderCurrentFrame,
  startCycle: startQrCycle,
  stopCycle,
  reset: resetQrCarousel,
  copyToClipboard: copyUr,
} = useQrCarousel()
const {
  scannerRef,
  retryingCamera,
  retry: retryCamera,
} = useScannerControl()

const mode = ref<'idle' | 'send' | 'receive'>('idle')
const submitting = ref(false)
const startError = ref<string | null>(null)
const resultError = ref<string | null>(null)
const request = ref<PoolUpdateRequest | null>(null)
// body_hash_hex from the /build response; a received result must hash-match
// it before it is accepted (stale-result guard).
const bodyHashHex = ref<string | null>(null)
const resultInput = ref('')
const result = ref<PoolUpdateResult | null>(null)
const cameraEnlarged = ref(false)
const submitted = ref<SubmittedTx | null>(null)
const submitError = ref<string | null>(null)
const finalSubmitting = ref(false)

const notify = useNotificationStore()

async function load() {
  loading.value = true
  error.value = null
  try {
    const r = await fetch('/api/pool/current')
    if (!r.ok) {
      const err = await extractError<ErrorCode>(r)
      if (err.code === 'not_configured') {
        notConfigured.value = true
        return
      }
      if (err.code === 'not_paired') {
        notPaired.value = true
        return
      }
      throw new Error(err.message)
    }
    current.value = (await r.json()) as PoolCurrent
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    loading.value = false
  }
}

function resetForBuild() {
  resetQrCarousel()
  request.value = null
  bodyHashHex.value = null
  result.value = null
  resultInput.value = ''
  startError.value = null
  resultError.value = null
  mode.value = 'send'
}

const sendCardEl = ref<{ $el: HTMLElement } | null>(null)
const receiveCardEl = ref<{ $el: HTMLElement; retry?: () => Promise<void> } | null>(null)
// ReceiveQrPanel exposes retry(); mirror its template ref into the scanner
// control so the error alert's 'Try again' restarts the camera instead of
// no-oping on a never-assigned scannerRef.
watch(receiveCardEl, (el) => { scannerRef.value = el })
const resultCardEl = ref<{ $el: HTMLElement } | null>(null)
const requestFingerprint = ref<string | null>(null)

async function onRequestBuilt(payload: { request: PoolUpdateRequest; ur_fragments: string[]; request_fingerprint: string | null; body_hash_hex: string | null }) {
  request.value = payload.request
  bodyHashHex.value = payload.body_hash_hex
  qrFragments.value = payload.ur_fragments
  requestFingerprint.value = payload.request_fingerprint
  qrIndex.value = 0
  await renderCurrentFrame()
  startQrCycle()
  await nextTick()
  sendCardEl.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
}

function onStartError(msg: string) {
  startError.value = msg
}

// Any form edit after a build was generated invalidates that build —
// scanning the stale QR would sign a tx that no longer matches what the
// SPO sees in the form. Discard the stale request + QR + result so the
// SPO must click Send to Signer again.
function onFormChanged() {
  if (!request.value && !result.value) return
  resetQrCarousel()
  request.value = null
  bodyHashHex.value = null
  result.value = null
  resultInput.value = ''
  startError.value = null
  resultError.value = null
  mode.value = 'idle'
  stopCycle()
}

async function enterReceive() {
  resetQrCarousel()
  result.value = null
  resultInput.value = ''
  startError.value = null
  resultError.value = null
  mode.value = 'receive'
  await nextTick()
  receiveCardEl.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
}

async function submitFragments(fragments: string[]) {
  submitting.value = true
  resultError.value = null
  try {
    if (!fragments.length) throw new Error('no UR fragments to submit')
    const r = await fetch('/api/pool/result', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ur_fragments: fragments }),
    })
    if (!r.ok) {
      const err = await extractError<ErrorCode>(r)
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
    notify.success(`Signed result received — ${data.witnesses.length} witnesses`)
    stopCycle()
    await nextTick()
    resultCardEl.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
  } catch (e: unknown) {
    resultError.value = e instanceof Error ? e.message : String(e)
  } finally {
    submitting.value = false
  }
}

async function onScannerComplete(fragments: string[]) { await submitFragments(fragments) }
async function onScannerCompleteEnlarged(fragments: string[]) {
  cameraEnlarged.value = false
  await submitFragments(fragments)
}
async function submitPasted() {
  const fragments = resultInput.value.split('\n').map(s => s.trim()).filter(Boolean)
  await submitFragments(fragments)
}

async function submitToChain() {
  if (!request.value || !result.value) return
  finalSubmitting.value = true
  submitError.value = null
  try {
    const r = await fetch('/api/pool/submit', {
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

function startNewSession() {
  submitted.value = null
  submitError.value = null
  result.value = null
  request.value = null
  bodyHashHex.value = null
  resultInput.value = ''
  qrFragments.value = []
  requestFingerprint.value = null
  qrDataUrl.value = null
  qrIndex.value = 0
  startError.value = null
  resultError.value = null
  mode.value = 'idle'
  stopCycle()
  load()
}

onMounted(load)
</script>

