<template>
  <v-card class="mb-4">
    <v-card-title>Leaderlog</v-card-title>
  </v-card>

  <NotConfiguredCard v-if="notConfigured" />
  <NotPairedCard v-else-if="notPaired" />

  <template v-else>
  <v-card class="mb-4">
    <v-card-text class="d-flex align-center" style="gap: 1rem;">
      <span class="text-body-1" :class="{ 'text-gold': chosenEpoch === 'next' }">Request leaderlog for next Epoch</span>
      <v-spacer />
      <div class="d-flex" style="gap: 0.5rem;">
        <v-btn
          size="small"
          color="primary"
          :variant="chosenEpoch === 'next' && mode === 'send' ? 'tonal' : 'outlined'"
          :loading="starting === 'next'"
          :disabled="starting === 'current' || nextNonceReady === false"
          prepend-icon="mdi-upload"
          style="width: 180px;"
          @click="openConfirmSend('next')"
        >Send to Signer</v-btn>
        <v-btn
          size="small"
          color="primary"
          :variant="chosenEpoch === 'next' && mode === 'receive' ? 'tonal' : 'outlined'"
          :disabled="!request || nextNonceReady === false"
          prepend-icon="mdi-download"
          style="width: 180px;"
          @click="enterReceive('next')"
        >Receive from Signer</v-btn>
      </div>
      <v-alert v-if="nextNonceReady === false" type="info" density="compact" variant="tonal" class="mt-3">
        Next-epoch nonce is finalised only in the last ~48 hours of the current epoch (the randomness-stabilisation window).
        {{ nextEpochUnlockUnix !== null ? `Try again after ${formatLocal(nextEpochUnlockUnix)} (${localTimeZone}).` : 'Try again after that.' }}
      </v-alert>
    </v-card-text>
  </v-card>

  <v-card class="mb-4">
    <v-card-text class="d-flex align-center" style="gap: 1rem;">
      <span class="text-body-1" :class="{ 'text-gold': chosenEpoch === 'current' }">Request leaderlog for current Epoch</span>
      <v-spacer />
      <div class="d-flex" style="gap: 0.5rem;">
        <v-btn
          size="small"
          color="primary"
          :variant="chosenEpoch === 'current' && mode === 'send' ? 'tonal' : 'outlined'"
          :loading="starting === 'current'"
          :disabled="starting === 'next'"
          prepend-icon="mdi-upload"
          style="width: 180px;"
          @click="openConfirmSend('current')"
        >Send to Signer</v-btn>
        <v-btn
          size="small"
          color="primary"
          :variant="chosenEpoch === 'current' && mode === 'receive' ? 'tonal' : 'outlined'"
          :disabled="!request"
          prepend-icon="mdi-download"
          style="width: 180px;"
          @click="enterReceive('current')"
        >Receive from Signer</v-btn>
      </div>
    </v-card-text>
  </v-card>

  <v-card v-if="startError" class="mb-4">
    <v-card-text>
      <v-alert type="error" density="compact" variant="tonal">{{ startError }}</v-alert>
    </v-card-text>
  </v-card>

  <v-card v-if="fallbackNotice && mode === 'send'" class="mb-4">
    <v-card-text>
      <v-alert type="info" density="compact" variant="tonal">{{ fallbackNotice }}</v-alert>
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
      title="Receive signed request"
      @scanner-complete="onScannerComplete"
      @scanner-complete-enlarged="onScannerCompleteEnlarged"
      @scanner-error="(m: string) => resultError = m"
      @retry-camera="retryCamera"
      @submit="submitPasted"
    />

  <v-card ref="resultCardEl" v-if="result">
    <v-card-text>
      <h3 class="text-subtitle-1 mt-0 mb-2">
        Schedule for epoch {{ result.epoch }}: {{ result.count }} block(s)
      </h3>
      <v-table density="compact">
        <thead>
          <tr>
            <th class="text-right text-gold">#</th>
            <th class="text-right text-gold">Slot</th>
            <th class="text-gold">UTC</th>
            <th class="text-gold">Local ({{ localTimeZone }})</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(s, i) in result.slots" :key="s.slot_no">
            <td class="text-right">{{ i + 1 }}</td>
            <td class="text-right"><code>{{ fmtInt(s.slot_no) }}</code></td>
            <td>{{ formatUtc(s.unix_time) }}</td>
            <td>{{ formatLocal(s.unix_time) }}</td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
  </v-card>

  <PreSendConfirm
    v-model="confirmSendOpen"
    title="Confirm leaderlog request"
    @confirm="onConfirmSend"
  >
    <p class="text-body-2 text-medium-emphasis mb-2">You are about to ask the signer to compute the leaderlog using the VRF skey.</p>
    <p class="text-body-2 text-medium-emphasis mb-0">Target epoch: <strong>{{ pendingEpoch }}</strong></p>
  </PreSendConfirm>
  </template>
</template>

<script setup lang="ts">
import { ref, onMounted, watch, nextTick } from 'vue'
import { useNotificationStore } from '@spo-tools/shared-frontend/stores/notification'
import { fmtInt } from '@spo-tools/shared-frontend/utils/format'
import SendQrPanel from '@spo-tools/shared-frontend/components/SendQrPanel.vue'
import ReceiveQrPanel from '@spo-tools/shared-frontend/components/ReceiveQrPanel.vue'
import { useQrCarousel } from '@spo-tools/shared-frontend/composables/useQrCarousel'
import { useScannerControl } from '@spo-tools/shared-frontend/composables/useScannerControl'
import NotConfiguredCard from '../components/NotConfiguredCard.vue'
import NotPairedCard from '../components/NotPairedCard.vue'
import type { ErrorCode } from '@spo-tools/shared-frontend/types/core'
import type { LeaderlogRequest } from '@spo-tools/shared-frontend/types/wire'
import { extractError } from '@spo-tools/shared-frontend/utils/error'
import PreSendConfirm from '@spo-tools/shared-frontend/components/PreSendConfirm.vue'


interface ScheduledSlot {
  slot_no: number
  unix_time: number
}
interface LeaderlogResultResponse {
  pool_id_bech32: string
  epoch: number
  count: number
  slots: ScheduledSlot[]
}

type WhichEpoch = 'current' | 'next'

const starting = ref<WhichEpoch | null>(null)
const chosenEpoch = ref<WhichEpoch | null>(null)
const effectiveEpoch = ref<WhichEpoch | null>(null)
const fallbackNotice = ref<string | null>(null)
const mode = ref<'send' | 'receive'>('send')
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

const submitting = ref(false)
const startError = ref<string | null>(null)
const resultError = ref<string | null>(null)
const request = ref<LeaderlogRequest | null>(null)
const resultInput = ref('')
const result = ref<LeaderlogResultResponse | null>(null)
const cameraEnlarged = ref(false)
const notConfigured = ref(false)
const nextNonceReady = ref<boolean | null>(null)
const nextEpochUnlockUnix = ref<number | null>(null)
const notPaired = ref(false)

const notify = useNotificationStore()
const requestFingerprint = ref<string | null>(null)

const sendCardEl = ref<{ $el: HTMLElement } | null>(null)
const receiveCardEl = ref<{ $el: HTMLElement; retry?: () => Promise<void> } | null>(null)
// ReceiveQrPanel exposes retry(); mirror its template ref into the scanner
// control so the error alert's 'Try again' restarts the camera instead of
// no-oping on a never-assigned scannerRef.
watch(receiveCardEl, (el) => { scannerRef.value = el })
const resultCardEl = ref<{ $el: HTMLElement } | null>(null)

const confirmSendOpen = ref(false)
const pendingEpoch = ref<WhichEpoch | null>(null)

function openConfirmSend(which: WhichEpoch) {
  pendingEpoch.value = which
  confirmSendOpen.value = true
}

async function onConfirmSend(payload: { pin: string }) {
  confirmSendOpen.value = false
  const which = pendingEpoch.value
  pendingEpoch.value = null
  if (!which) return
  await startLeaderlog(which, payload.pin)
}


async function enterReceive(which: WhichEpoch) {
  resetQrCarousel()
  result.value = null
  resultInput.value = ''
  startError.value = null
  resultError.value = null
  mode.value = 'receive'
  chosenEpoch.value = which
  await nextTick()
  receiveCardEl.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
}

async function startLeaderlog(which: WhichEpoch, pin: string) {
  resetQrCarousel()
  request.value = null
  result.value = null
  resultInput.value = ''
  startError.value = null
  resultError.value = null
  mode.value = 'send'
  starting.value = which
  chosenEpoch.value = which
  effectiveEpoch.value = null
  fallbackNotice.value = null

  try {
    const r = await fetch('/api/leaderlog/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin, epoch: which }),
    })
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
    const data = await r.json()
    request.value = data.request
    qrFragments.value = data.ur_fragments
    requestFingerprint.value = data.request_fingerprint || null
    const effective = (data.effective_epoch_kind ?? which) as WhichEpoch
    effectiveEpoch.value = effective
    fallbackNotice.value = data.fallback_notice ?? null
    // Track the actually-served epoch so the gold accent + button state
    // line up with the request preview and any fallback notice.
    chosenEpoch.value = effective
    qrIndex.value = 0
    await renderCurrentFrame()
    startQrCycle()
    await nextTick()
    sendCardEl.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
  } catch (e: unknown) {
    startError.value = e instanceof Error ? e.message : String(e)
  } finally {
    starting.value = null
  }
}


async function submitFragments(fragments: string[]) {
  submitting.value = true
  resultError.value = null
  try {
    if (!fragments.length) throw new Error('no UR fragments to submit')
    const r = await fetch('/api/leaderlog/result', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ur_fragments: fragments }),
    })
    if (!r.ok) {
      const err = await extractError<ErrorCode>(r)
      throw new Error(err.message)
    }
    const data = await r.json()
    result.value = data
    notify.success(`Leaderlog computed: ${data.count} block(s) for epoch ${data.epoch}`)
    await nextTick()
    resultCardEl.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
  } catch (e: unknown) {
    resultError.value = e instanceof Error ? e.message : String(e)
  } finally {
    submitting.value = false
  }
}

async function onScannerComplete(fragments: string[]) {
  await submitFragments(fragments)
}

async function onScannerCompleteEnlarged(fragments: string[]) {
  cameraEnlarged.value = false
  await submitFragments(fragments)
}

async function submitPasted() {
  const fragments = resultInput.value
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)
  await submitFragments(fragments)
}

function formatUtc(unix: number): string {
  return new Date(unix * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')
}
// The operator's own timezone, resolved by the browser: shown in the
// column header so the times cannot be mistaken for another zone.
const localTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone

function formatLocal(unix: number): string {
  return new Date(unix * 1000).toLocaleString(undefined, {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

onMounted(async () => {
  await checkNextNonceAvailability()
})

async function checkNextNonceAvailability() {
  try {
    const r = await fetch('/api/kes/status')
    if (!r.ok) {
      const err = await extractError<ErrorCode>(r)
      if (err.code === 'not_configured') { notConfigured.value = true; return }
      if (err.code === 'not_paired') { notPaired.value = true; return }
      return
    }
    const data = await r.json()
    const epochEnds = Number(data.epoch_ends_at_unix)
    if (!Number.isFinite(epochEnds)) return
    // Mainnet randomness-stabilisation window = 4k/f slots = 172_800
    // slots ≈ 48 hours (Praos, post-Vasil: TPraos used 3k/f). Mirrors
    // stability_window_slots in online-tool/src/koios.rs; mainnet slots
    // are 1 second, so slots == seconds.
    const stabilityWindowSec = 172_800
    const now = Math.floor(Date.now() / 1000)
    const secondsUntilEnd = epochEnds - now
    nextNonceReady.value = secondsUntilEnd <= stabilityWindowSec
    nextEpochUnlockUnix.value = epochEnds - stabilityWindowSec
  } catch (e: unknown) {
    nextNonceReady.value = null
    notify.error('Could not check next-epoch nonce: ' + (e instanceof Error ? e.message : String(e)))
  }
}


</script>
