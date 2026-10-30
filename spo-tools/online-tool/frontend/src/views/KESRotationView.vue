<template>
  <v-card class="mb-4">
    <v-card-title>KES Rotation</v-card-title>
  </v-card>

  <NotConfiguredCard v-if="notConfigured" />
  <NotPairedCard v-else-if="notPaired" />

  <template v-else>
  <!-- Genesis-not-available banner: Koios was unreachable at startup -->
  <v-card v-if="genesisAvailable === false" class="mb-4">
    <v-card-text>
      <v-alert
        type="warning"
        title="Cardano protocol parameters not loaded"
        density="comfortable"
        variant="tonal"
      >
        <p class="mb-2">
          Koios was unreachable when this binary started, so we have no
          chain parameters yet. Without them the tool refuses to compute
          KES periods rather than guess.
        </p>
        <v-btn
          color="warning"
          variant="flat"
          size="small"
          :loading="refreshingGenesis"
          class="text-white" prepend-icon="mdi-refresh"
          @click="refreshGenesis"
        >Retry Koios</v-btn>
        <span v-if="genesisError" class="text-caption ml-3">{{ genesisError }}</span>
      </v-alert>
    </v-card-text>
  </v-card>

  <v-card v-if="statusError" class="mb-4">
    <v-card-text>
      <v-alert type="error" density="compact" variant="tonal">{{ statusError }}</v-alert>
    </v-card-text>
  </v-card>

  <!-- Countdown banner, only when local state is bootstrapped -->
  <v-card v-if="status && status.opcert_seconds_remaining !== null" class="mb-4">
    <v-card-text>
      <v-alert
        :type="countdownAlertType"
        density="comfortable"
        variant="tonal"
      >
        <div>{{ countdownTitle }}</div>
        <div style="font-variant-numeric: tabular-nums;">
          Expires after KES period {{ status.opcert_end_kes_period }} on
          {{ formatUtc(status.opcert_expires_at_unix!) }} in
          <strong>{{ countdownText }}</strong>
        </div>
      </v-alert>

      <v-alert
        v-if="counterPending"
        type="info"
        density="compact"
        variant="tonal"
        class="mt-2"
      >
        On-chain counter ({{ status.on_chain_counter }}) is one behind your
        local record ({{ status.opcert_local_counter }}). This is expected
        directly after a rotation: the chain will catch up when your pool
        produces its next block.
      </v-alert>

      <v-alert
        v-if="counterUnexpected"
        type="warning"
        density="compact"
        variant="tonal"
        class="mt-2"
      >
        On-chain counter ({{ status.on_chain_counter }}) differs unexpectedly
        from your local record ({{ status.opcert_local_counter }}). Either
        someone rotated outside this tool, or local state was edited manually.
        Investigate before rotating again.
      </v-alert>
    </v-card-text>
  </v-card>

  <!-- Bootstrap form, only when state is empty -->
  <v-card v-if="status && status.opcert_start_kes_period === null" class="mb-4">
    <v-card-text>
      <v-alert type="info" density="comfortable" variant="tonal" class="mb-3">
        <strong>One-time setup needed for the countdown.</strong>
        Find your current opcert's <code>start_kes_period</code> on the BP node
        with <code>cardano-cli query kes-period-info --op-cert-file node.cert</code>
        (look for <code>qKesStartKesInterval</code>), then enter it once.
        After that the tool maintains it automatically.
      </v-alert>
      <div class="d-flex" style="gap: 1rem; align-items: end;">
        <v-text-field
          v-model.number="bootstrapStart"
          label="Current opcert start_kes_period"
          type="number"
          variant="outlined"
          density="compact"
          hide-details
          style="max-width: 320px;"
        />
        <v-text-field
          v-model.number="bootstrapCounter"
          label="Current opcert counter"
          type="number"
          variant="outlined"
          density="compact"
          hide-details
          style="max-width: 240px;"
        />
        <v-btn
          color="primary"
          :loading="savingState"
          :disabled="!bootstrapStart || bootstrapCounter === null"
          prepend-icon="mdi-content-save"
          @click="saveBootstrap"
        >Save</v-btn>
      </div>
      <v-alert v-if="stateError" type="error" density="compact" variant="tonal" class="mt-2">{{ stateError }}</v-alert>
    </v-card-text>
  </v-card>

  <v-card v-if="status" class="mb-4">
    <v-card-text>
      <div class="d-flex align-center mb-2" style="gap: 0.5rem;">
        <h3 class="text-subtitle-1 mt-0 mb-0">Status</h3>
        <v-spacer />
        <v-btn
          size="small"
          variant="outlined"
          :loading="loadingStatus"
          class="text-white" prepend-icon="mdi-refresh"
          @click="resetAndReload"
        >Refresh</v-btn>
        <v-btn
          size="small"
          color="primary"
          :variant="mode === 'send' ? 'tonal' : 'outlined'"
          :loading="starting"
          :disabled="!status"
          prepend-icon="mdi-upload"
          style="width: 180px;"
          @click="openConfirmSend"
        >Send to Signer</v-btn>
        <v-btn
          size="small"
          color="primary"
          :variant="mode === 'receive' ? 'tonal' : 'outlined'"
          :disabled="!request"
          prepend-icon="mdi-download"
          style="width: 180px;"
          @click="enterReceive"
        >Receive from Signer</v-btn>
      </div>
      <v-table density="compact">
        <tbody>
          <tr>
            <td class="text-medium-emphasis">Pool</td>
            <td><code>{{ status.pool_id_bech32 }}</code></td>
          </tr>
          <tr>
            <td class="text-medium-emphasis">Current epoch / slot</td>
            <td>{{ status.current_epoch }} &nbsp;/&nbsp; {{ fmtInt(status.current_slot) }}</td>
          </tr>
          <tr>
            <td class="text-medium-emphasis">Current KES period</td>
            <td>{{ status.current_kes_period }}</td>
          </tr>
          <tr>
            <td class="text-medium-emphasis">On-chain op-cert counter</td>
            <td>{{ status.on_chain_counter }}</td>
          </tr>
          <tr>
            <td class="text-medium-emphasis">Suggested next counter</td>
            <td><strong>{{ status.suggested_new_counter }}</strong></td>
          </tr>
          <tr v-if="status.latest_block_hash">
            <td class="text-medium-emphasis">Latest block</td>
            <td>
              <code>{{ status.latest_block_hash.slice(0, 16) }}…</code>
              at slot {{ fmtInt(status.latest_block_slot) }}
              (KES period {{ status.latest_block_kes_period }})
            </td>
          </tr>
          <tr>
            <td class="text-medium-emphasis">KES validity window</td>
            <td>{{ status.kes_validity_periods }} periods × {{ fmtInt(status.slots_per_kes_period) }} slots ≈ {{ Math.round(status.kes_validity_periods * status.slots_per_kes_period / 86400) }} days</td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
  </v-card>

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

  <v-card ref="resultCardEl" v-if="result">
    <v-card-text>
      <h3 class="text-subtitle-1 mt-0 mb-2">New operational certificate ready</h3>
      <v-table density="compact" class="mb-4">
        <tbody>
          <tr><td class="text-medium-emphasis">Counter</td><td><strong>{{ result.counter }}</strong></td></tr>
          <tr><td class="text-medium-emphasis">KES period</td><td>{{ result.kes_period }}</td></tr>
          <tr><td class="text-medium-emphasis">New KES vkey</td><td><code>{{ result.kes_vkey_hex }}</code></td></tr>
        </tbody>
      </v-table>

      <h3 class="text-subtitle-1 mt-0 mb-2">Files written by signer</h3>
      <v-alert type="info" density="compact" variant="tonal" class="mb-3">
        The signer wrote the three rotation files to its own disk. Pull the LUKS USB from the signer and use it to deploy the files. Nothing leaves the signer over QR.
      </v-alert>
      <v-table density="compact">
        <tbody>
          <tr><td class="text-medium-emphasis" style="width: 220px;">Output directory</td>
              <td><code>{{ result.output_dir }}</code></td></tr>
          <tr><td class="text-medium-emphasis">{{ result.kes_skey_filename }}</td>
              <td>Block-producer node: scp + restart cardano-node</td></tr>
          <tr><td class="text-medium-emphasis">{{ result.node_cert_filename }}</td>
              <td>Block-producer node: scp + restart cardano-node</td></tr>
          <tr><td class="text-medium-emphasis">{{ result.cold_counter_filename }}</td>
              <td>Replace local copy on this workstation and the backup on the producer</td></tr>
        </tbody>
      </v-table>
    </v-card-text>
  </v-card>

  <PreSendConfirm
    v-model="confirmSendOpen"
    title="Confirm KES rotation"
    @confirm="onConfirmSend"
  >
    <p class="text-body-2 text-medium-emphasis mb-2">You are about to rotate the KES key. The signer will produce a new operational certificate.</p>
  </PreSendConfirm>
  </template>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch, onUnmounted, nextTick } from 'vue'
import { useNotificationStore } from '@spo-tools/shared-frontend/stores/notification'
import { COUNTDOWN_TICK_INTERVAL_MS } from '@spo-tools/shared-frontend/constants/timings'
import NotConfiguredCard from '../components/NotConfiguredCard.vue'
import NotPairedCard from '../components/NotPairedCard.vue'
import SendQrPanel from '@spo-tools/shared-frontend/components/SendQrPanel.vue'
import ReceiveQrPanel from '@spo-tools/shared-frontend/components/ReceiveQrPanel.vue'
import { useQrCarousel } from '@spo-tools/shared-frontend/composables/useQrCarousel'
import { useScannerControl } from '@spo-tools/shared-frontend/composables/useScannerControl'
import type { ErrorCode } from '@spo-tools/shared-frontend/types/core'
import type { KesRotationRequest } from '@spo-tools/shared-frontend/types/wire'
import { fmtInt } from '@spo-tools/shared-frontend/utils/format'
import { extractError } from '@spo-tools/shared-frontend/utils/error'
import PreSendConfirm from '@spo-tools/shared-frontend/components/PreSendConfirm.vue'

interface KesStatus {
  pool_id_bech32: string
  current_slot: number
  current_epoch: number
  current_kes_period: number
  on_chain_counter: number
  suggested_new_counter: number
  latest_block_hash: string | null
  latest_block_slot: number | null
  latest_block_kes_period: number | null
  kes_validity_periods: number
  slots_per_kes_period: number
  opcert_start_kes_period: number | null
  opcert_local_counter: number | null
  opcert_end_kes_period: number | null
  opcert_expires_at_unix: number | null
  opcert_seconds_remaining: number | null
  state_last_updated_unix: number | null
}

interface KesResultResponse {
  pool_id_bech32: string
  counter: number
  kes_period: number
  kes_vkey_hex: string
  output_dir: string
  kes_skey_filename: string
  node_cert_filename: string
  cold_counter_filename: string
}

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

const loadingStatus = ref(false)
const starting = ref(false)
const submitting = ref(false)
const savingState = ref(false)
const refreshingGenesis = ref(false)
const genesisAvailable = ref<boolean | null>(null)
const genesisError = ref<string | null>(null)
const notConfigured = ref(false)
const notPaired = ref(false)
const statusError = ref<string | null>(null)
const startError = ref<string | null>(null)
const resultError = ref<string | null>(null)
const stateError = ref<string | null>(null)
const status = ref<KesStatus | null>(null)
const request = ref<KesRotationRequest | null>(null)
const resultInput = ref('')
const result = ref<KesResultResponse | null>(null)
const bootstrapStart = ref<number | null>(null)
const bootstrapCounter = ref<number | null>(null)
const tickNow = ref(Math.floor(Date.now() / 1000))
const mode = ref<'send' | 'receive'>('send')
const cameraEnlarged = ref(false)

const notify = useNotificationStore()
const requestFingerprint = ref<string | null>(null)
const confirmSendOpen = ref(false)

const sendCardEl = ref<{ $el: HTMLElement } | null>(null)
const receiveCardEl = ref<{ $el: HTMLElement; retry?: () => Promise<void> } | null>(null)
// ReceiveQrPanel exposes retry(); mirror its template ref into the scanner
// control so the error alert's 'Try again' restarts the camera instead of
// no-oping on a never-assigned scannerRef.
watch(receiveCardEl, (el) => { scannerRef.value = el })
const resultCardEl = ref<{ $el: HTMLElement } | null>(null)

let countdownTimer: ReturnType<typeof setInterval> | null = null

const counterPending = computed(() => {
  if (!status.value) return false
  if (status.value.opcert_local_counter === null) return false
  return status.value.opcert_local_counter === status.value.on_chain_counter + 1
})

const counterUnexpected = computed(() => {
  if (!status.value) return false
  if (status.value.opcert_local_counter === null) return false
  const local = status.value.opcert_local_counter
  const onchain = status.value.on_chain_counter
  return local !== onchain && local !== onchain + 1
})

const liveSecondsRemaining = computed(() => {
  if (!status.value || status.value.opcert_expires_at_unix === null) return null
  return status.value.opcert_expires_at_unix - tickNow.value
})

const countdownAlertType = computed<'success' | 'warning' | 'error'>(() => {
  const s = liveSecondsRemaining.value
  if (s === null) return 'success'
  if (s <= 0) return 'error'
  if (s < 7 * 86400) return 'warning'
  return 'success'
})

const countdownTitle = computed(() => {
  const s = liveSecondsRemaining.value
  const counter = status.value?.opcert_local_counter ?? '?'
  if (s === null) return 'KES status'
  if (s <= 0) return `Operational Certificate ${counter} is invalid`
  return `Operational Certificate ${counter} is valid`
})

const countdownText = computed(() => {
  const s = liveSecondsRemaining.value
  if (s === null) return ''
  const sign = s < 0 ? '-' : ''
  const abs = Math.abs(s)
  const days = Math.floor(abs / 86400)
  const h = Math.floor((abs % 86400) / 3600)
  const m = Math.floor((abs % 3600) / 60)
  const sec = abs % 60
  return `${sign}${days}d ${pad(h)}:${pad(m)}:${pad(sec)}`
})

function pad(n: number): string {
  return n < 10 ? `0${n}` : `${n}`
}

function resetAndReload() {
  resetQrCarousel()
  request.value = null
  result.value = null
  resultInput.value = ''
  startError.value = null
  resultError.value = null
  mode.value = 'send'
  stopCycle()
  loadStatus()
}

async function loadStatus() {
  loadingStatus.value = true
  statusError.value = null
  try {
    const r = await fetch('/api/kes/status')
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
      if (err.code === 'snapshot_not_ready') {
        // Genesis params not loaded: show retry banner instead of an error
        genesisAvailable.value = false
        status.value = null
        return
      }
      throw new Error(err.message)
    }
    genesisAvailable.value = true
    status.value = await r.json()
  } catch (e: unknown) {
    statusError.value = e instanceof Error ? e.message : String(e)
  } finally {
    loadingStatus.value = false
  }
}

async function refreshGenesis() {
  refreshingGenesis.value = true
  genesisError.value = null
  try {
    const r = await fetch('/api/genesis/refresh', { method: 'POST' })
    if (!r.ok) {
      const err = await extractError<ErrorCode>(r)
      throw new Error(err.message)
    }
    genesisAvailable.value = true
    await loadStatus()
  } catch (e: unknown) {
    genesisError.value = e instanceof Error ? e.message : String(e)
  } finally {
    refreshingGenesis.value = false
  }
}

async function saveBootstrap() {
  savingState.value = true
  stateError.value = null
  try {
    const r = await fetch('/api/kes/state', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        opcert_start_kes_period: bootstrapStart.value,
        opcert_counter: bootstrapCounter.value,
      }),
    })
    if (!r.ok) {
      const err = await extractError<ErrorCode>(r)
      throw new Error(err.message)
    }
    status.value = await r.json()
    notify.success('Local KES state bootstrapped')
    // Tell TopStatusBar to refresh immediately instead of waiting for
    // its next 90-second poll: opcert_expires_at_unix has just changed.
    window.dispatchEvent(new Event('spo-config-saved'))
  } catch (e: unknown) {
    stateError.value = e instanceof Error ? e.message : String(e)
  } finally {
    savingState.value = false
  }
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

function openConfirmSend() {
  confirmSendOpen.value = true
}

async function onConfirmSend(payload: { pin: string }) {
  confirmSendOpen.value = false
  await startRotation(payload.pin)
}

async function startRotation(pin: string) {
  resetQrCarousel()
  request.value = null
  result.value = null
  resultInput.value = ''
  startError.value = null
  resultError.value = null
  mode.value = 'send'
  starting.value = true

  try {
    const r = await fetch('/api/kes/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin }),
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
    status.value = data.status
    qrFragments.value = data.ur_fragments
    requestFingerprint.value = data.request_fingerprint || null
    qrIndex.value = 0
    await renderCurrentFrame()
    startQrCycle()
    await nextTick()
    sendCardEl.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
  } catch (e: unknown) {
    startError.value = e instanceof Error ? e.message : String(e)
  } finally {
    starting.value = false
  }
}


async function submitFragments(fragments: string[]) {
  submitting.value = true
  resultError.value = null
  try {
    if (!fragments.length) throw new Error('no UR fragments to submit')
    const r = await fetch('/api/kes/result', {
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
    notify.success(`Rotation result received: counter ${data.counter}, KES period ${data.kes_period}`)
    await nextTick()
    resultCardEl.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
    stopCycle()
    // Refresh status to pick up the auto-saved state, and tell
    // TopStatusBar to do the same: opcert_expires_at_unix has changed.
    await loadStatus()
    window.dispatchEvent(new Event('spo-config-saved'))
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

onMounted(() => {
  loadStatus()
  countdownTimer = setInterval(() => {
    tickNow.value = Math.floor(Date.now() / 1000)
  }, COUNTDOWN_TICK_INTERVAL_MS)
})

onUnmounted(() => {
  if (countdownTimer) clearInterval(countdownTimer)
})
</script>
